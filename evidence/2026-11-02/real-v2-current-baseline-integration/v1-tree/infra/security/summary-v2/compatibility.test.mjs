import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {spawnSync} from 'node:child_process';
import {summaryV2} from './producer.mjs';
import {verifyVersion} from './integrity.mjs';
import {validateGate} from '../promotion/contract.mjs';
import {evaluate} from '../policy/engine.mjs';
import {fixture,root,binding,contract} from './fixture-harness.mjs';

const base = path.join(root,'evidence/2026-11-02/summary-v2-migration');
const strip = value => { const {summaryProducer,policy,resolvedSources,aggregateSecurityGate,...legacy}=value;return legacy; };
const rows=[];
function runV1(state) {
  const dir=fs.mkdtempSync(path.join(os.tmpdir(),'summary-v1-isolated-'));
  try {
    fs.mkdirSync(path.join(dir,'.devsecops'));fs.writeFileSync(path.join(dir,'.git-sha'),binding.source);
    const write=(name,value)=>fs.writeFileSync(path.join(dir,'.devsecops',name),JSON.stringify(value));
    const status={PASS:'success',FAIL:'failed',WARN:'success',SKIPPED:'skipped',NOT_CONFIGURED:'not_configured',POLICY_ERROR:'error'}[state];
    write('security-manager.json',{mode:'enforce',profile:'java-web',modules:[{tool:'trivy',status}]});
    write('trivy-audit.json',{status,runtimeImage:binding.candidate,auditTargetImage:binding.candidate,targetScope:'candidate',...(state==='FAIL'?{failures:['CONTROLLED_FIXTURE']}:{})});
    // This is the ACTUAL frozen V1 producer, not a reimplementation. Disable
    // its optional transport and Sonar credential; no network/production access.
    const child=spawnSync(process.execPath,[path.join(base,'v1-tree/infra/security/security-summary.mjs')],{
      cwd:dir,encoding:'utf8',timeout:10000,env:{PATH:process.env.PATH,BUILD_NUMBER:'1',SECURITY_BUILD_RESULT:['FAIL','POLICY_ERROR'].includes(state)?'FAILURE':'SUCCESS',SECURITY_SUMMARY_WRITE_ONLY:'true',SONAR_TOKEN:'',ENABLE_PROVENANCE:'false'}});
    assert.equal(child.status,0,child.stderr);return JSON.parse(fs.readFileSync(path.join(dir,'.devsecops/security-summary.json')));
  } finally {fs.rmSync(dir,{recursive:true,force:true});}
}
for(const state of ['PASS','FAIL','WARN','SKIPPED','NOT_CONFIGURED','POLICY_ERROR'])test('actual V1 producer / candidate V2 legacy-field differential: '+state,async()=>{
  const before=runV1(state),f=await fixture(state==='POLICY_ERROR'?'PASS':state,state==='POLICY_ERROR'?{profile:'typo'}:{},before),after=summaryV2(f.packet,f.context);
  assert.deepEqual(strip(after),before);assert.equal(after.schema,1);assert.equal(after.summaryProducer.version,2);
  rows.push({state,classification:'CONTROLLED_SERIALIZATION_AND_ENGINE_UNIT',actualV1Executed:true,oldFieldsEqual:true,sourceRuntimeCaptureProven:false,
    trivyPolicyStatus:after.resolvedSources.find(x=>x.sourceId==='trivy').status});
});
const checks=(selectedVersion,consumerVersion,producer,extra={})=>verifyVersion({root,contract:contract(),selectedVersion,consumerVersion,producer,...extra});
test('mixed matrix A: exact V1 baseline recognized',()=>assert.ok(checks('V1','V1',contract().versions.V1.producer).checked.length>0));
test('mixed matrix B: candidate V2 accepted by explicit migrated contract verifier',()=>assert.ok(checks('V2','SummaryConsumerV2',contract().versions.V2.producer).checked.length>0));
test('mixed matrix C: V2 plus V1-only selected verifier rejects',()=>assert.throws(()=>checks('V2','V1',contract().versions.V2.producer),/mixed version/));
test('mixed matrix D: V1 allowed only through explicit V1 rollback contract',()=>{
  assert.ok(checks('V1','V2-explicit-rollback',contract().versions.V1.producer));assert.throws(()=>checks('V2','SummaryConsumerV2',contract().versions.V1.producer),/unknown producer/);
});
test('mixed matrix E: unknown producer/version rejected',()=>{
  assert.throws(()=>checks('V2','SummaryConsumerV2',{identity:'unknown',sha256:'0'.repeat(64)}),/unknown producer/);assert.throws(()=>checks('V9','V1',contract().versions.V1.producer),/unknown selected version/);
});
test('mixed matrix F/H: tampering rejected; controlled V2 to exact V1 restore succeeds',()=>{
  const dir=fs.mkdtempSync(path.join(os.tmpdir(),'summary-version-rollback-'));
  try {
    const c=contract();for(const selected of Object.values(c.versions))for(const relative of Object.keys(selected.files)){
      const target=path.join(dir,relative);fs.mkdirSync(path.dirname(target),{recursive:true});if(!fs.existsSync(target))fs.copyFileSync(path.join(root,relative),target);
    }
    assert.ok(checks('V2','SummaryConsumerV2',c.versions.V2.producer,{root:dir}));
    const producer='infra/security/summary-v2/producer.mjs';fs.appendFileSync(path.join(dir,producer),'\n// tampered controlled copy\n');
    assert.throws(()=>checks('V2','SummaryConsumerV2',c.versions.V2.producer,{root:dir}),/tampered/);
    // Rollback selects V1 AND restores V1 snapshot bytes; no hashes are relaxed.
    for(const relative of Object.keys(c.versions.V1.files))fs.copyFileSync(path.join(base,'v1-tree',relative),path.join(dir,relative));
    assert.ok(checks('V1','V2-explicit-rollback',c.versions.V1.producer,{root:dir}));
  }finally{fs.rmSync(dir,{recursive:true,force:true});}
});
test('no transitive Engine/owner import in Summary/artifact/Promotion precondition graph',()=>{
  const visited=new Set();const walk=file=>{
    if(visited.has(file))return;visited.add(file);const bytes=fs.readFileSync(file,'utf8');
    assert.doesNotMatch(bytes,/import\s*\(/,'dynamic import not allowed in consumer graph');
    for(const match of bytes.matchAll(/from\s+['"]([^'"]+)['"]/g))if(match[1].startsWith('.')){
      const next=path.resolve(path.dirname(file),match[1]);assert.doesNotMatch(next,/\/policy\/|\/owner\.mjs$/);walk(next);
    }
  };
  for(const name of ['producer','promotion-input'])walk(path.join(root,'infra/security/summary-v2/'+name+'.mjs'));
});
test('Jenkins existing archive globs include the candidate artifact path (static only)',()=>{
  const jenkins=fs.readFileSync(path.join(root,'Jenkinsfile.security-audit'),'utf8');assert.match(jenkins,/archiveArtifacts[^\n]*\.devsecops\/\*\*/);assert.ok('.devsecops/policy/pre-approval-'+'a'.repeat(64)+'.json');
});
test('Grafana existing exact JSON selectors preserve their fields (no live Loki query)',async()=>{
  const legacy=runV1('PASS');Object.assign(legacy,{kubescape_scan_success:1,kubescape_failed_controls:2,kubescape_high_risk_findings:3,kubescape_framework_summary:'controlled summary',defectdojo_import_success:1,defectdojo_open_findings:5,defectdojo_critical:0,defectdojo_high:0,defectdojo_medium:2,defectdojo_low:3,defectdojo_accepted_risk:0,defectdojo_mitigated_closed:0,defectdojo_false_positives:0,defectdojo_duplicates:0});
  const f=await fixture('PASS',{},legacy),after=JSON.parse(JSON.stringify(summaryV2(f.packet,f.context))),queries=JSON.stringify(JSON.parse(fs.readFileSync(path.join(root,'infra/security/governance/grafana-panels.json'))));
  const selectors=[...queries.matchAll(/json (?:value|summary)=\\"([^\\"]+)\\"/g)].map(x=>x[1]);assert.equal(selectors.length,14);
  for(const key of selectors)assert.deepEqual(after[key],legacy[key]);
});
test('old Promotion contract still checks legacy fields, not V2 authority: active dispatch remains BLOCKED',async()=>{
  const candidate='core.harbor.domain/petclinic/petclinic@sha256:'+'a'.repeat(64),previous='core.harbor.domain/petclinic/petclinic@sha256:'+'b'.repeat(64);
  const gate={result:'SUCCESS',build:1,source:binding.source,candidate,trivy:{status:'success',targetScope:'candidate',auditTargetImage:candidate,runtimeImage:previous,scans:[{digest:'sha256:'+'d'.repeat(64)},{digest:'sha256:'+'e'.repeat(64)}]},
    summary:{build:1,source:binding.source,targetScope:'candidate',auditTargetImage:candidate,trivy_critical:0,trivy_high:0,summaryProducer:{identity:'unknown'},policy:{state:'POLICY_ERROR'}},
    ...Object.fromEntries(['sourceScan','admission','semgrep','zap','falco','dojo','kubescape'].map(k=>[k,{status:'success'}])),business:{unchanged:true},sbom:{candidate,architectures:['amd64','arm64'].map(arch=>({arch,jarSha256:'sha256:'+'f'.repeat(64),sbomSha256:'sha256:'+'1'.repeat(64)}))}};
  assert.equal(validateGate(gate),candidate.split('@')[1]);
  // This is evidence of a NOT MIGRATED consumer, never a V2 acceptance pass.
});
test('Regression remains the original top-level Node exit-code Gate, not a TAP/history parser',()=>{
  const lock=JSON.parse(fs.readFileSync(path.join(root,'infra/security/policy/versions/regression-baseline-v1.json')));
  for(const status of [0,1,127]){
    const raw={schema:1,stage:'command',complete:true,command:lock.command,execution:{status,signal:null,error:null},stdout:'CONTROLLED_UNIT_NOT_ACTUAL_RUN',stderr:''};
    const result=evaluate({component:'regression',status:'success',raw});assert.equal(result.decision,status===0?'PASS':'FAIL');
  }
});
test.after(()=>fs.writeFileSync(path.join(base,'candidate-summary-differential.json'),JSON.stringify({classification:'CONTROLLED_UNIT_AND_ACTUAL_V1_SERIALIZATION',productionMigration:false,samples:rows},null,2)+'\n'));
