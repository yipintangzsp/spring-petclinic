import test from 'node:test';import assert from 'node:assert/strict';import fs from 'node:fs';import vm from 'node:vm';import crypto from 'node:crypto';import path from 'node:path';
import {summarizeKubescape,combineKubescape} from '../governance/kubescape-report.mjs';import {evaluate} from './engine.mjs';
const out='evidence/2026-11-01/kubescape-parent/',read=p=>JSON.parse(fs.readFileSync(p));
const source=fs.readFileSync('infra/security/governance/kubescape.mjs','utf8').replace(/^import .*;\s*$/gm,'');
const archived=read(out+'archived-consumed-fields.json'),pairs=read('infra/security/policy/versions/kubescape-parent-baseline-v1.json').scans,records=[];
const response=stdout=>({status:0,stdout,stderr:''}),observation=value=>({value});
function fixture(){
 const lock=read('infra/security/governance/tools-lock.json').kubescape;
 return {classification:'CONTROLLED_COMPLETE_GATE_WITH_HISTORICAL_CONSUMED_FIELDS',lock,holder:'fixture-holder',observations:{lockReadSucceeded:true,outputDirSucceeded:true,sourceReadSucceeded:true,
 hashes:Object.fromEntries([[lock.path,observation(lock.sha256)],...Object.entries(lock.artifacts).map(([n,h])=>[lock.artifactRoot+'/'+n,observation(h)])]),lease:response(JSON.stringify({spec:{holderIdentity:'fixture-holder'}})),tempCreateSucceeded:true,tempChmodSucceeded:true,
 server:response('https://fixture.invalid'),ca:response(JSON.stringify({data:{'ca.crt':'NON_SECRET_FIXTURE_CA'}})),token:response('SYNTHETIC_TOKEN_NEVER_USED'),configWriteSucceeded:true,secretReadCheck:{status:1,stdout:'no',stderr:''},businessWriteCheck:{status:1,stdout:'no',stderr:''},cleanupSucceeded:true,finalReportWriteSucceeded:true,
 scans:pairs.map(p=>{const report=archived.reports[p.scope+'-'+p.framework];return {command:response(''),logWriteSucceeded:true,report:observation(JSON.stringify(report.consumedFacts)),hash:observation(report.originalSha256)};})}};
}
function oldGate(raw){
 const o=raw.observations;let scanIndex=0,readCheckIndex=0;const written={},reportReads={};
 const reportPath=i=>'.devsecops/kubescape/'+pairs[i].scope+'-'+pairs[i].framework+'.json';
 const mockFs={
 mkdirSync:()=>{if(!o.outputDirSucceeded)throw Error('mkdir');},
 readFileSync:p=>{
  if(p==='infra/security/governance/tools-lock.json'){if(!o.lockReadSucceeded)throw Error('lock');return JSON.stringify({kubescape:raw.lock});}
  if(p==='.git-sha'){if(!o.sourceReadSucceeded)throw Error('source');return 'fixture-source';}
  if(Object.hasOwn(o.hashes,p)){const h=o.hashes[p];if(h.error)throw Error(h.error);return {frozenObservedHash:h.value};}
  const i=pairs.findIndex((_,i)=>reportPath(i)===p);if(i>=0){const count=reportReads[i]??0;reportReads[i]=count+1;const r=count===0?o.scans[i].report:o.scans[i].hash;if(r.error)throw Error(r.error);return count===0?r.value:{frozenObservedHash:r.value};}
  throw Error('unexpected fixture read');
 },
 mkdtempSync:()=>{if(!o.tempCreateSucceeded)throw Error('temp create');return '/fixture/temporary';},
 chmodSync:()=>{if(!o.tempChmodSucceeded)throw Error('temp chmod');},
 rmSync:()=>{if(!o.cleanupSucceeded)throw Error('cleanup');},
 writeFileSync:(p,value)=>{
  if(p==='/fixture/temporary/config'&&!o.configWriteSucceeded)throw Error('kubeconfig write');
  if(p.endsWith('.log')){const i=pairs.findIndex((_,i)=>reportPath(i)+'.log'===p);if(!o.scans[i].logWriteSucceeded)throw Error('log write');}
  if(p==='.devsecops/kubescape-gate.json'&&!o.finalReportWriteSucceeded)throw Error('report write');
  written[p]=String(value);
 }};
 const spawnSync=(bin,args)=>{
  let r;if(bin===raw.lock.path){r=o.scans[scanIndex++].command;}
  else if(args.includes('lease'))r=o.lease;else if(args.includes('view'))r=o.server;else if(args.includes('configmap'))r=o.ca;else if(args.includes('token'))r=o.token;else if(args.includes('can-i'))r=readCheckIndex++===0?o.secretReadCheck:o.businessWriteCheck;else throw Error('unexpected fixture command');
  return {...r,error:r.error?new Error(r.error):undefined};
 };
 // Hash operations are frozen observed digest facts, not recomputed fake binaries.
 const hashCrypto={createHash:()=>({update:b=>({digest:()=>b?.frozenObservedHash??crypto.createHash('sha256').update(b).digest('hex')})})};
 try{vm.runInNewContext(source,{fs:mockFs,crypto:hashCrypto,os:{tmpdir:()=>'/fixture'},path,Buffer,spawnSync,summarizeKubescape,combineKubescape,process:{env:{HEAVY_HOLDER:raw.holder,BUILD_NUMBER:'fixture'}},console:{log:()=>{}}});return {decision:'PASS',report:JSON.parse(written['.devsecops/kubescape-gate.json'])};}
 catch(error){return {decision:'FAIL',reason:error.message};}
}
function run(name,mutate,expected,branch){test('Kubescape complete Gate '+name,()=>{
 const raw=fixture();mutate(raw);const before=JSON.stringify(raw),old=oldGate(raw),p=evaluate({component:'kubescape',status:'success',raw});assert.equal(old.decision,expected,old.reason);assert.equal(p.decision,old.decision,p.reason);assert.equal(JSON.stringify(raw),before);assert.deepEqual(p.rawEvidence,raw);
 if(p.decision==='PASS'){
  for(const k of ['failedControls','highRiskFindings','findings'])assert.equal(p.counts[k],old.report[k]);
  for(let i=0;i<4;i++)for(const k of ['scope','framework','failedControls','resourceControlFindings','nativeSeverityCounters','failedControlCount','complianceScore','resources','controls'])assert.deepEqual(p.scans[i][k],old.report.scans[i][k]);
  assert.equal(p.auditMode,'AUDIT');if(p.counts.findings>0||p.counts.failedControls>0)assert.equal(p.auditDisposition,'WARN');
 }
 records.push({name,branch,classification:raw.classification,oldDecision:old.decision,standardDecision:p.decision,auditDisposition:p.auditDisposition,rawPreserved:true,legacyReason:old.reason,policyReason:p.reason});
 });}
run('archived-findings-retained',()=>{},'PASS','audit-and-aggregation');
run('zero-findings',r=>{for(const s of r.observations.scans){const d=JSON.parse(s.report.value);d.results=[];d.summaryDetails.controls={};s.report.value=JSON.stringify(d);}r.classification='SYNTHETIC_COMPLETE_GATE';},'PASS','audit-and-aggregation');
run('same-control-across-frameworks',r=>{for(const s of r.observations.scans)s.report.value=JSON.stringify({results:[{resourceID:'shared',controls:[{controlID:'C-X',status:{status:'failed'},severity:'High'}]}],resources:[{}],summaryDetails:{controls:{'C-X':{controlID:'C-X',status:'failed',severity:'High'}},complianceScore:0}});r.classification='SYNTHETIC_COMPLETE_GATE';},'PASS','audit-and-aggregation');
for(const [name,mutate]of [
 ['lock-unreadable',r=>r.observations.lockReadSucceeded=false],['output-directory-error',r=>r.observations.outputDirSucceeded=false],['source-read-error',r=>r.observations.sourceReadSucceeded=false],
 ['binary-hash-mismatch',r=>r.observations.hashes[r.lock.path].value='wrong'],['binary-unavailable',r=>r.observations.hashes[r.lock.path]={error:'ENOENT'}],
 ['framework-hash-mismatch',r=>r.observations.hashes[r.lock.artifactRoot+'/nsa.json'].value='wrong'],['framework-file-missing',r=>r.observations.hashes[r.lock.artifactRoot+'/controls-inputs.json']={error:'ENOENT'}],
 ['lease-query-failed',r=>r.observations.lease={status:1,stdout:'',stderr:'unavailable'}],['lease-malformed',r=>r.observations.lease=response('{')],['lease-holder-mismatch',r=>r.observations.lease=response(JSON.stringify({spec:{holderIdentity:'other'}}))],
 ['temp-create-failed',r=>r.observations.tempCreateSucceeded=false],['chmod-failed',r=>r.observations.tempChmodSucceeded=false],
 ['context-unavailable',r=>r.observations.server={status:1,stdout:'',stderr:'no context'}],['CA-query-failed',r=>r.observations.ca={status:1,stdout:'',stderr:'missing'}],['CA-malformed',r=>r.observations.ca=response('{')],['CA-data-absent',r=>r.observations.ca=response('{}')],
 ['token-request-failed',r=>r.observations.token={status:1,stdout:'',stderr:'forbidden'}],['kubeconfig-write-failed',r=>r.observations.configWriteSucceeded=false],
 ['secret-access-not-denied',r=>r.observations.secretReadCheck=response('yes')],['business-write-not-denied',r=>r.observations.businessWriteCheck=response('yes')],['capability-query-error',r=>r.observations.secretReadCheck={status:2,stdout:'',stderr:'connection failed'}],
 ['scan-nonzero',r=>r.observations.scans[0].command={status:1,stdout:'',stderr:'missing manifest/cluster access'}],['scan-timeout',r=>r.observations.scans[0].command={status:null,error:'ETIMEDOUT',stdout:'',stderr:''}],
 ['scan-log-write-failed',r=>r.observations.scans[0].logWriteSucceeded=false],['report-missing',r=>r.observations.scans[0].report={error:'ENOENT'}],['report-malformed',r=>r.observations.scans[0].report.value='{'],
 ['report-schema-incomplete',r=>r.observations.scans[0].report.value='{}'],['report-hash-read-failed',r=>r.observations.scans[0].hash={error:'ENOENT'}],
 ['cleanup-failed',r=>r.observations.cleanupSucceeded=false],['report-write-failed',r=>r.observations.finalReportWriteSucceeded=false],
 ['cleanup-after-scan-failure',r=>{r.observations.scans[0].command={status:1,stdout:'',stderr:''};r.observations.cleanupSucceeded=false;}]
 ])run(name,mutate,'FAIL','execution-capability-report-cleanup');
for(let i=1;i<4;i++)run('later-framework-failure-'+i,r=>r.observations.scans[i].command={status:1,stdout:'',stderr:'failed'},'FAIL','aggregation');
run('failed-controls-without-resource-pairs',r=>{for(const s of r.observations.scans){const d=JSON.parse(s.report.value);d.results=[];d.summaryDetails.controls={'C-X':{controlID:'C-X',status:'failed',severity:'High'}};s.report.value=JSON.stringify(d);}r.classification='SYNTHETIC_COMPLETE_GATE';},'PASS','audit-and-aggregation');
for(const [name,change]of [
 ['CA-content-missing',r=>r.observations.ca=response(JSON.stringify({data:{}}))],
 ['context-stdout-unavailable',r=>r.observations.server={status:0,stderr:''}],
 ['token-stdout-unavailable',r=>r.observations.token={status:0,stderr:''}],
 ['native-risk-score-malformed',r=>{const d=JSON.parse(r.observations.scans[0].report.value);d.summaryDetails.complianceScore='bad';r.observations.scans[0].report.value=JSON.stringify(d);}],
 ['native-resource-results-malformed',r=>{const d=JSON.parse(r.observations.scans[0].report.value);d.results={};r.observations.scans[0].report.value=JSON.stringify(d);}],
 ['malformed-report-plus-cleanup-failure',r=>{r.observations.scans[0].report.value='{';r.observations.cleanupSucceeded=false;}],
 ['final-report-write-after-scan-error',r=>{r.observations.scans[0].command={status:1,stdout:'',stderr:''};r.observations.finalReportWriteSucceeded=false;}]
 ])run(name,change,'FAIL','execution-capability-report-cleanup');
test('uncaptured parent evidence does not PASS',()=>assert.equal(evaluate({component:'kubescape',status:'success',raw:{}}).decision,null));
test.after(()=>fs.writeFileSync(out+'differential.json',JSON.stringify({records},null,2)));
