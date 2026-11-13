import test from 'node:test';import assert from 'node:assert/strict';import fs from 'node:fs';import vm from 'node:vm';import crypto from 'node:crypto';
import {evaluate} from './engine.mjs';
import {checkCosignVerification} from '../cosign-verification.mjs';
import {validatePriorExit,validateRuntimeContinuity} from '../runtime/health-contract.mjs';
import {persistentRuntime} from '../runtime/event-policy.mjs';
import {validate,verifyEnvelope} from '../provenance/contract.mjs';
import {validateBuildStatement} from '../provenance/build-contract.mjs';
import {validateGate,approvedRelease} from '../promotion/contract.mjs';
const dir='evidence/2026-11-01/remaining-policy/',archive=JSON.parse(fs.readFileSync(dir+'archived-270.json')).reports,records=[];
function diff(component,name,raw,old,expected,kind='synthetic-contract-fixture'){
 test(component+' / '+name,()=>{
  const before=JSON.stringify(raw);let legacy;
  try{legacy=old(raw)??'PASS';}catch{legacy='FAIL';}
  assert.equal(legacy,expected,'fixture must exercise intended legacy outcome');
  const result=evaluate({component,status:'success',raw});
  assert.equal(result.decision,legacy);assert.equal(JSON.stringify(raw),before);assert.deepEqual(result.frozenEvidence.rawEvidence,raw);
  records.push({component,case:name,kind,legacy,standard:result.decision,inputSha256:crypto.createHash('sha256').update(before).digest('hex'),rawUnchanged:true});
 });
}
const key=fs.readFileSync('infra/security/cosign.pub','utf8'),p=archive['provenance.json'];
const prov={envelope:archive['attestation-envelope.json'],publicKey:key,expected:{...p,image:p.candidateImage}};
const oldProv=r=>{validate(verifyEnvelope(r.envelope,r.publicKey),r.expected);};
diff('provenance-signature','archived-270-valid',prov,oldProv,'PASS','archived-positive');
for(const field of ['image','commit','builderIdentity']){const r=structuredClone(prov);r.expected[field]='changed';diff('provenance-signature','mismatch-'+field,r,oldProv,'FAIL');}
{const r=structuredClone(prov);r.envelope.payload=Buffer.from('tampered').toString('base64');diff('provenance-signature','tampered',r,oldProv,'FAIL');}
const build={envelope:archive['build-attestation-envelope.json'],publicKey:key,expected:archive['build-attestation-verification.json'].expected};
const oldBuild=r=>{validateBuildStatement(verifyEnvelope(r.envelope,r.publicKey),r.expected);};
diff('build-provenance-signature','archived-270-valid',build,oldBuild,'PASS','archived-positive');
for(const field of ['image','commit','builder']){const r=structuredClone(build);r.expected[field]='changed';diff('build-provenance-signature','mismatch-'+field,r,oldBuild,'FAIL');}
{const r=structuredClone(build);r.envelope.payload=Buffer.from('tampered').toString('base64');diff('build-provenance-signature','tampered',r,oldBuild,'FAIL');}
const oldCosign=r=>{checkCosignVerification(r.kind,r.exitStatus,r.stderr);};
for(const [name,raw,expected]of [
 ['signed-valid',{kind:'signed',exitStatus:0,stderr:''},'PASS'],
 ['unsigned-correct-rejection',{kind:'unsigned',exitStatus:1,stderr:'no signatures found'},'PASS'],
 ['wrong-key-correct-rejection',{kind:'wrong-key',exitStatus:1,stderr:'signature verification failed'},'PASS'],
 ['signed-invalid',{kind:'signed',exitStatus:1,stderr:'invalid signature'},'FAIL'],
 ['unsigned-accepted',{kind:'unsigned',exitStatus:0,stderr:''},'FAIL'],
 ['registry-error-not-signature-negative',{kind:'wrong-key',exitStatus:1,stderr:'connection timed out'},'FAIL']])diff('cosign-cli',name,raw,oldCosign,expected);
const current=archive['runtime-baseline.json'];
const oldPrior=r=>validatePriorExit(r.current)?.warning?'WARN':'PASS';
diff('falco-prior-exit','archived-nonclean-exit',{current},oldPrior,'WARN','archived-positive-warning');
diff('falco-prior-exit','clean-exit',{current:{...current,priorExit:{exitCode:0,reason:'Completed'}}},oldPrior,'PASS');
diff('falco-prior-exit','not-ready',{current:{...current,ready:false}},oldPrior,'FAIL');
const oldContinuity=r=>{validateRuntimeContinuity(r.current,r.baseline);};
diff('falco-continuity','unchanged',{current,baseline:current},oldContinuity,'PASS');
for(const field of ['restarts','containerId','nodeBootId']){const r={current:{...current,[field]:field==='restarts'?current.restarts+1:'changed'},baseline:current};diff('falco-continuity','changed-'+field,r,oldContinuity,'FAIL');}
const a={start:'2026-11-01T00:00:00Z',end:'2026-11-01T00:00:15Z',candidates:[{key:'same-proven-identity',count:2}],warnings:{}};
const b={...a,start:'2026-11-01T00:00:16Z',end:'2026-11-01T00:00:31Z'};
const oldPersistent=r=>persistentRuntime(r.first,r.second).blocking.length?'FAIL':'PASS';
diff('falco-persistence','persistent-confirmed',{first:a,second:b},oldPersistent,'FAIL');
diff('falco-persistence','transient',{first:a,second:{...b,candidates:[]}},oldPersistent,'PASS');
diff('falco-persistence','overlap-invalid',{first:a,second:a},oldPersistent,'FAIL');
// Execute the original SBOM script in a no-I/O VM; only fs/process inputs are fixtures.
const sbomSource=fs.readFileSync('infra/security/sbom-verify.mjs','utf8');
const oldSbom=r=>{
 const packaged=Buffer.from(r.packagedBase64,'base64'),maven=Buffer.from(r.mavenBase64,'base64');
 const mockFs={readFileSync:p=>p==='.git-sha'?'a'.repeat(40):maven,mkdirSync:()=>{},writeFileSync:()=>{}};
 vm.runInNewContext(sbomSource.replace(/^import .*;\s*$/gm,''),{fs:mockFs,crypto,execFileSync:()=>packaged,console:{log:()=>{}}});
};
const bom={bomFormat:'CycloneDX',specVersion:'1.6',components:Array.from({length:10},(_,i)=>({'bom-ref':'c'+i})),dependencies:[{ref:'c0'}]};
const encode=x=>Buffer.from(JSON.stringify(x)).toString('base64'),good={packagedBase64:encode(bom),mavenBase64:encode(bom)};
diff('sbom','valid',good,oldSbom,'PASS');
diff('sbom','packaged-mismatch',{...good,mavenBase64:encode({...bom,specVersion:'1.5'})},oldSbom,'FAIL');
for(const [name,change]of [['empty-components',x=>x.components=[]],['duplicate-ref',x=>x.components[1]['bom-ref']='c0'],['no-dependencies',x=>x.dependencies=[]],['wrong-version',x=>x.specVersion='1.5']]){
 const x=structuredClone(bom);change(x);diff('sbom',name,{packagedBase64:encode(x),mavenBase64:encode(x)},oldSbom,'FAIL');
}
const image='core.harbor.domain/petclinic/petclinic@sha256:'+'a'.repeat(64),prior='core.harbor.domain/petclinic/petclinic@sha256:'+'b'.repeat(64),source='c'.repeat(40);
const gate={result:'SUCCESS',build:1,source,candidate:image,trivy:{status:'success',targetScope:'candidate',auditTargetImage:image,runtimeImage:prior,scans:[{digest:'sha256:'+'d'.repeat(64)},{digest:'sha256:'+'e'.repeat(64)}]},summary:{source,build:1,targetScope:'candidate',auditTargetImage:image,trivy_critical:0,trivy_high:0},...Object.fromEntries(['sourceScan','admission','semgrep','zap','falco','dojo','kubescape'].map(k=>[k,{status:'success',source}])),business:{unchanged:true},sbom:{candidate:image,architectures:['amd64','arm64'].map(arch=>({arch,jarSha256:'sha256:'+'f'.repeat(64),sbomSha256:'sha256:'+'1'.repeat(64)}))}};
const oldApproval=r=>{validateGate(r.gate);};
diff('approval-evidence','complete',{gate},oldApproval,'PASS');
for(const [name,change]of [['high-finding',x=>x.summary.trivy_high=1],['stale-source',x=>x.summary.source='wrong'],['incomplete-sbom',x=>x.sbom.architectures=[]],['changed-runtime',x=>x.business.unchanged=false]]){const x=structuredClone(gate);change(x);diff('approval-evidence',name,{gate:x},oldApproval,'FAIL');}
const signing={images:[image,...gate.trivy.scans.map(s=>'core.harbor.domain/petclinic/petclinic@'+s.digest)].map(image=>({image,verified:true}))};
const oldSign=r=>{approvedRelease(r.gate,r.signing);};
diff('approval-signatures','complete-signatures',{gate,signing},oldSign,'PASS');
diff('approval-signatures','missing-signatures',{gate,signing:{images:[]}},oldSign,'FAIL');
test.after(()=>fs.writeFileSync(dir+'contract-differential.json',JSON.stringify({scope:'Explicit subcontracts only; not complete production stage coverage',records},null,2)));
