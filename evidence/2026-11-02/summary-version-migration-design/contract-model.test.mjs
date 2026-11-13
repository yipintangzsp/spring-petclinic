// Controlled design model + actual unchanged Engine calls. Not a production acceptance suite.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import {evaluate,evaluateAsync} from '../../../infra/security/policy/engine.mjs';
import {singleSourceOwner,encode,consume,gateView,metadataView,migrationCheck,sha} from './contract-model.mjs';
const root='evidence/2026-11-02/summary-version-migration-design/';
const records=[];
const facts={component:'semgrep',status:'success',raw:{findings:[{check_id:'review-only',extra:{severity:'WARNING'}}]}};
const binding={job:'controlled-model-job',build:1,project:'controlled-model-project',source:'a'.repeat(40),targetScope:'candidate',auditTargetImage:'example.invalid/repository/image@sha256:'+'b'.repeat(64),policyVersion:'baseline-v1'};
async function resolved(config={},input=facts){
 let calls=0;
 const owner=singleSourceOwner(async(f,c)=>{calls++;return evaluateAsync(f,c);});
 const currentBinding={...binding,project:config.project??binding.project};
 const before=JSON.stringify(input),result=await owner.run(input,config,currentBinding),packet=encode(result);
 const expected={binding:currentBinding,digest:packet.digest,factsSha256:result.factsSha256,configSha256:result.configSha256};
 assert.equal(JSON.stringify(input),before);
 return {owner,result,packet,expected,calls};
}
function checked(name,fn){test(name,async()=>{
 await fn();records.push({name,result:'PASS',classification:'DESIGN_HARNESS_NOT_PRODUCTION'});
});}
checked('one source: actual Engine invoked once; concurrent duplicate owner calls reuse identical result',async()=>{
 let n=0;const owner=singleSourceOwner(async(f,c)=>{n++;await Promise.resolve();return evaluateAsync(f,c);});
 const [a,b]=await Promise.all([owner.run(facts,{},binding),owner.run(facts,{},binding)]);
 assert.equal(n,1);assert.strictEqual(a,b);assert.equal(await owner.run(facts,{},binding),a);
 assert.throws(()=>owner.run({...facts,status:'error'},{},binding),/POLICY_ERROR/);
 assert.ok(Object.isFrozen(a.result.effectivePolicy.semgrep));
});
checked('Gate and metadata receive same owner-pinned serialized result digest',async()=>{
 const r=await resolved(),gate=consume(r.packet,r.expected),summary=consume(r.packet,r.expected);
 assert.deepEqual(gate,summary);assert.equal(sha(r.packet.bytes),r.expected.digest);
 assert.deepEqual(gateView(gate),{status:'WARN',decision:'WARN'});
 assert.equal(metadataView(summary).status,'WARN');assert.equal(r.calls,1);
});
checked('metadata projection cannot trigger an evaluation; repeated serialization invokes none',async()=>{
 const r=await resolved();for(let i=0;i<3;i++)metadataView(consume(r.packet,r.expected));
 assert.equal(r.calls,1);
 const model=fs.readFileSync(root+'contract-model.mjs','utf8').split('export function metadataView')[1].split('export function migrationCheck')[0];
 assert.ok(!/evaluate|resolvePolicy|singleSourceOwner/.test(model));
});
checked('missing result rejected',async()=>{const r=await resolved();assert.throws(()=>consume(null,r.expected),/result missing/);});
checked('malformed result rejected even with owner-pinned digest',async()=>{
 const r=await resolved(),bad=structuredClone(r.result);delete bad.result.effectivePolicy;
 const packet=encode(bad);assert.throws(()=>consume(packet,{...r.expected,digest:packet.digest}),/malformed Engine result/);
 const malformed={bytes:'{'};assert.throws(()=>consume(malformed,{...r.expected,digest:sha('{')}),/malformed JSON/);
});
checked('stale build rejected against independently supplied current context',async()=>{
 const r=await resolved();assert.throws(()=>consume(r.packet,{...r.expected,binding:{...binding,build:2}}),/binding mismatch/);
});
checked('wrong candidate rejected',async()=>{
 const r=await resolved();assert.throws(()=>consume(r.packet,{...r.expected,binding:{...binding,auditTargetImage:'example.invalid/repository/image@sha256:'+'c'.repeat(64)}}),/binding mismatch/);
});
checked('wrong source and cross-job replay rejected',async()=>{
 const r=await resolved();
 for(const b of [{...binding,source:'d'.repeat(40)},{...binding,job:'other-job'}])assert.throws(()=>consume(r.packet,{...r.expected,binding:b}),/binding mismatch/);
});
checked('wrong policyVersion rejected',async()=>{
 const r=await resolved(),bad=structuredClone(r.result);bad.result.policyVersion='unknown';const packet=encode(bad);
 assert.throws(()=>consume(packet,{...r.expected,digest:packet.digest}),/wrong policyVersion/);
});
checked('tampered bytes rejected using digest retained outside artifact',async()=>{
 const r=await resolved();assert.throws(()=>consume({...r.packet,bytes:r.packet.bytes+' '},r.expected),/digest mismatch/);
});
checked('facts/config snapshot mismatch rejected',async()=>{
 const r=await resolved();
 assert.throws(()=>consume(r.packet,{...r.expected,factsSha256:'x'}),/input snapshot mismatch/);
 assert.throws(()=>consume(r.packet,{...r.expected,configSha256:'x'}),/input snapshot mismatch/);
});
checked('actual Engine POLICY_ERROR preserved; no fabricated default metadata',async()=>{
 const r=await resolved({profile:'invalid'}),v=consume(r.packet,r.expected);
 assert.equal(r.calls,1);assert.equal(v.result,null);
 assert.equal(gateView(v).status,'POLICY_ERROR');const m=metadataView(v);
 assert.equal(m.status,'POLICY_ERROR');assert.ok(!Object.hasOwn(m,'securityLevel'));
 assert.ok(!Object.hasOwn(m,'effectivePolicy'));assert.equal(gateView(v).decision,null);
});
checked('default standard metadata comes from actual Engine result',async()=>{
 const r=await resolved();assert.equal(metadataView(consume(r.packet,r.expected)).securityLevel,'standard');
 assert.equal(metadataView(r.result).policyVersion,'baseline-v1');
});
for(const level of ['low','strict'])checked('explicit '+level+' metadata preserved',async()=>{
 const r=await resolved({securityLevel:level});assert.equal(metadataView(consume(r.packet,r.expected)).securityLevel,level);
});
checked('component override preserved, scoped and immutable',async()=>{
 const r=await resolved({componentOverrides:{semgrep:{Medium:'FAIL'}}}),v=consume(r.packet,r.expected);
 assert.equal(v.result.effectivePolicy.semgrep.Medium,'FAIL');assert.equal(v.result.effectivePolicy.trivy.Medium,'WARN');
 assert.deepEqual(v.result.appliedOverrides,[{layer:'component',component:'semgrep',values:{Medium:'FAIL'}}]);
 assert.throws(()=>{v.result.appliedOverrides[0].layer='project';},TypeError);
});
checked('project override and full appliedOverrides order preserved',async()=>{
 const config={project:'p',componentOverrides:{semgrep:{Medium:'FAIL'}},projectOverride:{project:'p',components:{semgrep:{Medium:'WARN'}}}};
 const r=await resolved(config),v=consume(r.packet,r.expected);
 assert.equal(v.result.effectivePolicy.semgrep.Medium,'WARN');assert.deepEqual(v.result.appliedOverrides.map(x=>x.layer),['component','project']);
 assert.deepEqual(metadataView(v).appliedOverrides,r.result.result.appliedOverrides);
});
for(const [name,input]of [['SKIPPED',{...facts,status:'skipped'}],['NOT_CONFIGURED',{...facts,status:'not_configured'}],['ERROR',{...facts,status:'error'}]])
 checked(name+' is preserved without turning it into PASS',async()=>{
  const r=await resolved({},input),v=consume(r.packet,r.expected);
  assert.equal(v.result.status,name);assert.equal(v.result.decision,name==='ERROR'?'FAIL':null);
 });
checked('whole-pipeline ONCE requirement is NOT established by existing single-source API',async()=>{
 assert.throws(()=>evaluate([facts,{...facts,component:'trivy'}]),/POLICY_ERROR: invalid scanner facts/);
 let actualCalls=0;
 const observed=async input=>{actualCalls++;return evaluateAsync(input);};
 await observed(facts);await observed({...facts,status:'skipped',component:'trivy'});
 assert.equal(actualCalls,2);
 fs.writeFileSync(root+'single-evaluation-scope-gap.json',JSON.stringify({
  classification:'ACTUAL_EXISTING_ENGINE_API_PROBE',
  currentApi:'evaluate(facts,config) / evaluateAsync(facts,config), one component per call',
  arrayFactsRejected:true,twoIndependentSourceEvaluations:actualCalls,
  wholePipelineExistingEngineCallCountOneProven:false,
  noRelabelingOfBatchOwnerCallsAsEngineCalls:true,
  blocker:'Need explicit multi-source evaluation contract or approved per-source invariant; no existing aggregate Policy status implementation'
 },null,2));
});
const v1Observations=[];
for(const [component,file]of [
 ['security-approval-promotion','evidence/2026-11-01/promotion-parent/fixtures/candidate-sbom--valid.json'],
 ['regression','evidence/2026-11-01/regression-parent/fixtures/command--unchanged-current-suite.json'],
])checked('existing V1 read-only adapter accepts retained '+component+' evidence',async()=>{
 const document=JSON.parse(fs.readFileSync(file,'utf8')),raw=document.raw??document,before=JSON.stringify(raw);
 const output=evaluate({component,status:'success',raw});
 assert.equal(output.decision,'PASS');assert.equal(JSON.stringify(raw),before);
 v1Observations.push({component,input:file,decision:output.decision,rawUnchanged:true,classification:'EXISTING_FROZEN_INPUT_READ_ONLY_ADAPTER_EVALUATION',oldOperationExecuted:false});
});
// Pure version-selection model. There is NO V2 code, identity registration or production V2 hash.
const v1={identity:'SUMMARY_PRODUCER_V1',sha256:'038320f04c67fb1fe5ff711c11d445c2de88cc50b2230eb4c971bf46142f5b34'};
const v2={identity:'MODEL_ONLY_UNASSIGNED_V2',sha256:'MODEL_ONLY_NO_REAL_V2_HASH'};
const c1={generation:1,producer:v1},c2={generation:2,producer:v2};
for(const [name,p,c,valid,want]of [
 ['V1 with V1 contract',v1,c1,true,'ACCEPT'],
 ['model V2 with explicitly selected model V2 contract',v2,c2,true,'ACCEPT'],
 ['V2 with old contract',v2,c1,true,'POLICY_ERROR'],
 ['V1 with new V2-selected contract',v1,c2,true,'POLICY_ERROR'],
 ['unknown producer',{identity:'unknown',sha256:'unknown'},c2,true,'POLICY_ERROR'],
 ['missing producer identity',{sha256:v1.sha256},c1,true,'POLICY_ERROR'],
 ['tampered producer',{...v2,sha256:'tampered'},c2,true,'POLICY_ERROR'],
 ['correct model V2 identity with malformed metadata',v2,c2,false,'POLICY_ERROR'],
 ])checked('migration model: '+name,async()=>{
  if(want==='ACCEPT')assert.equal(migrationCheck(p,c,valid),want);else assert.throws(()=>migrationCheck(p,c,valid),/^Error: POLICY_ERROR:/);
 });
checked('migration model: rollback requires explicit whole V1 contract selection',async()=>{
 assert.equal(migrationCheck(v2,c2),'ACCEPT');assert.throws(()=>migrationCheck(v1,c2),/unsupported producer/);
 assert.equal(migrationCheck(v1,c1),'ACCEPT');
});
test.after(()=>{
 fs.writeFileSync(root+'model-test-results.json',JSON.stringify({classification:'DESIGN_HARNESS_ONLY',tests:records.length,pass:records.length,records,productionAcceptance:false,V2Created:false,newParentScannerSamples:0},null,2));
 fs.writeFileSync(root+'v1-readonly-observations.json',JSON.stringify({records:v1Observations,newParentScannerSamples:0},null,2));
});
