import test from 'node:test';import assert from 'node:assert/strict';import fs from 'node:fs';import os from 'node:os';import path from 'node:path';import crypto from 'node:crypto';import {spawnSync} from 'node:child_process';
import {evaluate} from './engine.mjs';import {fixture,oracle,predicate,sha} from './provenance-test-harness.mjs';
const out='evidence/2026-11-01/provenance-parent/',records=[],cases=[],steps=['source-withEnv','operations-withEnv','stage-generate','stage-create','stage-verify','credentials-create','credentials-verify','status-write'];
function workflow(mode='enforce'){
 const env=fixture('verify').environment;
 return {classification:'CONTROLLED_REPLAY',workflow:true,cfg:{mode},environment:env,params:{ENABLE_PROVENANCE:true,AUDIT_CANDIDATE_IMAGE:predicate.candidateImage},git:{repository:{value:predicate.repository+'\n'},commit:{value:predicate.commit+'\n'}},steps:Object.fromEntries(steps.map(k=>[k,{}])),operations:Object.fromEntries(['generate','create','verify'].map(a=>[a,fixture(a)]))};
}
function row(name,change,want,mode='enforce'){const raw=workflow(mode);change(raw);cases.push({name,raw,want});}
for(const mode of ['enforce','audit']){
 row(mode+'-success',()=>{},'PASS',mode);
 for(const action of ['generate','create','verify'])row(mode+'-'+action+'-failure',r=>{r.operations[action].io['output-mkdir']={error:'controlled failure'};},mode==='audit'?'WARN':'FAIL',mode);
 for(const step of steps)row(mode+'-step-exception-'+step,r=>r.steps[step]={error:'controlled Jenkins step failure'},'FAIL',mode);
 row(mode+'-git-commit-failure',r=>r.git.commit={error:'git failed'},'FAIL',mode);
 row(mode+'-git-repository-failure',r=>r.git.repository={error:'git failed'},'FAIL',mode);
 row(mode+'-invalid-build-number',r=>r.environment.BUILD_NUMBER='not-a-number','FAIL',mode);
 row(mode+'-truncated-build-number-forbidden',r=>r.environment.BUILD_NUMBER='270.2','FAIL',mode);
 row(mode+'-overflow-build-number',r=>r.environment.BUILD_NUMBER='2147483648','FAIL',mode);
 row(mode+'-source-mismatch',r=>r.git.commit.value='b'.repeat(40),mode==='audit'?'WARN':'FAIL',mode);
}
row('whitespace-build-number',r=>{r.environment.BUILD_NUMBER=' 270 ';r.environment.HEAVY_HOLDER='jenkins-petclinic-270';},'PASS');
row('off-skips-every-operation',r=>r.cfg.mode='off',null);
row('default-disabled',r=>{delete r.params.ENABLE_PROVENANCE;},null);
row('params-false-beats-env-and-cfg',r=>{r.params.ENABLE_PROVENANCE=false;r.environment.ENABLE_PROVENANCE='true';r.cfg.enableProvenance=true;},null);
row('params-string-true-is-not-boolean',r=>r.params.ENABLE_PROVENANCE='true',null);
row('env-true',r=>{delete r.params.ENABLE_PROVENANCE;r.environment.ENABLE_PROVENANCE='true';},'PASS');
row('env-false-beats-cfg-true',r=>{delete r.params.ENABLE_PROVENANCE;r.environment.ENABLE_PROVENANCE='false';r.cfg.enableProvenance=true;},null);
row('cfg-explicit-true',r=>{delete r.params.ENABLE_PROVENANCE;r.cfg.enableProvenance=true;},'PASS');
row('mode-absent-default-enforce',r=>delete r.cfg.mode,'PASS');
row('invalid-mode-errors-even-disabled',r=>{r.cfg.mode='invalid';r.params.ENABLE_PROVENANCE=false;},'FAIL');
row('explicit-repository-avoids-git-repository-query',r=>{r.cfg.repository=predicate.repository;r.git.repository={error:'must not be read'};},'PASS');
row('cfg-candidate-priority',r=>{r.cfg.candidateImage=predicate.candidateImage;r.params.AUDIT_CANDIDATE_IMAGE='core.harbor.domain/other@sha256:'+'a'.repeat(64);},'PASS');
row('cfg-image-fallback',r=>{delete r.params.AUDIT_CANDIDATE_IMAGE;r.cfg.image=predicate.candidateImage;},'PASS');
row('candidate-absent-fails-generation',r=>delete r.params.AUDIT_CANDIDATE_IMAGE,'FAIL');
row('audit-failure-then-stage-exception-still-FAIL',r=>{r.operations.generate.io['output-mkdir']={error:'failed'};r.steps['stage-verify']={error:'stage error'};},'FAIL','audit');
const prepared=[];
for(const c of cases){
 const r=c.raw,repository=r.cfg.repository||r.git.repository?.value?.trim()||'',commit=r.git.commit?.value?.trim()||'',candidate=r.cfg.candidateImage||r.params.AUDIT_CANDIDATE_IMAGE||r.cfg.image||'';
 c.operationEnvironment={...r.environment,PROVENANCE_CANDIDATE:candidate,PROVENANCE_REPOSITORY:repository,PROVENANCE_COMMIT:commit};c.exitCodes={};
 for(const action of ['generate','create','verify']){const facts=structuredClone(r.operations[action]);facts.environment=c.operationEnvironment;const old=await oracle(facts);assert.notEqual(old.decision,null);c.exitCodes[action]=old.decision==='PASS'?0:1;}
 prepared.push({name:c.name,raw:r,exitCodes:c.exitCodes});
}
const jar=process.env.PROVENANCE_GROOVY_JAR||'/tmp/provenance-policy-groovy/groovy-all-2.4.21.jar';
assert.ok(fs.existsSync(jar),'Pinned local Groovy jar required; see Provenance compatibility report for setup. No automatic downloads in tests.');
assert.equal(sha(fs.readFileSync(jar)),'de65260cf2070442e99882f2f3d72e7531725c1e6a257446cc0cea525c607bd0','Groovy runner digest mismatch');
const tmp=fs.mkdtempSync(path.join(os.tmpdir(),'provenance-workflow-test-'));let legacy;
try{
 const input=path.join(tmp,'input.json');fs.writeFileSync(input,JSON.stringify(prepared));
 const result=spawnSync('java',['-Xmx192m','-cp',jar,'groovy.ui.GroovyMain','infra/security/policy/provenance-workflow-oracle.groovy',input],{encoding:'utf8',timeout:60000,maxBuffer:8*1024*1024});assert.equal(result.status,0,result.stderr);legacy=JSON.parse(result.stdout);
}finally{fs.rmSync(tmp,{recursive:true,force:true});}
for(const c of cases)test('unchanged Groovy Provenance workflow '+c.name,()=>{
 const old=legacy.find(x=>x.name===c.name).result,before=JSON.stringify(c.raw),p=evaluate({component:'provenance',status:'success',raw:c.raw});assert.equal(old.decision,c.want,old.reason);assert.equal(p.decision,old.decision,p.reason);assert.equal(JSON.stringify(c.raw),before);assert.deepEqual(p.rawEvidence,c.raw);
 assert.deepEqual(p.invoked,old.trace.map(x=>x.action));if(old.report)assert.deepEqual(p.report,old.report);
 for(const invocation of old.trace)assert.deepEqual(invocation.environment,c.operationEnvironment);
 records.push({name:c.name,classification:'CONTROLLED_REPLAY',oldDecision:old.decision,standardDecision:p.decision,oldStatus:old.report?.status==='skipped'?'SKIPPED':old.decision,standardStatus:p.status,invoked:p.invoked,rawPreserved:true,originalGroovyExecuted:true,inputSha256:sha(before),legacyReason:old.reason,policyReason:p.reason});
 fs.writeFileSync(out+'fixtures/workflow--'+c.name+'.json',JSON.stringify(c.raw,null,2));
});
test('incomplete workflow evidence is not PASS',()=>{const r=workflow();delete r.steps['status-write'];const p=evaluate({component:'provenance',status:'success',raw:r});assert.equal(p.status,'NOT_TESTED');assert.equal(p.decision,null);});
test('workflow refuses wrong operation/action evidence binding',()=>{const r=workflow();r.operations.generate.action='verify';const p=evaluate({component:'provenance',status:'success',raw:r});assert.equal(p.decision,null);assert.equal(p.status,'NOT_TESTED');});
test.after(()=>fs.writeFileSync(out+'workflow-differential.json',JSON.stringify({runner:{version:'Groovy 2.4.21, local JVM with inert Jenkins DSL; no Jenkins CPS execution',sha256:sha(fs.readFileSync(jar))},records},null,2)));
