import test from 'node:test';import assert from 'node:assert/strict';import fs from 'node:fs';import os from 'node:os';import path from 'node:path';import {spawnSync} from 'node:child_process';
import {evaluate} from './engine.mjs';import {replayBuildStage} from './build-provenance-replay.mjs';import {fixture,historical,sha,cmd} from './build-provenance-test-fixtures.mjs';
const out='evidence/2026-11-01/build-provenance-parent/',cases=[],records=[],steps=['stage','withEnv','credentials','status-write'];
function row(name,change,want,mode='enforce'){
 const p=historical.predicate,raw={workflow:true,classification:'CONTROLLED_REPLAY',cfg:{mode,enabled:true,image:p.candidateImage,commit:p.source.commit,repository:p.source.repository,builder:p.builder.identity,buildNumber:2},environment:{BUILD_NUMBER:'270',HARBOR_USER:'synthetic-user',HARBOR_PASS:'synthetic-password'},steps:Object.fromEntries(steps.map(k=>[k,{}]))},input=fixture('verify');change(raw,input);cases.push({name,raw,input,want});
}
for(const mode of ['audit','enforce']){
 row(mode+'-valid',()=>{},'PASS',mode);
 for(const k of ['image','commit','repository','builder','buildNumber'])row(mode+'-'+k+'-mismatch',r=>r.cfg[k]=k==='buildNumber'?3:k==='commit'?'b'.repeat(40):k==='image'?r.cfg.image.slice(0,-1)+'0':'other',mode==='audit'?'WARN':'FAIL',mode);
 row(mode+'-command-error',(_,i)=>i.commands.cosign[0]=cmd('',1),mode==='audit'?'WARN':'FAIL',mode);
 for(const key of steps)row(mode+'-Jenkins-step-failure-'+key,r=>r.steps[key]={error:'Jenkins step error'},'FAIL',mode);
 row(mode+'-build-nonnumeric',r=>r.environment.BUILD_NUMBER='bad','FAIL',mode);
 row(mode+'-build-overflow',r=>r.environment.BUILD_NUMBER='2147483648','FAIL',mode);
}
row('off-skip',r=>r.cfg.mode='off',null);row('enabled-absent-skip',r=>delete r.cfg.enabled,null);row('enabled-false-skip',r=>r.cfg.enabled=false,null);row('enabled-string-true-skip',r=>r.cfg.enabled='true',null);
row('mode-default-enforce',r=>delete r.cfg.mode,'PASS');row('invalid-mode-even-when-disabled',r=>{r.cfg.mode='unknown';r.cfg.enabled=false;},'FAIL');
row('whitespace-consumer-build-number',r=>r.environment.BUILD_NUMBER=' 270 ','PASS');
row('missing-image-audit-retains-WARN',r=>delete r.cfg.image,'WARN','audit');

const prepared=[];
for(const c of cases){
 const cfg=c.raw.cfg;c.operationEnvironment={...c.input.environment,...c.raw.environment,BUILD_PROVENANCE_IMAGE:String(cfg.image||''),BUILD_SOURCE_COMMIT:String(cfg.commit||''),BUILD_SOURCE_REPOSITORY:String(cfg.repository||''),BUILD_BUILDER_IDENTITY:String(cfg.builder||''),BUILD_SOURCE_NUMBER:String(cfg.buildNumber||'')};c.input.environment=c.operationEnvironment;
 const replay=await replayBuildStage(c.input);assert.ok(replay.facts.complete);c.raw.verificationFacts=replay.facts;c.exitCode=replay.facts.execution.exitCode;prepared.push({name:c.name,raw:c.raw,exitCode:c.exitCode});
}
const jar=process.env.PROVENANCE_GROOVY_JAR||'/tmp/provenance-policy-groovy/groovy-all-2.4.21.jar';assert.equal(sha(fs.readFileSync(jar)),'de65260cf2070442e99882f2f3d72e7531725c1e6a257446cc0cea525c607bd0');
const temp=fs.mkdtempSync(path.join(os.tmpdir(),'build-prov-groovy-'));let old;
try{const input=path.join(temp,'rows.json');fs.writeFileSync(input,JSON.stringify(prepared));const r=spawnSync('java',['-Xmx192m','-cp',jar,'groovy.ui.GroovyMain','infra/security/policy/build-provenance-workflow-oracle.groovy',input],{encoding:'utf8',timeout:60000,maxBuffer:8*1024*1024});assert.equal(r.status,0,r.stderr);old=JSON.parse(r.stdout);}finally{fs.rmSync(temp,{recursive:true,force:true});}
for(const c of cases)test('original Build Provenance Groovy '+c.name,()=>{
 const result=old.find(x=>x.name===c.name).result,before=JSON.stringify(c.raw),p=evaluate({component:'build-provenance',status:'success',raw:c.raw});assert.equal(result.decision,c.want,result.reason);assert.equal(p.decision,result.decision,p.reason);assert.equal(JSON.stringify(c.raw),before);assert.deepEqual(p.rawEvidence,c.raw);assert.equal(p.invoked,result.trace.length>0);if(result.report)assert.deepEqual(p.report,result.report);
 for(const call of result.trace)for(const key of ['BUILD_PROVENANCE_IMAGE','BUILD_SOURCE_COMMIT','BUILD_SOURCE_REPOSITORY','BUILD_BUILDER_IDENTITY','BUILD_SOURCE_NUMBER'])assert.equal(call.environment[key],c.operationEnvironment[key]);
 records.push({name:c.name,classification:'CONTROLLED_REPLAY',oldDecision:result.decision,standardDecision:p.decision,oldStatus:result.status==='SKIPPED'?'SKIPPED':result.decision,standardStatus:p.status,rawPreserved:true,actualGroovyExecuted:true,inputSha256:sha(before)});fs.writeFileSync(out+'fixtures/workflow--'+c.name+'.json',JSON.stringify(c.raw,null,2));
});
test('wrong facts cannot bind to different workflow identity',()=>{const r=structuredClone(cases[0].raw);r.cfg.builder='different';const result=evaluate({component:'build-provenance',status:'success',raw:r});assert.equal(result.status,'NOT_TESTED');assert.equal(result.decision,null);});
test.after(()=>fs.writeFileSync(out+'workflow-differential.json',JSON.stringify({records},null,2)));
