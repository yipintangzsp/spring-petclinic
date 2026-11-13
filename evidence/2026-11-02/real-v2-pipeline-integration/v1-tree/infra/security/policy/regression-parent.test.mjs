import test from 'node:test';import assert from 'node:assert/strict';import fs from 'node:fs';import os from 'node:os';import path from 'node:path';import crypto from 'node:crypto';import {spawnSync} from 'node:child_process';
import {evaluate} from './engine.mjs';
const base='evidence/2026-11-01/regression-parent/',sha=x=>crypto.createHash('sha256').update(x).digest('hex'),read=p=>JSON.parse(fs.readFileSync(p)),command=read('resources/security-manager/petclinic-adapter.json').find(x=>x.id==='regression').command,records=[];
const executions=read(base+'controlled-executions.json').records;
for(const row of executions)test('actual original Regression command '+row.name,()=>{
 const raw=read(base+'fixtures/'+row.fixture),before=JSON.stringify(raw),p=evaluate({component:'regression',status:'success',raw});assert.equal(p.decision,row.oldDecision);assert.equal(p.securityLevel,'standard');assert.equal(JSON.stringify(raw),before);assert.deepEqual(p.rawEvidence,raw);
 records.push({name:row.name,stage:'command',classification:raw.classification,oldDecision:row.oldDecision,standardDecision:p.decision,rawPreserved:true,inputSha256:sha(before),originalExecution:true,fixture:row.fixture});
});
// The existing Manager shell wrapper is executed as-is, with only node replaced by an inert fixture.
function shell(name,status,options={}){
 const dir=fs.mkdtempSync(path.join(os.tmpdir(),'regression-shell-'));try{
  fs.mkdirSync(path.join(dir,'.devsecops/gates'),{recursive:true});if(options.redirectionFailure)fs.mkdirSync(path.join(dir,'.devsecops/gates/regression.log'));
  fs.writeFileSync(path.join(dir,'node'),'#!/bin/sh\nprintf "%s\\n" "$FAKE_OUTPUT"\nprintf "%s\\n" "$*" > "$CALLS"\nexit "$FIXTURE_STATUS"\n',{mode:0o700});
  // cat failure must not override explicit final exit "$rc" in the unchanged production wrapper.
  fs.writeFileSync(path.join(dir,'cat'),options.catFailure?'#!/bin/sh\necho "readback failed" >&2\nexit 1\n':'#!/bin/sh\n/bin/cat "$@"\n',{mode:0o700});
  const script='set +e\n'+command+' > .devsecops/gates/regression.log 2>&1\nrc=$?\ncat .devsecops/gates/regression.log\nexit "$rc"';
  const r=spawnSync('/bin/sh',['-c',script],{cwd:dir,env:{PATH:options.noNode?'/nonexistent':dir,CALLS:path.join(dir,'calls'),FIXTURE_STATUS:String(status),FAKE_OUTPUT:options.text??'fixture output'},encoding:'utf8',timeout:5000});
  return {schema:1,stage:'command',classification:'CONTROLLED_REPLAY',collector:'unchanged-production-shell-with-inert-node',complete:true,command,execution:{status:r.status,signal:r.signal,error:r.error?String(r.error):null},stdout:r.stdout??'',stderr:r.stderr??'',originalWrapper:script,nodeInvocation:fs.existsSync(path.join(dir,'calls'))?fs.readFileSync(path.join(dir,'calls'),'utf8'):null,note:'Inert node output is synthetic, not historical test execution'};
 }finally{fs.rmSync(dir,{recursive:true,force:true});}
}
for(const [name,status,options,want]of [
 ['zero-success',0,{},'PASS'],['one-failure',1,{},'FAIL'],['two-execution-error',2,{},'FAIL'],['nonzero-ten-not-WARN',10,{},'FAIL'],['missing-node',0,{noNode:true},'FAIL'],['137-not-claimed-real-OOM',137,{},'FAIL'],['143-not-claimed-real-signal',143,{},'FAIL'],['log-redirection-failed',0,{redirectionFailure:true},'FAIL'],['log-readback-error-final-exit-stays-zero',0,{catFailure:true},'PASS'],['TAP-looking-FAIL-text-not-parsed',0,{text:'# tests 1\n# fail 1'},'PASS'],['TAP-looking-PASS-does-not-hide-nonzero',1,{text:'# tests 147\n# pass 147\n# fail 0'},'FAIL'],['empty-output-exit-zero-not-new-parser-rule',0,{text:''},'PASS'],
])test('exact Regression parent shell '+name,()=>{
 const raw=shell(name,status,options),old=raw.execution.status===0?'PASS':'FAIL',before=JSON.stringify(raw),p=evaluate({component:'regression',status:'success',raw});assert.equal(old,want);assert.equal(p.decision,old);assert.deepEqual(p.rawEvidence,raw);assert.equal(JSON.stringify(raw),before);
 const file='shell--'+name+'.json';fs.writeFileSync(base+'fixtures/'+file,JSON.stringify(raw,null,2));records.push({name,stage:'shell',classification:'CONTROLLED_REPLAY',oldDecision:old,standardDecision:p.decision,rawPreserved:true,inputSha256:sha(before),originalWrapperExecuted:true,fixture:file});
});
const wrappers=[];
function wrapper(name,change,want){const raw={cfg:{adapter:'petclinic',mode:'enforce'},steps:Object.fromEntries(['credentials','module-stage','gate','manager-write','archive','scan-sh'].map(k=>[k,{}]))},operation=executions.find(x=>x.name==='unchanged-current-suite');const row={name,raw,operationExitCode:read(base+'fixtures/'+operation.fixture).execution.status,want};change(row);wrappers.push(row);}
wrapper('production-pass',()=>{},'PASS');wrapper('production-regression-failure',r=>r.operationExitCode=1,'FAIL');wrapper('production-execution-error',r=>r.operationExitCode=127,'FAIL');wrapper('production-exit10-not-WARN',r=>r.operationExitCode=10,'FAIL');
for(const step of ['credentials','module-stage','gate','manager-write','archive','scan-sh'])wrapper('wrapper-'+step+'-failure',r=>r.raw.steps[step]={error:'controlled original Jenkins step error'},'FAIL');
wrapper('production-mode-audit-rejected',r=>r.raw.cfg.mode='audit','FAIL');wrapper('production-mode-off-rejected',r=>r.raw.cfg.mode='off','FAIL');wrapper('unknown-regression-disable-rejected',r=>r.raw.cfg.disabledModules=['regression'],'FAIL');
const jar=process.env.PROVENANCE_GROOVY_JAR||'/tmp/provenance-policy-groovy/groovy-all-2.4.21.jar';assert.equal(sha(fs.readFileSync(jar)),'de65260cf2070442e99882f2f3d72e7531725c1e6a257446cc0cea525c607bd0');
const dir=fs.mkdtempSync(path.join(os.tmpdir(),'regression-groovy-'));let legacy;
try{const file=path.join(dir,'input.json');fs.writeFileSync(file,JSON.stringify(wrappers));const r=spawnSync('java',['-Xmx192m','-cp',jar,'groovy.ui.GroovyMain','infra/security/policy/regression-workflow-oracle.groovy',file],{encoding:'utf8',timeout:60000,maxBuffer:8*1024*1024});assert.equal(r.status,0,r.stderr);legacy=JSON.parse(r.stdout);}finally{fs.rmSync(dir,{recursive:true,force:true});}
for(const row of wrappers)test('unchanged original Manager Regression '+row.name,()=>{
 const old=legacy.find(x=>x.name===row.name),oldDecision=old.failed?'FAIL':'PASS';assert.equal(oldDecision,row.want,old.reason);
 const raw={schema:1,stage:'wrapper',complete:true,classification:'CONTROLLED_REPLAY',execution:{failed:old.failed,reason:old.reason},module:old.module,observations:old.trace},before=JSON.stringify(raw),p=evaluate({component:'regression',status:'success',raw});assert.equal(p.decision,oldDecision);assert.deepEqual(p.rawEvidence,raw);assert.equal(JSON.stringify(raw),before);
 const file='wrapper--'+row.name+'.json';fs.writeFileSync(base+'fixtures/'+file,JSON.stringify(raw,null,2));records.push({name:row.name,stage:'wrapper',classification:'CONTROLLED_REPLAY',oldDecision,standardDecision:p.decision,rawPreserved:true,inputSha256:sha(before),originalGroovyExecuted:true,fixture:file});
});
const good=()=>read(base+'fixtures/'+executions[0].fixture);
for(const [name,change]of [['absent-completion',r=>r.complete=false],['missing-exit-observation',r=>delete r.execution.status],['unknown-completion',r=>{r.execution.status=null;r.execution.signal=null;r.execution.error=null;}],['uncaptured-output',r=>delete r.stdout],['different-command-not-this-contract',r=>r.command='node --test other-tests.mjs'],['unsupported-stage',r=>r.stage='other']])test('missing Regression proof '+name,()=>{const raw=good();change(raw);const result=evaluate({component:'regression',status:'success',raw});assert.equal(result.status,'NOT_TESTED');assert.equal(result.decision,null);});
test('frozen Regression FAIL cannot be softened by low / strict / override / audit',()=>{const raw=read(base+'fixtures/command--enforcement-regression.json');for(const config of [{securityLevel:'low'},{securityLevel:'strict'},{mode:'audit',componentOverrides:{regression:{High:'PASS'}}}])assert.equal(evaluate({component:'regression',status:'success',raw},config).decision,'FAIL');});
test('no circular Policy self-validation in production Regression imports',()=>{
 const inventory=read(base+'production-test-inventory.json');assert.equal(inventory.fileCount,35);assert.ok(inventory.files.every(x=>!x.usesPolicyEngine));const script=fs.readFileSync('infra/security/policy/regression-evidence.mjs','utf8');assert.ok(!/from ['"].*(?:engine|scanner|child_process)/.test(script));assert.equal(inventory.policyTestsIncluded,false);
});
test.after(()=>fs.writeFileSync(base+'differential.json',JSON.stringify({records},null,2)));
