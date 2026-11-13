import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';import os from 'node:os';import path from 'node:path';
import {collectRuntimeFacts,validateRuntimeFacts} from './collector.mjs';
import {createRuntimeOwner} from './owner.mjs';
import {executionPayload} from './projection.mjs';
import {writeRuntimeArtifactCandidate} from './artifact-candidate.mjs';
import {digest} from '../summary-v2/codec.mjs';
import {mergeKyvernoPackets} from './kyverno-observer.mjs';
import {spawnSync} from 'node:child_process';
const binding={job:'controlled-owner-tests',build:1,project:'fixture',source:'a'.repeat(40),candidate:'registry.invalid/fixture@sha256:'+'b'.repeat(64),targetScope:'project',runId:'test-1'};
const execution={command:'original-observed-command',exitStatus:0,signal:null,errorClass:null};
const envelope=(id='regression',presence='executed',payload)=>collectRuntimeFacts({sourceId:id,binding,execution:{...execution,...(presence==='executed'?{}:{exitStatus:null,reason:'explicit controlled presence'})},presence,payload:payload??executionPayload({sourceId:id,command:'node --test --test-concurrency=1 infra/observability/*.test.mjs infra/security/*.test.mjs',exitStatus:0,stdout:'controlled',stderr:''})});
function temp(){const directory=fs.mkdtempSync(path.join(os.tmpdir(),'runtime-owner-'));return {directory,dispose:()=>fs.rmSync(directory,{recursive:true,force:true})};}
test('fact envelope binds same payload/command, never adds a decision',()=>{const e=envelope();assert.equal(e.rawFactDigest,digest(e.facts));assert.equal(e.decision,undefined);assert.deepEqual(validateRuntimeFacts(e,binding),e);});
test('missing execution status and unknown/alias/post sources reject',()=>{
 for(const id of ['semgrep','security-approval-promotion','unknown'])assert.throws(()=>envelope(id),/noncanonical/);
 assert.throws(()=>collectRuntimeFacts({sourceId:'regression',binding,execution:{command:'x',exitStatus:null,signal:null,errorClass:null},payload:{}}),/not terminal/);
});
test('stale binding rejects before owner invocation',()=>assert.throws(()=>validateRuntimeFacts(envelope(),{...binding,build:2}),/stale/));
test('tampered facts reject even if envelope digest alone is recalculated',()=>{const e=structuredClone(envelope());e.facts.raw.stdout='tamper';const {envelopeDigest,...body}=e;e.envelopeDigest=digest(body);assert.throws(()=>validateRuntimeFacts(e,binding),/integrity/);});
test('real owner claims once and Gate reuses result identity without evaluation',async()=>{
 const t=temp();try{const o=createRuntimeOwner({binding,directory:t.directory}),e=envelope();const r=await o.accept(e);const g=o.reuseForGate('regression','success');assert.equal(g.resultDigest,r.resultDigest);assert.equal(o.snapshot().evaluationCounts.regression,1);assert.equal(o.snapshot().complete,false);
 await assert.rejects(o.accept(e),/EEXIST/);assert.equal(o.snapshot().evaluationCounts.regression,1);assert.throws(()=>o.reuseForGate('regression','success'),/duplicate Gate/);
 }finally{t.dispose();}
});
test('concurrent duplicate rejected before second Engine invocation',async()=>{const t=temp();try{const o=createRuntimeOwner({binding,directory:t.directory});const first=o.accept(envelope());await assert.rejects(o.accept(envelope()),/EEXIST/);await first;assert.equal(o.snapshot().evaluationCounts.regression,1);}finally{t.dispose();}});
test('second owner/process claim and incomplete owner restart fail closed',()=>{const t=temp();try{createRuntimeOwner({binding,directory:t.directory});assert.throws(()=>createRuntimeOwner({binding,directory:t.directory}),/EEXIST/);}finally{t.dispose();}});
test('success native report without source-specific facts cannot become Gate PASS',async()=>{const t=temp();try{const o=createRuntimeOwner({binding,directory:t.directory});const r=await o.accept(envelope('sops','executed',{status:'success'}));assert.equal(r.evidenceComplete,false);assert.equal(r.result.status,'NOT_CONFIGURED');assert.equal(r.result.decision,null);assert.throws(()=>o.reuseForGate('sops','success'),/incomplete/);}finally{t.dispose();}});
test('shell success is never synthesized into complete scanner parent facts',async()=>{
 for(const sourceId of ['gitleaks','semgrep-command-audit','trivy','zap','sbom']){
  const raw=executionPayload({sourceId,command:'true',exitStatus:0,stdout:'success',stderr:''});
  assert.equal(raw.captureStatus,'SOURCE_SPECIFIC_OBSERVATIONS_UNAVAILABLE');assert.equal(raw.complete,undefined);assert.equal(raw.module,undefined);
  const t=temp();try{const o=createRuntimeOwner({binding,directory:t.directory}),r=await o.accept(envelope(sourceId,'executed',raw));
   assert.notEqual(r.result?.decision,'PASS');assert.throws(()=>o.reuseForGate(sourceId,'success'),/drift|incomplete/);
  }finally{t.dispose();}
 }
});
test('missing canonical sources cannot produce immutable complete artifact',async()=>{const t=temp();try{const o=createRuntimeOwner({binding,directory:t.directory});await o.accept(envelope());o.reuseForGate('regression','success');assert.throws(()=>writeRuntimeArtifactCandidate({snapshot:o.snapshot()}),/incomplete/);}finally{t.dispose();}});
for(const presence of ['skipped','not_configured','error'])test('observed presence preserved: '+presence,async()=>{const t=temp();try{const o=createRuntimeOwner({binding,directory:t.directory}),r=await o.accept(envelope('regression',presence,{}));assert.equal(r.result.status,presence.toUpperCase());assert.equal(r.result.decision,presence==='error'?'FAIL':null);}finally{t.dispose();}});
test('POLICY_ERROR preserved and Gate refuses using it as legacy success',async()=>{const t=temp();try{const o=createRuntimeOwner({binding,directory:t.directory,config:{profile:'typo'}}),r=await o.accept(envelope());assert.equal(r.result,null);assert.equal(r.error.code,'POLICY_ERROR');assert.throws(()=>o.reuseForGate('regression','success'),/drift/);}finally{t.dispose();}});
test('raw source payload is never written in owner capture/receipt files',async()=>{const t=temp();try{const marker='SYNTHETIC_SENSITIVE_VALUE_MUST_NOT_BE_PERSISTED';const o=createRuntimeOwner({binding,directory:t.directory});const r=await o.accept(envelope('regression','executed',{...envelope().facts.raw,stdout:marker}));assert.ok(r.rawFactDigest);for(const f of fs.readdirSync(t.directory))assert.ok(!fs.readFileSync(path.join(t.directory,f),'utf8').includes(marker));}finally{t.dispose();}});
test('collector graph has no Policy evaluator or decision classification',()=>{const source=fs.readFileSync(new URL('./collector.mjs',import.meta.url),'utf8');assert.doesNotMatch(source,/from .*policy\/|evaluate\(/);});
test('Regression result identity is deterministic for equivalent facts and binding in isolated replays',async()=>{
 const a=temp(),b=temp();try{
  const first=createRuntimeOwner({binding,directory:a.directory}),second=createRuntimeOwner({binding,directory:b.directory});
  const r=await first.accept(envelope()),s=await second.accept(envelope());assert.equal(r.resultDigest,s.resultDigest);
  assert.equal(first.reuseForGate('regression','success').resultDigest,r.resultDigest);assert.equal(second.reuseForGate('regression','success').resultDigest,s.resultDigest);
  assert.equal(first.snapshot().evaluationCounts.regression,1);assert.equal(second.snapshot().evaluationCounts.regression,1);
 }finally{a.dispose();b.dispose();}
});
test('Kyverno two-command collection preserves original observations without a decision',()=>{
 const r={schema:1,sourceId:'kyverno',phase:'rbac',exitStatus:0,configuration:{},observations:{rbac:[{status:0,stdout:'original'}],sourceReadSucceeded:true,rbacReportWriteSucceeded:true},events:[]};
 const a={schema:1,sourceId:'kyverno',phase:'admission',exitStatus:0,configuration:{tools:{},baseline:{},exceptions:{}},observations:{rbac:[],probes:[{status:1,stderr:'original denial'}]},events:[]};
 const before=digest([r,a]),p=mergeKyvernoPackets([r,a]);assert.equal(digest([r,a]),before);assert.deepEqual(p.adapterPayload.observations.rbac,r.observations.rbac);assert.deepEqual(p.adapterPayload.observations.probes,a.observations.probes);assert.equal(p.adapterPayload.decision,undefined);
 assert.throws(()=>mergeKyvernoPackets([r,r]),/Duplicate/);assert.throws(()=>mergeKyvernoPackets([a,r]),/reordered/);assert.throws(()=>mergeKyvernoPackets([r]),/missing admission/);
});
test('Kyverno failed first command cannot be followed by invented admission observations',()=>{
 const r={schema:1,sourceId:'kyverno',phase:'rbac',exitStatus:1,configuration:{},observations:{rbac:[{status:1,stderr:'actual failure'}]},events:[]};
 assert.equal(mergeKyvernoPackets([r]).adapterPayload.observations.configurationReadSucceeded,false);
 assert.throws(()=>mergeKyvernoPackets([r,{...r,phase:'admission'}]),/after RBAC failure/);
});
test('passive Kyverno observer reads original tools-lock, preserving process exit and bytes',()=>{
 const t=temp();try{
  const file=path.join(t.directory,'admission-gate.mjs');
  fs.writeFileSync(file,"import fs from 'node:fs';fs.readFileSync('infra/security/tools-lock.json');fs.readFileSync('infra/security/scanner-tools.json');console.log('ORIGINAL_OUTPUT');");
  const observer=new URL('./observe.mjs',import.meta.url).pathname;
  const r=spawnSync(process.execPath,['--import='+observer,file],{encoding:'utf8',env:{...process.env,RUNTIME_FACT_SOURCE:'kyverno'},stdio:['ignore','pipe','pipe','pipe']});
  assert.equal(r.status,0);assert.equal(r.stdout,'ORIGINAL_OUTPUT\n');assert.equal(r.stderr,'');
  const p=JSON.parse(r.output[3]);assert.equal(p.phase,'admission');
  assert.deepEqual(p.configuration.tools,JSON.parse(fs.readFileSync('infra/security/tools-lock.json')));assert.ok(p.configuration.tools.gitleaks);
 }finally{t.dispose();}
});
test('Falco first baseline prerequisite clock is never replaced by later query clocks',()=>{
 const t=temp();try{
  fs.writeFileSync(path.join(t.directory,'.git-sha'),'c'.repeat(40));
  const file=path.join(t.directory,'clock.mjs');fs.writeFileSync(file,"import fs from 'node:fs';fs.readFileSync('.git-sha');const first=Date.now();await new Promise(r=>setTimeout(r,5));const second=Date.now();console.log(JSON.stringify({first,second}));");
  const r=spawnSync(process.execPath,['--import='+new URL('./observe.mjs',import.meta.url).pathname,file],{cwd:t.directory,encoding:'utf8',env:{...process.env,RUNTIME_FACT_SOURCE:'falco-baseline'},stdio:['ignore','pipe','pipe','pipe']});
  assert.equal(r.status,0);const clocks=JSON.parse(r.stdout),p=JSON.parse(r.output[3]);assert.ok(clocks.second>clocks.first);assert.equal(p.adapterPayload.now,clocks.first);
 }finally{t.dispose();}
});
