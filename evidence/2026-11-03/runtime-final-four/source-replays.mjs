// Accepted whole-Gate Falco replay plus redacted SOPS archive SHAPE only.
// Neither is labeled as a fresh live pipeline observation.
import fs from 'node:fs';import vm from 'node:vm';import os from 'node:os';import path from 'node:path';import assert from 'node:assert/strict';
import {runtimeWindow,persistentRuntime} from '../../../infra/security/runtime/event-policy.mjs';
import {validatePriorExit,validateRuntimeContinuity,driverDiagnostics} from '../../../infra/security/runtime/health-contract.mjs';
import {collectRuntimeFacts,validateRuntimeFacts} from '../../../infra/security/runtime-facts/collector.mjs';
import {createRuntimeOwner} from '../../../infra/security/runtime-facts/owner.mjs';
import {digest,sha} from '../../../infra/security/summary-v2/codec.mjs';
const root=new URL('../../../',import.meta.url),out=new URL('./',import.meta.url),repair=new URL('evidence/2026-11-02/falco-time-contract-repair/',root);
const read=p=>JSON.parse(fs.readFileSync(p));
const body=fs.readFileSync(new URL('infra/security/runtime/health.mjs',root),'utf8').replace(/^import .*;\s*$/gm,'');
const harness=fs.readFileSync(new URL('timing-matrix.mjs',repair),'utf8');
const fn=harness.slice(harness.indexOf('async function original('),harness.indexOf("fs.mkdirSync(new URL('fixtures/',out)"));
const original=vm.runInNewContext('('+fn.trim()+')',{Date,body,assert,vm,runtimeWindow,persistentRuntime,validatePriorExit,validateRuntimeContinuity,driverDiagnostics,AbortSignal});
const refs=read(new URL('timing-after.json',repair)).records,records=[],sops=[];
const binding=(id)=>({job:'controlled-source-replay',build:1,project:'fixture',source:'c'.repeat(40),candidate:'registry.invalid/fixture@sha256:'+'a'.repeat(64),targetScope:'candidate',runId:id});
for(const mode of ['baseline','check'])for(const kind of ['normal','original-2s-boundary']){
 const ref=refs.find(r=>r.mode===mode&&(kind==='normal'?r.oldDecision==='PASS':r.originalDiscoveryCase));assert.ok(ref);
 let raw=read(new URL(ref.fixture,repair));const old=await original(raw,kind==='normal'?{}:{firstWorkloadMs:2000});raw=JSON.parse(JSON.stringify(raw));
 const before=digest(raw),sourceId=mode==='baseline'?'falco-baseline':'falco-final',b=binding(mode+'-'+kind);
 const envelope=collectRuntimeFacts({sourceId,binding:b,execution:{command:'ACCEPTED_WHOLE_GATE_REPLAY',exitStatus:old.oldDecision==='PASS'?0:1,signal:null,errorClass:null},payload:raw,evidence:[{classification:'CONTROLLED_ACCEPTED_GATE_REPLAY_NOT_LIVE_RUNTIME',fixture:ref.fixture,observerFunctionSha256:sha(fn)}]});
 const directory=fs.mkdtempSync(path.join(os.tmpdir(),'runtime-falco-replay-'));
 try{
  const owner=createRuntimeOwner({binding:b,directory}),r=await owner.accept(envelope),g=owner.reuseForGate(sourceId,old.oldDecision==='PASS'?'success':'failed');
  assert.equal(r.result.decision,old.oldDecision);assert.equal(g.resultDigest,r.resultDigest);assert.equal(owner.snapshot().evaluationCounts[sourceId],1);assert.equal(digest(raw),before);
  if(kind==='original-2s-boundary')assert.equal(old.oldDecision,'FAIL');
  records.push({sourceId,kind,classification:'CONTROLLED_ACCEPTED_GATE_REPLAY_NOT_LIVE_RUNTIME',oldDecision:old.oldDecision,policyDecision:r.result.decision,resultDigest:r.resultDigest,gateResultDigest:g.resultDigest,evaluationCount:1,rawPreserved:true,windowEndMs:raw.observations.samples.map(s=>s.windowEndMs)});
 }finally{fs.rmSync(directory,{recursive:true,force:true});}
}
for(const file of ['01-POSITIVE_FULL_PATH-execution.json','03-DECRYPT_ERROR-execution.json','11-TOOL_MISSING-execution.json']){
 const reference=new URL('evidence/2026-11-02/sops-authoritative-differential-02/'+file,root),archive=read(reference),raw=archive.result.rawEvidence.facts;
 const before=digest(raw),b=binding(file),e=collectRuntimeFacts({sourceId:'sops',binding:b,execution:{command:'ACCEPTED_REDACTED_ARCHIVE_SHAPE',exitStatus:archive.child.exit.code,signal:null,errorClass:null},payload:raw,evidence:[{classification:'HISTORICAL_CONTROLLED_EXECUTION_REDACTED_SHAPE_ONLY',path:reference.pathname,sha256:sha(fs.readFileSync(reference))}]});
 assert.deepEqual(validateRuntimeFacts(e,b).facts.raw,raw);assert.equal(digest(raw),before);
 assert.ok(raw.prerequisites);assert.ok(Array.isArray(raw.targets));assert.equal(raw.expectedTargetCount,4);
 // Positive decryption stdout is already redacted by its accepted archive.
 // Never turn its digest into plaintext or feed the redaction to the Engine.
 if(file.startsWith('01')){assert.equal(typeof raw.targets[0].decrypt.stdout,'object');assert.ok(raw.rbac);assert.ok(raw.verifierRbac);}
 if(file.startsWith('03'))assert.notEqual(raw.targets[0].decrypt.exitStatus,0);
 if(file.startsWith('11'))assert.equal(raw.prerequisites.tools,false);
 sops.push({file,classification:'HISTORICAL_CONTROLLED_EXECUTION_REDACTED_SHAPE_ONLY',rawFactDigest:e.rawFactDigest,archiveSha256:sha(fs.readFileSync(reference)),rawPreserved:true,policyReevaluation:'NOT_PERFORMED_REDACTED_CONTENT_IS_NOT_RAW_SECRET',freshGateExecution:false,productionSecretAccess:0});
}
fs.writeFileSync(new URL('source-replay-results.json',out),JSON.stringify({falco:{samples:records.length,match:records.length,drift:0,records},sops:{shapes:sops.length,records:sops,productionSecretAccess:0,keyAccess:0},temporaryReplayDirectoriesRemoved:true},null,2)+'\n');
console.log(JSON.stringify({falcoReplayMatch:records.length,falcoReplayDrift:0,sopsRedactedArchiveShapes:sops.length,newSopsExecution:0}));
