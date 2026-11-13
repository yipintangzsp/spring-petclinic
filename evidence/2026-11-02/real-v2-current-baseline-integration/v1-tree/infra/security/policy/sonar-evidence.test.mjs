import test from 'node:test';import assert from 'node:assert/strict';import fs from 'node:fs';
import {evaluate} from './engine.mjs';import {sonarEvidence} from './sonar-evidence.mjs';
const base='evidence/2026-11-01/sonar-policy/',raw=JSON.parse(fs.readFileSync(base+'analysis-bound-facts.json'));
const facts={component:'sonarqube',status:'success',raw};
test('real analysis-bound OK retains facts and matches actual Jenkins Gate PASSED',()=>{
 const old=JSON.parse(fs.readFileSync(base+'jenkins-analysis-binding.json')).builds.find(b=>b.build===270);
 assert.ok(old.gateLog.some(s=>s.includes('QUALITY GATE STATUS: PASSED')));
 assert.equal(raw.gate.projectStatus.status,'OK');assert.equal(raw.task.task.componentKey,'petclinic');
 const at=Date.parse(raw.task.task.executedAt);assert.ok(at>=old.timestamp);
 const before=JSON.stringify(raw),r=evaluate(facts);
 assert.equal(r.securityLevel,'standard');assert.equal(r.decision,'PASS');assert.equal(JSON.stringify(raw),before);
 assert.deepEqual(r.sonarEvidence.rawEvidence,raw);
 fs.writeFileSync(base+'positive-differential.json',JSON.stringify({status:'VERIFIED',scope:'Real OK sample only',jenkinsBuild:270,legacyGateLog:old.gateLog,analysisId:raw.task.task.analysisId,taskId:raw.task.task.id,legacyDecision:'PASS',standardDecision:r.decision,rawUnchanged:true},null,2));
});
test('task, project and analysis identities cannot be replaced or omitted',()=>{
 for(const mutate of [r=>r.binding.projectKey='other',r=>r.binding.taskId='other',r=>r.binding.requestedAnalysisId='other',r=>delete r.task.task.analysisId,r=>r.task.task.status='FAILED']){
  const r=structuredClone(raw);mutate(r);assert.throws(()=>sonarEvidence(r),/POLICY_ERROR/);
 }
});
test('missing condition facts or unsupported status is not treated as PASS',()=>{
 for(const mutate of [r=>delete r.gate.projectStatus.conditions[0].actualValue,r=>r.gate.projectStatus.status='NONE',r=>delete r.gate.projectStatus.conditions]){
  const r=structuredClone(raw);mutate(r);assert.throws(()=>sonarEvidence(r),/POLICY_ERROR/);
 }
});
test('synthetic ERROR mapping is contract-only, never a real failed-analysis verification',()=>{
 const r=structuredClone(raw);r.gate.projectStatus.status='ERROR';
 assert.equal(evaluate({...facts,raw:r}).decision,'FAIL');
 // This synthetic status is deliberately not saved as observed Sonar evidence.
});
test('levels do not recompute server decisions or modify its conditions',()=>{
 const before=JSON.stringify(raw);
 for(const securityLevel of ['low','standard','strict'])assert.equal(evaluate(facts,{securityLevel}).decision,'PASS');
 assert.equal(JSON.stringify(raw),before);
});
