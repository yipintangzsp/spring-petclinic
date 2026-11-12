import test from 'node:test';import assert from 'node:assert/strict';
import {buildKyvernoFact,buildKyvernoRuntimeFacts,buildKyvernoEvidenceRefs,validateKyvernoPacket,kyvernoProjects} from './kyverno-real.mjs';
import {evaluate} from '../policy/engine.mjs';
const project=kyvernoProjects()['kyverno-supply-chain'];
const packet=(over={})=>({kind:'RestrictedLinuxKyverno',projectId:'kyverno-supply-chain',runId:'web-123e4567-e89b-12d3-a456-426614174000',caseId:'signed',uid:1002,gid:1002,groups:[1002],noNewPrivs:true,namespace:'devsecops-supply-chain',policy:'devsecops-signed-images',image:project.cases.signed.image,allowed:true,exitCode:0,diagnostic:'',toolVersion:'1.36.1',toolSha256:project.toolSha256,stages:[{stage:'ADMISSION_STARTED',pid:42},{stage:'RUN_COMPLETED'}],realCreate:{attempted:true,created:true,deleted:true,verifiedGone:true},cleanup:'VERIFIED',startedAt:'2026-11-12T00:00:00.000Z',completedAt:'2026-11-12T00:00:01.000Z',...over});
test('fact maps admitted workload to frozen admission PASS',()=>{
 const f=buildKyvernoFact(packet(),project);assert.equal(f.component,'kyverno-admission');assert.equal(f.raw.expectedDenial,false);assert.equal(f.raw.result.allowed,true);
 const r=evaluate(f,{policyVersion:'baseline-v1',securityLevel:'standard'});assert.equal(r.decision,'PASS');
});
test('fact maps denied workload to frozen admission FAIL',()=>{
 const f=buildKyvernoFact(packet({caseId:'unsigned',image:project.cases.unsigned.image,allowed:false,exitCode:1,diagnostic:'devsecops-signed-images: no signatures found',realCreate:null}),project);
 const r=evaluate(f,{policyVersion:'baseline-v1',securityLevel:'standard'});assert.equal(r.decision,'FAIL');assert.equal(r.admissionDisposition,'DENIED');
});
test('runtimeFacts carry the Loki fresh-run contract field',()=>{
 const rt=buildKyvernoRuntimeFacts(packet(),'web-123e4567-e89b-12d3-a456-426614174000');
 assert.equal(rt.validationRunId,'web-123e4567-e89b-12d3-a456-426614174000');assert.equal(rt.classification,'REAL_CONTROLLED_EXECUTION');assert.equal(typeof rt.diagnosticSha256,'string');
 const refs=buildKyvernoEvidenceRefs(packet(),project,'web-123e4567-e89b-12d3-a456-426614174000');assert.equal(refs[0].validationRunId,rt.validationRunId);
});
test('packet validation rejects project, digest and identity drift',()=>{
 assert.equal(validateKyvernoPacket(packet(),{projectId:'kyverno-supply-chain',runId:packet().runId,project}),true);
 assert.throws(()=>validateKyvernoPacket(packet({image:'core.harbor.domain/petclinic/petclinic@sha256:2fbaea65ab030c56c60c62e3ee9fbe362deb8bbbb8216a891ef4c7bbbcea6d55'}),{projectId:'kyverno-supply-chain',runId:packet().runId,project}),/RUNNER_REPORT_ERROR/);
 assert.throws(()=>validateKyvernoPacket(packet({uid:1000}),{projectId:'kyverno-supply-chain',runId:packet().runId,project}),/RUNNER_REPORT_ERROR/);
 assert.throws(()=>validateKyvernoPacket(packet(),{projectId:'kyverno-workload',runId:packet().runId,project}),/RUNNER_REPORT_ERROR/);
 assert.throws(()=>validateKyvernoPacket(packet({realCreate:{attempted:true,created:true,deleted:false,verifiedGone:false}}),{projectId:'kyverno-supply-chain',runId:packet().runId,project}),/RUNNER_REPORT_ERROR/);
});
test('second project is independently defined',()=>{
 const b=kyvernoProjects()['kyverno-workload'];assert.equal(b.namespace,'devsecops-execution');assert.equal(b.policy,'devsecops-workload-contract');assert.ok(b.cases.compliant);assert.ok(b.cases['host-access']);
});
