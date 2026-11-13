import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import {digest} from '../../summary-v2/codec.mjs';
import {replayAuditEvent,verifyReplayAuditEvent,withReplayAudit} from './loki-replay.mjs';
import {canReadRun} from './project-access.mjs';
const read=p=>JSON.parse(fs.readFileSync(new URL(p,import.meta.url)));
const proofRoot='../../../../evidence/2026-11-12/trivy-loki-router-repair/';
const original=read('../../../../evidence/2026-11-12/trivy-v2-closure/raw/run-web-4d4b4773-6750-4927-8e6a-8deef839a6f4/result.json');
const receipt=read(proofRoot+'router-receipt.json').lokiDelivery,queryProof=read(proofRoot+'query-proof.json');
const create=()=>replayAuditEvent(structuredClone(original),structuredClone(receipt),structuredClone(queryProof));
function reseal(event){const {auditDigest,...body}=event;event.auditDigest=digest(body);return event;}
test('original automatic failure and Policy FAIL preserved beside independently verified replay',()=>{
 const before=JSON.stringify(original),a=create(),r=withReplayAudit(original,a);
 assert.equal(JSON.stringify(original),before);assert.deepEqual(r.lokiDelivery,original.lokiDelivery);
 assert.equal(r.lokiDelivery.state,'FAILED');assert.equal(r.lokiDelivery.reason,'LOKI_PLUGIN_SELECTION_REJECTED');
 assert.equal(r.policyDecision,'FAIL');assert.equal(r.resultDigest,original.resultDigest);
 assert.equal(r.lokiReplayEvents[0].state,'DELIVERED');assert.equal(r.lokiReplayEvents[0].automatic,false);
 assert.equal(r.lokiReplayEvents[0].sourceClassification,'SEALED_ARTIFACT_REPLAY_NOT_NEW_SCAN');
 assert.equal(r.lokiReplayEvents[0].nativeSeverityCounts.HIGH,2);assert.equal(r.lokiReplayEvents[0].nativeSeverityCounts.MEDIUM,58);assert.equal(r.lokiReplayEvents[0].nativeSeverityCounts.LOW,4);
});
test('invalid audit/result digests, run and project bindings fail closed',()=>{
 const a=create();a.auditDigest='0'.repeat(64);assert.throws(()=>verifyReplayAuditEvent(a,original),/AUDIT_INTEGRITY/);
 for(const [key,value]of [['resultDigest','0'.repeat(64)],['runId','web-00000000-0000-0000-0000-000000000000'],['projectId','other-project']]){
  const a=create();a[key]=value;assert.throws(()=>verifyReplayAuditEvent(reseal(a),original),/RESULT_BINDING/);
 }
});
test('receipt mismatch, false query success, changed policy and modified native counts rejected',()=>{
 const a=create();a.receipt.resultDigests.trivy='0'.repeat(64);assert.throws(()=>verifyReplayAuditEvent(reseal(a),original),/RECEIPT_INTEGRITY/);
 for(const mutate of [a=>{a.queryProof.httpStatus=401;},a=>{a.queryProof.events=[];},a=>{a.queryProof.policyDecision='PASS';}]){
  const a=create();mutate(a);assert.throws(()=>verifyReplayAuditEvent(reseal(a),original),/QUERY_BINDING/);
 }
 const b=create();b.queryProof.events[0].nativeSeverityCounts.HIGH++;b.queryProof.events[0].nativeSeverityCounts.MEDIUM--;assert.throws(()=>verifyReplayAuditEvent(reseal(b),original),/PAYLOAD_BINDING/);
});
test('response projection excludes arbitrary receipt/query diagnostics and secrets',()=>{
 const a=create();a.receipt.privateDiagnostic='NON_SECRET_PRIVATE_TEST_SENTINEL';const {receiptDigest,...body}=a.receipt;a.receipt.receiptDigest=digest(body);a.queryProof.ignoredDiagnostic='NON_SECRET_QUERY_TEST_SENTINEL';
 const r=withReplayAudit(original,reseal(a));const output=JSON.stringify(r.lokiReplayEvents);
 assert.ok(!output.includes('SENTINEL'));assert.ok(!/Bearer |PRIVATE KEY|access_token|Authorization/.test(output));
 const b=create();b.queryProof.events[0].unexpectedSecret='NON_SECRET_TEST';assert.throws(()=>verifyReplayAuditEvent(reseal(b),original),/EVENT_SCHEMA/);
});
test('project-scoped identities cannot query Trivy or another project; operator remains allowed',()=>{
 const a=create(),r=withReplayAudit(original,a);
 const access={operator:req=>req.operator===true,project:req=>req.project??null,authorized:(req,id)=>req.operator===true||req.project===id};
 assert.equal(canReadRun({project:'java-fixture'},r,access),false);
 assert.equal(canReadRun({project:'other-project'},r,access),false);
 assert.equal(canReadRun({operator:true},r,access),true);
 assert.equal(canReadRun({project:'java-fixture'},{pluginId:'sbom',projectId:'service-fixture'},access),false);
 assert.equal(canReadRun({project:'java-fixture'},{pluginId:'sbom',projectId:'java-fixture'},access),true);
 assert.equal(canReadRun({project:'java-fixture'},{...r,ciContext:{}},access),false);
});
test('frontend preserves initial delivery and separately labels historical replay',()=>{
 const source=fs.readFileSync(new URL('./app.js',import.meta.url),'utf8');
 assert.ok(source.includes("row('Loki 自动投递',l.state)"));
 assert.ok(source.includes('r.lokiReplayEvents??[]'));assert.ok(source.includes('历史真实结果 · 后续补投（非新扫描）'));assert.ok(source.includes("row('Policy（原判定）',l.policyDecision)"));
});
