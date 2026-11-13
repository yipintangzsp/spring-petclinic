import test from 'node:test';import assert from 'node:assert/strict';import fs from 'node:fs';import path from 'node:path';import crypto from 'node:crypto';import {verifyCheckpoint} from './verify-checkpoint.mjs';
const base=new URL('./',import.meta.url).pathname,root=path.resolve(base,'../../..'),anchor=JSON.parse(fs.readFileSync(base+'checkpoint-digest.json')),bytes=fs.readFileSync(path.join(root,anchor.checkpointPath)),cp=JSON.parse(bytes),sha=b=>crypto.createHash('sha256').update(b).digest('hex');
function altered(change){const c=structuredClone(cp);change(c);const b=Buffer.from(JSON.stringify(c));return {root,checkpointPath:anchor.checkpointPath,expectedSha256:sha(b),readFile:p=>p===path.join(root,anchor.checkpointPath)?b:fs.readFileSync(p)};}
test('14/16 hashes verify; authoritative promotion fails closed on unresolved proxy drift',()=>{const r=verifyCheckpoint({root,...{checkpointPath:anchor.checkpointPath,expectedSha256:anchor.sha256}});assert.equal(r.integrityStatus,'VERIFIED');assert.equal(r.status,'FAILED');assert.equal(r.resumeAllowed,false);assert.equal(r.acceptedWiredCount,14);assert.equal(r.policyEvaluations,0);});
test('checkpoint bytes tamper rejects trusted digest mismatch',()=>assert.throws(()=>verifyCheckpoint({...altered(c=>c.release=1),expectedSha256:anchor.sha256}),/BYTES_CHANGED/));
test('canonical source omission is not15/16success',()=>assert.throws(()=>verifyCheckpoint(altered(c=>c.sources.pop())),/SOURCE_COUNT/));
test('duplicate canonical source rejects even recomputed checkpoint hash',()=>assert.throws(()=>verifyCheckpoint(altered(c=>c.sources[1]=c.sources[0])),/CANONICAL_SET/));
test('runtime source file drift rejects',()=>assert.throws(()=>verifyCheckpoint(altered(c=>c.runtimeImplementationHashes['infra/security/runtime-facts/collector.mjs']='0'.repeat(64))),/SOURCE_HASH/));
test('engineering blocker cannot become Policy PASS',()=>assert.throws(()=>verifyCheckpoint(altered(c=>c.sources.find(s=>s.sourceId==='trivy').policyResult={decision:'PASS'})),/BLOCKER_NOT_POLICY_RESULT/));
test('changed source result receipt identity rejects',()=>assert.throws(()=>verifyCheckpoint(altered(c=>c.sources.find(s=>s.sourceId==='cosign').resultDigest='0'.repeat(64))),/SOURCE_RECEIPT_IDENTITY/));
test('global completeness cannot be upgraded by checkpoint',()=>assert.throws(()=>verifyCheckpoint(altered(c=>c.currentRuntimeVerdicts.REAL_POLICY_OWNER='VERIFIED')),/OVERALL_VERDICT/));
test('same-run complete claim rejected',()=>assert.throws(()=>verifyCheckpoint(altered(c=>c.sameRun16Proven=true)),/NO_COMPLETE_ARTIFACT/));
test('referenced resume or guard plan tamper rejected',()=>assert.throws(()=>verifyCheckpoint(altered(c=>c.resumeContract.sha256='0'.repeat(64))),/REFERENCE_HASH/));

test('guard-analysis reference tamper rejected',()=>assert.throws(()=>verifyCheckpoint(altered(c=>c.guardReview.sha256='0'.repeat(64))),/REFERENCE_HASH/));

test('unresolved protection drift cannot be relabeled authoritative VERIFIED',()=>assert.throws(()=>verifyCheckpoint(altered(c=>c.authoritativeAcceptance='VERIFIED')),/PROTECTED_DRIFT_FAIL_CLOSED/));
