// T08a / C4: pre-approval assembly from real run outputs — the V1 writer's
// actual summary file plus the cross-process receipts — and its failure
// modes when an input is absent.
import assert from 'node:assert';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {fixture,binding} from './fixture-harness.mjs';
import {claimAndWrite} from './receipts.mjs';
import {assemblePreApproval,producerFromContract} from './assemble.mjs';

const {sources} = await fixture('PASS');
const producer = producerFromContract('.');
const root = fs.mkdtempSync(path.join(os.tmpdir(),'t08a-assemble-'));
fs.mkdirSync(root+'/.devsecops/receipts',{recursive:true});
const legacy = {schema:1,project:binding.project,pipeline:'security-audit',build:binding.build,
  source:binding.source,auditTargetImage:binding.candidate,targetScope:binding.targetScope,
  build_result:'SUCCESS',recorded_at:'2026-11-02T00:00:00Z',missing:[]};
fs.writeFileSync(root+'/.devsecops/security-summary.json',JSON.stringify(legacy));
for (const r of sources) claimAndWrite(root+'/.devsecops/receipts',r);

const externalChecks = {snapshotBefore:'success',readOnlyReleaseVerification:'success'};
const artifact = assemblePreApproval({root,binding,producer,externalChecks});
assert.equal(artifact.kind,'PreApprovalPolicyArtifact');
assert.equal(artifact.completeness,'COMPLETE');
assert.equal(artifact.binding.source,binding.source);
assert.equal(Object.keys(artifact.aggregate.sources).length,16);
assert.equal(artifact.aggregate.result,'SUCCESS');
// The V2 consumer accepts the assembled artifact under its trusted digest.
const {encodeArtifact,consumeArtifact} = await import('./artifact.mjs');
const packet = encodeArtifact(artifact);
assert.equal(consumeArtifact(packet,{digest:packet.digest,binding,producer}).completeness,'COMPLETE');

// External checks may also arrive through the run-directory file.
fs.writeFileSync(root+'/.devsecops/external-checks.json',JSON.stringify(externalChecks));
assert.equal(assemblePreApproval({root,binding,producer}).aggregate.result,'SUCCESS');

// A missing receipt fails the assembly by name.
const root2 = fs.mkdtempSync(path.join(os.tmpdir(),'t08a-assemble-missing-'));
fs.mkdirSync(root2+'/.devsecops/receipts',{recursive:true});
fs.writeFileSync(root2+'/.devsecops/security-summary.json',JSON.stringify(legacy));
for (const r of sources) if (r.sourceId !== 'falco-final') claimAndWrite(root2+'/.devsecops/receipts',r);
assert.throws(() => assemblePreApproval({root:root2,binding,producer,externalChecks}),
  /source receipt missing: falco-final/);

// Absent external checks are an assembly error, never a fabricated pass.
const root3 = fs.mkdtempSync(path.join(os.tmpdir(),'t08a-assemble-nochecks-'));
fs.mkdirSync(root3+'/.devsecops/receipts',{recursive:true});
fs.writeFileSync(root3+'/.devsecops/security-summary.json',JSON.stringify(legacy));
for (const r of sources) claimAndWrite(root3+'/.devsecops/receipts',r);
assert.throws(() => assemblePreApproval({root:root3,binding,producer}),/external Gate checks absent/);

console.log('assemble.test PASS');
