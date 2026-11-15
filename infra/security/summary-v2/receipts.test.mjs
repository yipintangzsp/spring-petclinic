// T08a / C2: cross-process receipt handoff protocol — claim/write/collect,
// idempotent retry, conflict rejection, missing-source detection, and the
// Kyverno observation-part round trip.
import assert from 'node:assert';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {fixture,binding} from './fixture-harness.mjs';
import {EXPECTED_SOURCES} from './inventory.mjs';
import {claimAndWrite,collectReceipts,writePart,readPart} from './receipts.mjs';
import {createSourceOwner} from './owner.mjs';

const tmp = fs.mkdtempSync(path.join(os.tmpdir(),'t08a-receipts-'));
const {sources} = await fixture('PASS');

// First handoff of every source writes claim + result.
const dir = path.join(tmp,'receipts');
for (const r of sources) assert.equal(claimAndWrite(dir,r).written,true,r.sourceId);
// Identical retry is idempotent, not an error.
for (const r of sources) assert.equal(claimAndWrite(dir,r).idempotent,true,r.sourceId);
// Collection returns exactly the canonical source set, digests intact.
const got = collectReceipts(dir,binding);
assert.equal(got.size,EXPECTED_SOURCES.length);
for (const r of sources) assert.equal(got.get(r.sourceId).resultDigest,r.resultDigest);

// A different evaluation of an already-claimed (binding, source) is rejected.
const owner = createSourceOwner(binding);
const other = await owner.evaluateOnce('trivy',
  {component:'trivy',status:'success',raw:{findings:[{id:'OTHER',severity:'Critical'}],review:{entries:[]},image:binding.candidate}});
assert.notEqual(other.resultDigest,sources.find(r => r.sourceId === 'trivy').resultDigest);
assert.throws(() => claimAndWrite(dir,other),/duplicate source evaluation/);

// A missing source is reported by name.
const dir2 = path.join(tmp,'receipts-missing');
for (const r of sources) if (r.sourceId !== 'cosign') claimAndWrite(dir2,r);
assert.throws(() => collectReceipts(dir2,binding),/source receipt missing: cosign/);

// A claim without its result is an inconsistency, not a pass.
const dir3 = path.join(tmp,'receipts-claim-only');
claimAndWrite(dir3,sources[0]);
fs.rmSync(path.join(dir3,'results'),{recursive:true,force:true});
assert.throws(() => collectReceipts(dir3,binding),/source receipt missing/);

// Observation parts round-trip and are identity-checked.
const part = {kind:'SourceObservationPart',source:'kyverno',part:'rbac',
  run:{source:'a'.repeat(40),build:3},observations:{},outcome:'success'};
writePart(dir,part);
assert.deepEqual(readPart(dir,'kyverno','rbac'),part);
assert.equal(readPart(dir,'kyverno','admission'),null);
const partFile = path.join(dir,'parts','kyverno-rbac.json');
fs.writeFileSync(partFile,fs.readFileSync(partFile,'utf8').replace('"rbac"','"admission"'));
assert.throws(() => readPart(dir,'kyverno','rbac'),/identity mismatch/);

console.log('receipts.test PASS');
