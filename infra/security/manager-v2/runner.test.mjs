import test from 'node:test';import assert from 'node:assert/strict';import fs from 'node:fs';
import {CATALOG,decodeArchive,executeArchive,workerInventory} from './archive.mjs';import {registry} from './registry.mjs';
import {evaluateAsync} from '../policy/engine.mjs';import {canonical,sha} from '../summary-v2/codec.mjs';
for(const [id,e]of Object.entries(CATALOG))test('D independent immutable archive '+id,async()=>{
 const p=registry().get(e.pluginId),rawBefore=fs.readFileSync(new URL('./fixtures/'+e.file,import.meta.url));
 const r=await executeArchive(p,{archiveId:id,approvedDigest:e.sha256});const before=canonical(r.fact);
 assert.equal((await evaluateAsync(r.fact,{mode:'enforce'})).decision,e.oldDecision);
 assert.equal(canonical(r.fact),before);
 assert.equal(r.cleanup.workerTerminated,true);assert.equal(r.cleanup.threadIdAfterJoin,-1);assert.equal(sha(rawBefore),sha(fs.readFileSync(new URL('./fixtures/'+e.file,import.meta.url))));
});
test('D unapproved/cross-plugin digest prevents worker start',async()=>{for(const input of [{archiveId:'unknown'},{archiveId:'gitleaks-pass',approvedDigest:'bad'},{archiveId:'semgrep-pass',approvedDigest:CATALOG['semgrep-pass'].sha256}])await assert.rejects(executeArchive(registry().get('gitleaks'),input),/unapproved/);});
test('D missing and corrupted raw reports cannot reach Policy',()=>{assert.throws(()=>decodeArchive(Buffer.from('wrong'),CATALOG['gitleaks-pass']),/corruption/);assert.throws(()=>decodeArchive(Buffer.from('{}'),{sha256:sha('{}')}),/missing/);});
test('D timeout and pre-cancellation join a dedicated bounded worker',async()=>{await assert.rejects(executeArchive({...registry().get('gitleaks'),timeout:1},{archiveId:'gitleaks-pass',approvedDigest:CATALOG['gitleaks-pass'].sha256}),/TIMEOUT/);assert.deepEqual(workerInventory(),[]);const c=new AbortController();c.abort();await assert.rejects(executeArchive(registry().get('gitleaks'),{archiveId:'gitleaks-pass',approvedDigest:CATALOG['gitleaks-pass'].sha256},{signal:c.signal}),/CANCELLED/);assert.deepEqual(workerInventory(),[]);});
test('D in-flight cancellation leaves no active owned worker',async()=>{const c=new AbortController();const pending=executeArchive(registry().get('cosign'),{archiveId:'cosign-pass',approvedDigest:CATALOG['cosign-pass'].sha256},{signal:c.signal});assert.equal(workerInventory().length,1);c.abort();await assert.rejects(pending,/CANCELLED/);assert.deepEqual(workerInventory(),[]);});
