import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {ensureScannerDatabases,verifyManifest,requireFreshScannerMetadata} from './scanner-db-refresh.mjs';
const stamp = ms => new Date(ms).toISOString();
function metadata(expired = []) {
 const now = Date.now();
 return Object.fromEntries([['db',2],['java-db',1]].map(([kind,Version]) => [kind,{Version,
  UpdatedAt:stamp(now-3600000),DownloadedAt:stamp(now-60000),NextUpdate:stamp(now+(expired.includes(kind)?-60000:86400000))}]));
}
function fake(expired) {
 const before = metadata(expired), calls = [], recorded = [];
 return {before,calls,recorded,io:{
  assertOwner(){calls.push('owner');},
  upstream(kind){calls.push('manifest:'+kind);return {kind,digest:'sha256:'+'a'.repeat(64)};},
  download(kind){calls.push('download:'+kind);return 'normal updater';},
  read(kind){calls.push('read:'+kind);return metadata()[kind];},
  record(action){recorded.push(action);}
 }};
}
test('fresh scanner caches do not start maintenance or acquire another lock',async()=>{
 const f=fake([]), r=await ensureScannerDatabases(f.before,f.io);assert.deepEqual(f.calls,[]);assert.equal(r.actions.length,0);
});
test('only the expired database is refreshed and actual updater metadata is required',async()=>{
 const f=fake(['db']),r=await ensureScannerDatabases(f.before,f.io);
 assert.deepEqual(f.calls,['owner','manifest:db','download:db','read:db']);assert.equal(r.actions.length,1);requireFreshScannerMetadata(r.metadata);
 assert.equal(f.before.db.NextUpdate>r.metadata.db.NextUpdate,false);assert.deepEqual(r.metadata['java-db'],f.before['java-db']);
});
test('two expired databases refresh serially under the existing owner',async()=>{
 const f=fake(['db','java-db']);await ensureScannerDatabases(f.before,f.io);
 assert.deepEqual(f.calls,['owner','manifest:db','download:db','read:db','owner','manifest:java-db','download:java-db','read:java-db']);assert.equal(f.recorded.length,2);
});
test('foreign heavy Lease prevents even fetching metadata',async()=>{
 const f=fake(['db']);f.io.assertOwner=()=>{throw Error('foreign Lease');};
 await assert.rejects(ensureScannerDatabases(f.before,f.io),/foreign Lease/);assert.deepEqual(f.calls,[]);
});
test('updater failures and stale output cannot turn the freshness gate green',async()=>{
 const f=fake(['db']);f.io.download=()=>{throw Error('upstream unavailable');};
 await assert.rejects(ensureScannerDatabases(f.before,f.io),/upstream unavailable/);assert.throws(()=>requireFreshScannerMetadata(f.before));
 const g=fake(['db']);g.io.read=()=>g.before.db;
 await assert.rejects(ensureScannerDatabases(g.before,g.io),/DID_NOT_PRODUCE_FRESH/);
});
test('official manifest hash and exact layer type are mandatory before using a mirror',()=>{
 const manifest={schemaVersion:2,layers:[{mediaType:'application/vnd.aquasec.trivy.db.layer.v1.tar+gzip',digest:'sha256:'+'b'.repeat(64),size:128}]};
 const bytes=Buffer.from(JSON.stringify(manifest)),digest='sha256:'+createHash('sha256').update(bytes).digest('hex');
 assert.equal(verifyManifest('db',bytes,digest).repository,'ghcr.nju.edu.cn/aquasecurity/trivy-db@'+digest);
 assert.throws(()=>verifyManifest('db',bytes,'sha256:'+'0'.repeat(64)),/digest mismatch/);
 assert.throws(()=>verifyManifest('java-db',bytes,digest),/Unexpected official/);
});
test('corrupt metadata does not trigger an uncontrolled cache replacement',async()=>{
 const f=fake([]);f.before.db.Version=99;
 await assert.rejects(ensureScannerDatabases(f.before,f.io),/METADATA_INVALID/);assert.deepEqual(f.calls,[]);
});
