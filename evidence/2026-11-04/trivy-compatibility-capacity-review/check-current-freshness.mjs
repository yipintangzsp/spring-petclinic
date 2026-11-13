// Read-only replay of the unchanged production prerequisite against captured metadata.
import fs from 'node:fs';
import assert from 'node:assert/strict';
import {requireFreshScannerMetadata} from '../../../infra/observability/scanner-db-refresh.mjs';
const dir=new URL('./',import.meta.url),input=JSON.parse(fs.readFileSync(new URL('current-db.json',dir)));
const now=Date.parse(input.sampledAt),facts=JSON.stringify(input.metadata),rows=[];
for(const [kind,version]of [['db',2],['java-db',1]]){
 const metadata=input.metadata[kind];assert.equal(metadata.Version,version);
 const expired=Date.parse(metadata.NextUpdate)<=now;assert.equal(expired,true);
 // The other kind's timestamp is a test control, clearly separate from captured raw facts.
 const isolated=structuredClone(input.metadata),other=kind==='db'?'java-db':'db';
 isolated[other].NextUpdate=new Date(now+60000).toISOString();
 let error;try{requireFreshScannerMetadata(isolated,now);}catch(e){error=e.message;}
 assert.equal(error,'PREFLIGHT_SCANNER_DATABASE_REFRESH_REQUIRED: '+kind);
 rows.push({kind,schema:version,metadata,expiredAtSample:true,prerequisiteResult:error,
  classification:'CAPTURED_METADATA_PREREQUISITE_REPLAY_OTHER_KIND_FRESH_TEST_CONTROL'});
}
let combined;try{requireFreshScannerMetadata(input.metadata,now);}catch(e){combined=e.message;}
assert.match(combined,/PREFLIGHT_SCANNER_DATABASE_REFRESH_REQUIRED/);
assert.equal(JSON.stringify(input.metadata),facts);
const result={classification:'READ_ONLY_PREREQUISITE_EVALUATION_NOT_SCAN',sampledAt:input.sampledAt,
 rows,combinedResult:combined,rawMetadataUnchanged:true,fullIntegrity:'UNKNOWN_NOT_FULL_CHECKED',
 freshness:'STALE',existingCompliantScanCandidate:false,refreshRequired:true,
 javaDBRequiredByCurrentProductionPrerequisite:true,skipUpdateFlagsUsed:false,
 realDBRefreshCount:0,realScanCount:0};
fs.writeFileSync(new URL('current-freshness-proof.json',dir),JSON.stringify(result,null,2)+'\n');
console.log(JSON.stringify({freshness:result.freshness,bothSchemasVerified:rows.length,rawMetadataUnchanged:true}));
