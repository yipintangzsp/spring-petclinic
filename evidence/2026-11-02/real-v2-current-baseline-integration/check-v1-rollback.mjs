// Snapshot/explicit-version proof only; never changes the live Jenkins selection.
import fs from 'node:fs';
import assert from 'node:assert/strict';
import {verifyVersion} from '../../../infra/security/summary-v2/integrity.mjs';
import {sha} from '../../../infra/security/summary-v2/codec.mjs';
const root=new URL('../../../',import.meta.url),out=new URL('./',import.meta.url);
const read=p=>JSON.parse(fs.readFileSync(p));
const c=read(new URL('infra/security/summary-v2/candidate-integrity-r2.json',root));
const v1=read(new URL('V1_IDENTITY.json',out)),active=read(new URL('ACTIVE_V1_IDENTITY.json',out));
const candidate=verifyVersion({root:root.pathname,contract:c,selectedVersion:'V2',consumerVersion:'SummaryConsumerV2',producer:c.versions.V2.producer});
for(const [p,x] of Object.entries(v1.files))assert.equal(sha(fs.readFileSync(new URL('v1-tree/'+p,out))),x.sha256);
for(const [p,x] of Object.entries(active.files))if(x.exists)assert.equal(sha(fs.readFileSync(new URL('active-v1-tree/'+p,out))),x.sha256);
const restored=verifyVersion({root:new URL('v1-tree/',out).pathname,contract:c,selectedVersion:'V1',consumerVersion:'V2-explicit-rollback',producer:c.versions.V1.producer});
assert.equal(c.versions.V1.producer.identity,v1.identity);
fs.writeFileSync(new URL('v1-rollback-receipt.json',out),JSON.stringify({classification:'CONTROLLED_VERSION_SELECTION_AND_EXACT_SNAPSHOT_PROOF_NOT_REAL_PIPELINE_ROLLBACK',candidateVersionChecked:candidate.selectedVersion,restoredVersionChecked:restored.selectedVersion,localV1Identity:v1.identity,localSnapshotFiles:Object.keys(v1.files).length,liveActiveSnapshotFiles:Object.keys(active.files).length,liveJob:active.job,liveLastBuild:active.build,liveLibrary:active.libraries,producerHash:v1.producerSha256,localAndLiveManagerMustNotBeConfused:{local:v1.files['vars/securityManager.groovy'].sha256,live:active.files['vars/securityManager.groovy'].sha256},snapshotHashValidation:'PASS',explicitV1RollbackContract:'PASS',productionVersionSwitched:false,productionRestore:'NOT_REQUIRED_NO_SWITCH_PERFORMED',realPipelineRollback:'NOT_TESTED',verificationCommand:'node evidence/2026-11-02/real-v2-current-baseline-integration/check-v1-rollback.mjs',rollbackInstruction:'Non-release candidate caller must explicitly select V1 with the frozen snapshot. Do not copy local Manager over live Manager; no production switch was performed.'},null,2)+'\n');
console.log('CONTROLLED_V1_ROLLBACK_SNAPSHOT_PASS; REAL_PIPELINE_ROLLBACK_NOT_TESTED');
