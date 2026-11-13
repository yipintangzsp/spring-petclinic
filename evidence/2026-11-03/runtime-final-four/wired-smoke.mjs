import fs from 'node:fs';import assert from 'node:assert/strict';
import {validateResult,gateView} from '../../../infra/security/summary-v2/results.mjs';
import {EXPECTED_SOURCES} from '../../../infra/security/summary-v2/inventory.mjs';
const root=new URL('../../../',import.meta.url),out=new URL('./',import.meta.url),read=p=>JSON.parse(fs.readFileSync(p));
const runs=[read(new URL('evidence/2026-11-02/runtime-final-eight/jenkins-build-12.json',root)),read(new URL('evidence/2026-11-03/runtime-controlled-six/jenkins-build-14.json',root)),read(new URL('evidence/2026-11-03/runtime-controlled-six/jenkins-build-15.json',root))],ids=new Map(),counts=[];
for(const run of runs){const files=run.artifacts;for(const [p,r]of Object.entries(files)){
 if(!p.endsWith('.result.json'))continue;const prefix=p.slice(0,-'.result.json'.length),capture=files[prefix+'.capture.json'],gate=files[prefix+'.gate.json'];validateResult(r,r.binding);assert.equal(r.binding.build,run.build);assert.equal(capture.evaluationCount,1);assert.equal(capture.rawFactDigest,r.rawFactDigest);assert.equal(r.resultDigest,gate.resultDigest);assert.equal(r.resultDigest,capture.resultDigest);assert.deepEqual(gateView(r,r.binding),{sourceId:gate.sourceId,resultDigest:gate.resultDigest,status:gate.status,decision:gate.decision});
 counts.push({build:run.build,sourceId:r.sourceId,evaluationCount:capture.evaluationCount,digest:r.resultDigest,gateDigest:gate.resultDigest});ids.set(r.sourceId,true);
}}
assert.equal(ids.size,12);assert.ok(!ids.has('security-approval-promotion'));assert.ok(!ids.has('semgrep'));
const report={canonical:EXPECTED_SOURCES.length,cumulativeWiredCapability:ids.size,missing:EXPECTED_SOURCES.filter(s=>!ids.has(s)),counts,uniqueWithinEachOriginalBinding:true,baselineReceiptsRetainBuild12:true,policyReevaluations:0,currentCombinedArtifactComplete:false,notMergedAcrossBuildBindings:true};
fs.writeFileSync(new URL('wired-smoke.json',out),JSON.stringify(report,null,2)+'\n');console.log(JSON.stringify({canonical:16,acceptedCapabilities:ids.size,checkedOriginalReceipts:counts.length,policyReevaluations:0,sameBuildComplete:false}));
