// Controlled candidate rebase check, NOT a real pipeline/runtime execution.
import fs from 'node:fs';
import vm from 'node:vm';
import assert from 'node:assert/strict';
import {runtimeWindow,persistentRuntime} from '../../../infra/security/runtime/event-policy.mjs';
import {validatePriorExit,validateRuntimeContinuity,driverDiagnostics} from '../../../infra/security/runtime/health-contract.mjs';
import {createSourceOwner} from '../../../infra/security/summary-v2/owner.mjs';
import {EXPECTED_SOURCES} from '../../../infra/security/summary-v2/inventory.mjs';
import {finalizeArtifact,encodeArtifact,writeImmutableArtifact} from '../../../infra/security/summary-v2/artifact.mjs';
import {summaryV2} from '../../../infra/security/summary-v2/producer.mjs';
import {digest,sha} from '../../../infra/security/summary-v2/codec.mjs';

const root=new URL('../../../',import.meta.url),out=new URL('./',import.meta.url),repair=new URL('evidence/2026-11-02/falco-time-contract-repair/',root);
const load=p=>JSON.parse(fs.readFileSync(p));
const contract=load(new URL('infra/security/summary-v2/candidate-integrity-r2.json',root));
const source=fs.readFileSync(new URL('infra/security/runtime/health.mjs',root),'utf8');
assert.equal(sha(source),'65ab133a4248b9900265a47d943f9e6430b9ec9581ddd624b1d9257322b0d921');
const body=source.replace(/^import .*;\s*$/gm,'');
// Reuse the EXACT accepted whole-body replay observer, not a rewritten Gate.
const harness=fs.readFileSync(new URL('timing-matrix.mjs',repair),'utf8');
const fn=harness.slice(harness.indexOf('async function original('),harness.indexOf("fs.mkdirSync(new URL('fixtures/',out)"));
const original=vm.runInNewContext('('+fn.trim()+')',{Date,body,assert,vm,runtimeWindow,persistentRuntime,validatePriorExit,validateRuntimeContinuity,driverDiagnostics,AbortSignal});
const retained=load(new URL('timing-after.json',repair)).records;
const producer=contract.versions.V2.producer,records=[];
for(const mode of ['baseline','check'])for(const kind of ['normal','original-2s-boundary']){
  const ref=retained.find(r=>r.mode===mode&&(kind==='normal'?r.oldDecision==='PASS':r.originalDiscoveryCase));
  assert.ok(ref);
  let raw=load(new URL(ref.fixture,repair));
  const old=await original(raw,kind==='normal'?{}:{firstWorkloadMs:2000});
  assert.equal(old.oldDecision,ref.oldDecision);
  // The accepted VM observer creates objects in another realm. Cross the same
  // explicit JSON boundary as frozen fixtures; preserve every recorded value.
  const observedBytes=JSON.stringify(raw);raw=JSON.parse(observedBytes);assert.equal(JSON.stringify(raw),observedBytes);
  const rawBefore=digest(raw),sourceId=mode==='baseline'?'falco-baseline':'falco-final';
  const binding={job:'controlled-falco-v2-rebase',build:1,project:'petclinic',source:'c'.repeat(40),candidate:'registry.invalid/controlled@sha256:'+'a'.repeat(64),targetScope:'candidate',runId:mode+'-'+kind};
  const owner=createSourceOwner(binding),receipts=[];
  for(const id of EXPECTED_SOURCES)receipts.push(await owner.evaluateOnce(id,id===sourceId?{component:id,status:'success',raw}:{component:id,status:'skipped',raw:{classification:'EXPLICIT_CONTROLLED_SKIP_NOT_RUNTIME'}}));
  const result=owner.get(sourceId);assert.equal(result.result.decision,old.oldDecision);assert.equal(digest(raw),rawBefore);
  const aggregate={finalized:true,sources:Object.fromEntries(receipts.map(r=>[r.sourceId,{resultDigest:r.resultDigest,observedStatus:r.sourceId===sourceId?(old.oldDecision==='FAIL'?'failed':'success'):'skipped'}])),externalChecks:{snapshotBefore:'success',readOnlyReleaseVerification:'success'},inheritedBuildResult:'SUCCESS',result:old.oldDecision==='FAIL'?'FAILURE':'SUCCESS'};
  const legacySummary={schema:1,project:binding.project,pipeline:'controlled-security-validation',build:binding.build,source:binding.source,auditTargetImage:binding.candidate,targetScope:binding.targetScope,build_result:aggregate.result,missing:[]};
  const artifact=finalizeArtifact({binding,sources:receipts,aggregate,legacySummary,producer}),packet=encodeArtifact(artifact);
  const countsBefore=owner.counts(),context={digest:packet.digest,binding,producer,integrity:{root:root.pathname,contract}};
  const summary=summaryV2(packet,context),serialized=JSON.parse(packet.bytes).sources.find(r=>r.sourceId===sourceId),projected=summary.resolvedSources.find(r=>r.sourceId===sourceId);
  assert.equal(serialized.result.decision,old.oldDecision);assert.equal(projected.decision,old.oldDecision);
  assert.equal(result.resultDigest,projected.resultDigest);assert.equal(result.resultDigest,aggregate.sources[sourceId].resultDigest);
  assert.deepEqual(owner.counts(),countsBefore);assert.ok(Object.values(countsBefore).every(c=>c===1));
  if(kind==='original-2s-boundary')assert.equal(old.oldDecision,'FAIL');
  const directory=new URL('controlled-falco-artifacts/'+mode+'-'+kind+'/',out);
  const written=writeImmutableArtifact(directory.pathname,artifact);
  fs.writeFileSync(new URL('controlled-'+mode+'-'+kind+'-summary.json',out),JSON.stringify(summary,null,2)+'\n',{flag:'wx'});
  records.push({sourceId,kind,classification:'CONTROLLED_COMPLETE_GATE_REPLAY_THROUGH_REBASED_CANDIDATE_NOT_RUNTIME',fixture:ref.fixture,oldGateDecision:old.oldDecision,policyDecision:result.result.decision,artifactDecision:serialized.result.decision,summaryDecision:projected.decision,rawUnchanged:true,artifactDigest:packet.digest,artifactPath:written.path,resultDigest:result.resultDigest,gateResultDigest:aggregate.sources[sourceId].resultDigest,summaryResultDigest:projected.resultDigest,controlledEvaluationCounts:owner.counts(),realPipelineCountsObserved:false});
}
fs.writeFileSync(new URL('falco-v2-rebase-preflight.json',out),JSON.stringify({classification:'CONTROLLED_REBASE_PREFLIGHT_NOT_REAL_PIPELINE',samples:records.length,match:records.length,drift:0,originalObserverFunctionSha256:sha(fn),productionExecutionCount:0,records},null,2)+'\n',{flag:'wx'});
console.log(JSON.stringify({cases:records.length,MATCH:records.length,DRIFT:0,realPipeline:false}));
