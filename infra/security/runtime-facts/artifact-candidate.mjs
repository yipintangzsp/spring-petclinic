import {EXPECTED_SOURCES} from '../summary-v2/inventory.mjs';
import {finalizeArtifact,writeImmutableArtifact} from '../summary-v2/artifact.mjs';
import {fail,equal} from '../summary-v2/codec.mjs';
import {validateResult} from '../summary-v2/results.mjs';

// Runtime acceptance receipts are required in addition to resolved result bytes.
// This validator never evaluates Policy or creates synthetic receipts.
export function validateRuntimeCompleteness(snapshot,runtimeReceipts){
  if(!snapshot.complete||snapshot.missing.length||snapshot.sources.length!==EXPECTED_SOURCES.length)fail('runtime artifact incomplete');
  if(!Array.isArray(runtimeReceipts)||runtimeReceipts.length!==EXPECTED_SOURCES.length)fail('runtime receipt count incomplete');
  const seen=new Set(),evaluations=new Set();
  for(const r of runtimeReceipts){
    if(!EXPECTED_SOURCES.includes(r.sourceId)||seen.has(r.sourceId))fail('duplicate/noncanonical runtime receipt');seen.add(r.sourceId);
    if(!equal(r.binding,snapshot.binding))fail('stale runtime receipt binding');
    if(typeof r.executionScope!=='string'||!r.executionScope.trim()||['UNKNOWN','NOT_TESTED'].includes(r.executionScope))fail('missing executionScope');
    if(r.evaluationCount!==1||typeof r.evaluationId!=='string'||!r.evaluationId||evaluations.has(r.evaluationId))fail('duplicate Policy evaluation receipt');evaluations.add(r.evaluationId);
    if(snapshot.evaluationCounts?.[r.sourceId]!==1)fail('runtime evaluation count mismatch');
    const source=snapshot.sources.find(s=>s.sourceId===r.sourceId);validateResult(source,snapshot.binding);
    if(!source.evidenceComplete||r.factDigest!==source.rawFactDigest||r.resultDigest!==source.resultDigest||r.GateInputDigest!==source.resultDigest||snapshot.gate?.[r.sourceId]?.resultDigest!==source.resultDigest)fail('runtime receipt/result integrity mismatch');
  }
  return true;
}

// Stops before Summary. No evaluation, approval, signing or Promotion import.
export function writeRuntimeArtifactCandidate({snapshot,producer,legacySummary,externalChecks,inheritedBuildResult,directory,runtimeReceipts}){
  if(!snapshot.complete||snapshot.missing.length)fail('runtime artifact incomplete: '+snapshot.missing.join(','));
  if(snapshot.sources.length!==EXPECTED_SOURCES.length)fail('runtime source count incomplete');
  validateRuntimeCompleteness(snapshot,runtimeReceipts);
  const sources=Object.fromEntries(Object.entries(snapshot.gate).map(([id,g])=>[id,{resultDigest:g.resultDigest,observedStatus:g.observedStatus}]));
  const failed=Object.values(sources).some(x=>x.observedStatus==='failed')||Object.values(externalChecks).includes('failed');
  const aggregate={finalized:true,sources,externalChecks,inheritedBuildResult,result:failed?'FAILURE':inheritedBuildResult};
  const artifact=finalizeArtifact({binding:snapshot.binding,sources:snapshot.sources,aggregate,legacySummary,producer});
  return writeImmutableArtifact(directory,artifact);
}
