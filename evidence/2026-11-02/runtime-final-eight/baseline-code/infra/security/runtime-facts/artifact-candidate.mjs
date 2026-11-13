import {EXPECTED_SOURCES} from '../summary-v2/inventory.mjs';
import {finalizeArtifact,writeImmutableArtifact} from '../summary-v2/artifact.mjs';
import {fail} from '../summary-v2/codec.mjs';

// Stops before Summary. No evaluation, approval, signing or Promotion import.
export function writeRuntimeArtifactCandidate({snapshot,producer,legacySummary,externalChecks,inheritedBuildResult,directory}){
  if(!snapshot.complete||snapshot.missing.length)fail('runtime artifact incomplete: '+snapshot.missing.join(','));
  if(snapshot.sources.length!==EXPECTED_SOURCES.length)fail('runtime source count incomplete');
  const sources=Object.fromEntries(Object.entries(snapshot.gate).map(([id,g])=>[id,{resultDigest:g.resultDigest,observedStatus:g.observedStatus}]));
  const failed=Object.values(sources).some(x=>x.observedStatus==='failed')||Object.values(externalChecks).includes('failed');
  const aggregate={finalized:true,sources,externalChecks,inheritedBuildResult,result:failed?'FAILURE':inheritedBuildResult};
  const artifact=finalizeArtifact({binding:snapshot.binding,sources:snapshot.sources,aggregate,legacySummary,producer});
  return writeImmutableArtifact(directory,artifact);
}
