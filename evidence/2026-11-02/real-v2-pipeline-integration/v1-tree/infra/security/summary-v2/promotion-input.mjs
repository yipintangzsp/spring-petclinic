import {consumeArtifact} from './artifact.mjs';
import {fail} from './codec.mjs';
import {verifyVersion} from './integrity.mjs';

// Candidate policy precondition ONLY. Not wired into sign/promote. This cannot
// authorize approval/signing/Git writes: original Promotion checks remain needed.
export function preApprovalPolicyInput(packet,context) {
  verifyVersion({...context.integrity,selectedVersion:'V2',consumerVersion:'PromotionConsumerV2',producer:context.producer});
  const artifact = consumeArtifact(packet,context);
  if (artifact.aggregate.result !== 'SUCCESS' || artifact.policyState !== 'RESOLVED' || artifact.sources.some(r => ['FAIL','ERROR','NOT_TESTED'].includes(r.result?.status))) fail('Policy artifact not eligible');
  return {binding:artifact.binding,artifactDigest:context.digest,aggregate:artifact.aggregate,
    sourceResultDigests:artifact.sources.map(r => [r.sourceId,r.resultDigest])};
}
