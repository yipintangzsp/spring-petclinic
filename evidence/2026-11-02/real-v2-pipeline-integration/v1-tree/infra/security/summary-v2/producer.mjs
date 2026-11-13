import {consumeArtifact} from './artifact.mjs';
import {gateView} from './results.mjs';
import {freeze} from './codec.mjs';
import {verifyVersion} from './integrity.mjs';

// Explicit V2 candidate. Pure artifact serialization: no report reads, HTTP,
// Policy import, evaluator injection or future PromotionResult access.
export function summaryV2(packet,trustedOwnerContext) {
  verifyVersion({...trustedOwnerContext.integrity,selectedVersion:'V2',consumerVersion:'SummaryConsumerV2',producer:trustedOwnerContext.producer});
  const artifact = consumeArtifact(packet,trustedOwnerContext);
  return freeze({...structuredClone(artifact.legacySummary),
    summaryProducer:{identity:artifact.producer.identity,sha256:artifact.producer.sha256,version:2,artifactDigest:trustedOwnerContext.digest,phase:'pre-approval'},
    policy:artifact.policy === null ? {state:artifact.policyState} : {...structuredClone(artifact.policy),state:artifact.policyState},
    resolvedSources:artifact.sources.map(r => ({...gateView(r,artifact.binding),
      rawFactDigest:r.rawFactDigest,configDigest:r.configDigest,
      policy:r.error?null:structuredClone(r.result),error:structuredClone(r.error)})),
    aggregateSecurityGate:structuredClone(artifact.aggregate)});
}
