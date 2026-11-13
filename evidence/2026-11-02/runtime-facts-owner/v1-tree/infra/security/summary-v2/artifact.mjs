import fs from 'node:fs';
import path from 'node:path';
import {EXPECTED_SOURCES} from './inventory.mjs';
import {canonical,digest,equal,fail,freeze,object,sha,validateBinding} from './codec.mjs';
import {gateView,validateResult} from './results.mjs';

// Stage/Jenkins observations are distinct from Policy decisions. Preserve the
// existing catchError/audit/optional and SnapshotBefore/ReadOnlyVerification scope.
export function legacyModuleStatus(exitCode,mode) {
  if (!Number.isInteger(exitCode) || !['audit','enforce'].includes(mode)) fail('module outcome absent');
  return exitCode === 0 ? 'success' : exitCode === 10 && mode === 'audit' ? 'warn' : 'failed';
}
function validateAggregate(aggregate,sources,binding) {
  if (!object(aggregate) || aggregate.finalized !== true || !object(aggregate.sources)) fail('aggregate not finalized');
  if (!equal(Object.keys(aggregate.sources).sort(),[...EXPECTED_SOURCES].sort())) fail('aggregate source set');
  for (const r of sources) {
    const gate = aggregate.sources[r.sourceId];
    if (!object(gate) || gate.resultDigest !== r.resultDigest || !['success','warn','failed','skipped','disabled','not_configured'].includes(gate.observedStatus)) fail('aggregate result binding');
    gateView(r,binding);
  }
  if (!object(aggregate.externalChecks) || !equal(Object.keys(aggregate.externalChecks).sort(),['readOnlyReleaseVerification','snapshotBefore'].sort()) || !Object.values(aggregate.externalChecks).every(x => ['success','failed'].includes(x))) fail('external Gate checks missing');
  if (!['SUCCESS','UNSTABLE','FAILURE','ABORTED'].includes(aggregate.inheritedBuildResult)) fail('Jenkins build result absent');
  const failed = Object.values(aggregate.sources).some(x => x.observedStatus === 'failed') || Object.values(aggregate.externalChecks).includes('failed');
  const expected = failed ? 'FAILURE' : aggregate.inheritedBuildResult;
  if (aggregate.result !== expected) fail('aggregate Gate semantic drift');
  return expected;
}
const future = new Set(['promotionApproved','candidateDigest','approvedDigest','promotionResult','PromotionResult','finalApprovalSignatureResult','promotedDigestState','releaseSuccess','runtimeAfter','runtimeDigest','argoSyncResult','argoHealth','rollbackOccurred','gitOpsCommit','securityGitCommit']);
export function validatePreApproval(value) {
  const visit = x => { if (object(x)) for (const [k,v] of Object.entries(x)) { if (future.has(k)) fail('future promotion evidence in pre-approval input: '+k); visit(v); } else if (Array.isArray(x)) x.forEach(visit); };
  visit(value);
}
export function validateLegacySummary(summary,binding) {
  if (!object(summary) || summary.schema !== 1 || summary.build !== binding.build || summary.source !== binding.source || summary.project !== binding.project || summary.auditTargetImage !== binding.candidate || summary.targetScope !== binding.targetScope) fail('legacy Summary binding');
  if (['summaryProducer','policy','resolvedSources','aggregateSecurityGate'].some(k => Object.hasOwn(summary,k))) fail('legacy Summary collides with V2 metadata');
  validatePreApproval(summary);
}
export function finalizeArtifact({binding,sources,aggregate,legacySummary,producer}) {
  validateBinding(binding);
  if (!Array.isArray(sources) || sources.length !== EXPECTED_SOURCES.length) fail('missing expected source');
  if (!equal(sources.map(r => r.sourceId).sort(),[...EXPECTED_SOURCES].sort())) fail('duplicate/unknown/missing source');
  const validated = sources.map(r => validateResult(r,binding));
  if (validated.some(r => !r.evidenceComplete)) fail('incomplete raw source evidence');
  const configs = new Set(validated.map(r => r.configDigest));
  if (configs.size !== 1) fail('inconsistent Policy configuration snapshots');
  const success = validated.filter(r => r.result !== null).map(r => r.result);
  const metadata = success.length ? Object.fromEntries(['policyVersion','securityLevel','profile','effectivePolicy','appliedOverrides'].map(k => [k,structuredClone(success[0][k])])) : null;
  if (success.some(r => !equal(Object.fromEntries(Object.keys(metadata).map(k => [k,r[k]])),metadata))) fail('inconsistent resolved Policy metadata');
  validateAggregate(aggregate,validated,binding); validateLegacySummary(legacySummary,binding);
  if (!object(producer) || typeof producer.identity !== 'string' || !/^[a-f0-9]{64}$/.test(producer.sha256)) fail('producer identity absent');
  const value = {schema:1,kind:'PreApprovalPolicyArtifact',phase:'pre-approval',completeness:'COMPLETE',producer:structuredClone(producer),binding:structuredClone(binding),
    expectedSources:[...EXPECTED_SOURCES],sources:validated,policy:metadata,policyState:validated.some(r => r.error)?'POLICY_ERROR':'RESOLVED',
    aggregate:structuredClone(aggregate),legacySummary:structuredClone(legacySummary)};
  validatePreApproval(value); return freeze(value);
}
export function encodeArtifact(artifact) {
  const bytes = canonical(artifact); return freeze({bytes,digest:sha(bytes)});
}
export function consumeArtifact(packet,{digest:trustedDigest,binding,producer}) {
  if (!object(packet) || typeof packet.bytes !== 'string' || sha(packet.bytes) !== trustedDigest) fail('artifact integrity');
  let parsed; try { parsed = JSON.parse(packet.bytes); } catch { fail('malformed artifact JSON'); }
  if (parsed.kind !== 'PreApprovalPolicyArtifact' || parsed.schema !== 1 || parsed.phase !== 'pre-approval' || parsed.completeness !== 'COMPLETE') fail('incomplete artifact');
  if (!equal(parsed.binding,binding) || !equal(parsed.producer,producer)) fail('stale/wrong artifact producer or binding');
  const rebuilt = finalizeArtifact(parsed);
  if (!equal(rebuilt,parsed)) fail('malformed artifact fields');
  return rebuilt;
}
export function writeImmutableArtifact(directory,artifact) {
  const packet = encodeArtifact(artifact); fs.mkdirSync(directory,{recursive:true,mode:0o700});
  const filename = path.join(directory,'pre-approval-'+packet.digest+'.json');
  // No overwrite or symlink following; owner keeps digest outside file content.
  const fd = fs.openSync(filename,'wx',0o400);
  try { fs.writeFileSync(fd,packet.bytes); fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
  return freeze({path:filename,digest:packet.digest,binding:artifact.binding,producer:artifact.producer});
}
