import fs from 'node:fs';
import {finalizeArtifact} from './artifact.mjs';
import {collectReceipts} from './receipts.mjs';
import {runBinding,receiptsDir} from './collectors/context.mjs';

// Pre-approval context assembly from a REAL run's outputs (T08a / C4). The
// legacy field snapshot is the actual V1 writer output
// (.devsecops/security-summary.json) — not a fixture; the source set is the
// cross-process receipt handoff (receipts.mjs); the aggregate is derived
// from those receipts and the writer's recorded build result. Nothing is
// fabricated: any missing input fails the assembly by name. The two external
// Gate checks are supplied by the executing context (a
// .devsecops/external-checks.json written by the Gate steps, or an explicit
// argument) because no pre-approval module produces them today.
export function producerFromContract(root = '.') {
  const c = JSON.parse(fs.readFileSync(root+'/infra/security/summary-v2/candidate-integrity.json','utf8'));
  return c.versions.V2.producer;
}
const observedStatus = r => {
  if (r.error) return 'failed';
  if (r.result.decision === 'FAIL' || r.result.status === 'ERROR') return 'failed';
  if (r.result.decision === 'WARN') return 'warn';
  if (r.result.decision === 'PASS') return 'success';
  return {SKIPPED:'skipped',DISABLED:'disabled',NOT_CONFIGURED:'not_configured'}[r.result.status] ?? 'failed';
};
export function assemblePreApproval({root = '.',binding = null,producer = null,externalChecks = null} = {}) {
  const bound = binding ?? runBinding(root);
  if (!bound) throw Error('POLICY_ERROR: run binding unavailable for assembly');
  if (!producer) throw Error('POLICY_ERROR: trusted producer identity absent');
  if (!externalChecks) {
    try { externalChecks = JSON.parse(fs.readFileSync(root+'/.devsecops/external-checks.json','utf8')); }
    catch { throw Error('POLICY_ERROR: external Gate checks absent'); }
  }
  const legacySummary = JSON.parse(fs.readFileSync(root+'/.devsecops/security-summary.json','utf8'));
  const receipts = collectReceipts(receiptsDir(root),bound);
  const sources = [...receipts.values()];
  const aggregate = {finalized:true,
    sources:Object.fromEntries(sources.map(r => [r.sourceId,{resultDigest:r.resultDigest,observedStatus:observedStatus(r)}])),
    externalChecks,inheritedBuildResult:legacySummary.build_result,result:null};
  aggregate.result = (Object.values(aggregate.sources).some(x => x.observedStatus === 'failed') || Object.values(externalChecks).includes('failed'))
    ? 'FAILURE' : legacySummary.build_result;
  return finalizeArtifact({binding:bound,sources,aggregate,legacySummary,producer});
}
