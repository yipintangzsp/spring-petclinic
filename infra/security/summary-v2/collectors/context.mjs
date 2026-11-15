import fs from 'node:fs';

// Trusted run context for collectors and for the pre-approval assembler
// (T08a / C4). The binding identity comes from the execution environment and
// from run files the pipeline itself produced — never from the artifact or
// receipt being assembled. Resolution order for the audit target:
//   1. AUDIT_TARGET_IMAGE / TARGET_SCOPE environment (Job parameters),
//   2. .devsecops/trivy-audit.json (auditTargetImage / targetScope),
//   3. .devsecops/security-summary.json (mid-pipeline writer output).
// Returns null when any identity piece is absent (manual or dev runs):
// collectors then stay silent and the production flow is untouched.
export function runBinding(root = '.') {
  try {
    const readJson = p => JSON.parse(fs.readFileSync(root+'/'+p,'utf8'));
    const source = fs.readFileSync(root+'/.git-sha','utf8').trim();
    if (!/^[a-f0-9]{40}$/.test(source)) return null;
    const build = Number(process.env.BUILD_NUMBER);
    if (!Number.isSafeInteger(build) || build < 1) return null;
    let candidate = process.env.AUDIT_TARGET_IMAGE || null, targetScope = process.env.TARGET_SCOPE || null, project = 'petclinic';
    if (!candidate) { try { const t = readJson('.devsecops/trivy-audit.json'); candidate = t.auditTargetImage; targetScope = t.targetScope; } catch {} }
    if (!candidate) { try { const s = readJson('.devsecops/security-summary.json'); candidate = s.auditTargetImage; targetScope = s.targetScope; project = s.project ?? project; } catch {} }
    if (!candidate || !/^\S+@sha256:[a-f0-9]{64}$/.test(candidate) || !['candidate','runtime','project'].includes(targetScope)) return null;
    return Object.freeze({job: process.env.JOB_NAME || 'petclinic-ci', build, project, source, candidate, targetScope,
      runId: process.env.BUILD_TAG || ('build-'+build)});
  } catch { return null; }
}
export const receiptsDir = (root = '.') => root+'/.devsecops/receipts';
