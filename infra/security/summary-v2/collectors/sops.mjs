// Runtime collector for the sops source (secrets-gate.mjs). Captures exactly
// the raw shape policy/sops-evidence.mjs replays: prerequisites, per-target
// decrypt/read/apply/read-back observations, both can-i maps and the report
// write outcome. Decrypted stdout and Secret data exist only in this
// in-memory object for the duration of the gate process; the emitted receipt
// carries their digest, never the values (see ../receipts.mjs).
export function createSopsCollector() {
  const raw = {prerequisites:{},targets:[]};
  return {raw,
    prerequisites(p) { Object.assign(raw.prerequisites,p); },
    sourceRead(ok) { raw.sourceReadSucceeded = ok; },
    begin(readOnly,expectedTargetCount) { raw.readOnly = readOnly; raw.expectedTargetCount = expectedTargetCount; },
    target(namespace,name,decryptResult) {
      const t = {expected:{namespace,name},decrypt:{exitStatus:decryptResult.status,stdout:decryptResult.stdout}};
      raw.targets.push(t); return t;
    },
    rbac(map) { raw.rbac = map; },
    verifierRbac(map) { raw.verifierRbac = map; },
    reportWrite(ok) { raw.reportWriteSucceeded = ok; }
  };
}
