// W9 probe: feed the genuine step1 image SBOMs (Trivy 0.76.2, CycloneDX 1.7)
// through the FROZEN SBOM Policy adapter in the exact standalone fact shape
// sbom-real.mjs constructs, and record the decisions. Read-only; seals nothing.
// Also isolates the blocker: the same documents with ONLY specVersion
// rewritten 1.7 -> 1.6 (probe copies, never sealed or shipped) flip to PASS,
// proving specVersion strict equality is the sole failing check.
import fs from "node:fs";
import path from "node:path";
const root = path.resolve(new URL("../../../", import.meta.url).pathname);
const {sbomParent} = await import(path.join(root, "infra/security/policy/sbom-parent.mjs"));
const {sbomEvidence} = await import(path.join(root, "infra/security/policy/sbom-evidence.mjs"));
const {evaluate} = await import(path.join(root, "infra/security/policy/engine.mjs"));
const out = {};
for (const arch of ["arm64", "amd64"]) {
  const raw = fs.readFileSync(path.join(root, "evidence/2026-11-12/supply-chain-step1-sbom-binding/artifact/sbom-image-" + arch + ".cdx.json"));
  const b64 = raw.toString("base64");
  const fact = {component: "sbom", status: "success", raw: {stage: "standalone", now: 1763040000000, extraction: {status: 0, base64: b64}, files: {"target/classes/META-INF/sbom/application.cdx.json": {value: b64}, ".git-sha": {value: "artifact-sha256:probe"}}, io: {"output-mkdir": {}, "sbom-write": {}, "summary-write": {}}}};
  const ev = sbomEvidence({packagedBase64: b64, mavenBase64: b64});
  const parent = sbomParent(structuredClone(fact.raw));
  const eng = evaluate(structuredClone(fact), {policyVersion: "baseline-v1", securityLevel: "standard", mode: "enforce"});
  const doc = JSON.parse(raw); doc.specVersion = "1.6";
  const b64b = Buffer.from(JSON.stringify(doc)).toString("base64");
  const ev2 = sbomEvidence({packagedBase64: b64b, mavenBase64: b64b});
  const fact2 = structuredClone(fact); fact2.raw.extraction.base64 = b64b; fact2.raw.files["target/classes/META-INF/sbom/application.cdx.json"].value = b64b;
  const parent2 = sbomParent(fact2.raw);
  out[arch] = {
    sbomEvidence: {decision: ev.decision, reason: ev.reason ?? null},
    sbomParent: {decision: parent.decision, status: parent.status, reason: parent.reason ?? null, failurePhase: parent.failurePhase ?? null},
    engine: {decision: eng.decision, status: eng.status, reason: eng.reason ?? null},
    specOnlyRewrite16: {sbomEvidence: {decision: ev2.decision, reason: ev2.reason ?? null}, sbomParent: {decision: parent2.decision, status: parent2.status, reason: parent2.reason ?? null}}
  };
}
console.log(JSON.stringify(out, null, 1));
