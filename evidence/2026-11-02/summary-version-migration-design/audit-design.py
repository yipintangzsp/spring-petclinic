"""Finalize design evidence. Never edit frozen/production files or old evidence."""
from pathlib import Path
import hashlib
import json
import subprocess

OUT = Path(__file__).resolve().parent
ROOT = OUT.parents[2]
DOC = ROOT / "docs/SUMMARY-VERSION-MIGRATION-DESIGN-20261102.md"
PRIOR = ROOT / "evidence/2026-11-02/summary-integration-readiness-audit"


def sha(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()


def write(name, value):
    (OUT / name).write_text(json.dumps(value, indent=2, ensure_ascii=False) + "\n")


before = json.loads((OUT / "before-sha256.json").read_text())
changed = [{"path": name, "before": old, "after": sha(ROOT / name) if (ROOT / name).is_file() else None}
           for name, old in before.items() if not (ROOT / name).is_file() or sha(ROOT / name) != old]
unexpected_new = [
    str(p.relative_to(ROOT)) for p in ROOT.rglob("*")
    if p.is_file() and ".git" not in p.relative_to(ROOT).parts and "__pycache__" not in p.parts
    and str(p.relative_to(ROOT)) not in before and OUT not in p.parents and p != DOC
]
write("no-production-mutation.json", {
    "existingFilesChecked": len(before), "changedOrRemoved": changed, "unexpectedNewFiles": unexpected_new,
    "allowedNewScope": [str(OUT.relative_to(ROOT)), str(DOC.relative_to(ROOT))],
    "productionFilesChanged": False if not changed and not unexpected_new else "ERROR",
    "releaseCount": 0, "rolloutCount": 0, "newRegisteredProducerHashes": 0,
    "newSummaryProducerCreated": False, "V1EvidenceRewritten": False,
})
checks = json.loads((PRIOR / "source-integrity.json").read_text())["checks"]
failures = []
for c in checks:
    actual = sha(ROOT / c["path"]) if (ROOT / c["path"]).is_file() else None
    if actual != c["expected"]:
        failures.append({**c, "actual": actual})
write("source-integrity.json", {"references": len(checks), "distinctFiles": len({c["path"] for c in checks}), "failures": failures})

targets = [
    "infra/security/security-summary.mjs", "resources/security-manager/summary.mjs",
    "infra/security/manager/summary.mjs", "vars/securityManager.groovy",
    "resources/security-manager/petclinic-adapter.json", "Jenkinsfile.security-audit",
]
locks = []
for p in sorted((ROOT / "infra/security/policy/versions").glob("*.json")):
    d = json.loads(p.read_text())
    relevant = {k: v for k, v in d.get("sourceHashes", {}).items() if k in targets}
    if relevant:
        locks.append({"path": str(p.relative_to(ROOT)), "sha256": sha(p), "relevantSourceHashes": relevant})
write("inspection.json", {
    "classification": "READ_ONLY_SOURCE_INSPECTION",
    "targets": {name: {"sha256": sha(ROOT / name), "locks": [r["path"] for r in locks if name in r["relevantSourceHashes"]]} for name in targets},
    "locks": locks,
    "guardPurpose": "Frozen compatibility oracle source-integrity, not a newly added production vulnerability/identity Gate",
    "genericLibraryResourceDirectlyPinnedBySourceHashes": any(targets[1] in r["relevantSourceHashes"] for r in locks),
    "noUntrustedProducerSelectedContract": True,
})
for name, argv in [
    ("policy-caller-search.txt", ["rg", "-n", "evaluate\\(|evaluateAsync\\(|resolvePolicy\\(|policy/engine|policy-result", "vars", "resources", "infra/security", "--glob", "!*.test.mjs", "--glob", "!*.json", "--glob", "!*.md"]),
    ("summary-consumer-search.txt", ["rg", "-n", "security-summary\\.json|security-summary\\.mjs|security-manager-summary", "Jenkinsfile.security-audit", "vars", "resources", "infra"]),
    ("source-guard-search.txt", ["rg", "-n", "sourceHashes|frozen .*source changed", "infra/security/policy", "--glob", "!*.test.mjs", "--glob", "!*.json"]),
]:
    p = subprocess.run(argv, cwd=ROOT, capture_output=True, text=True)
    assert p.returncode in (0, 1), p.stderr
    (OUT / name).write_text(p.stdout)
write("call-graph.json", {
    "production": [
        "Jenkinsfile.security-audit",
        "vars/securityManager.groovy call",
        "resources/security-manager/petclinic-adapter.json module.command",
        "Original scanner/prerequisite/Gate/cleanup -> reports/exception/exit code",
        "Manager code0=success; code10=warn only generic audit; other nonzero=failed",
        "security-manager.json, currentBuild result, fixed reports",
        "production security-summary.mjs before approval and in post always",
        "Promotion known-field contract, archive, Loki",
    ],
    "compatibility": ["frozen tests/harness", "existing evaluate/evaluateAsync", "resolvePolicy + classifier/frozen adapter", "actual Policy return object", "differential assertion/evidence"],
    "productionEngineCallerExists": False,
    "currentGateUsesEngineReturnFields": [],
    "currentEngineReturnSavedAsProductionArtifact": False,
    "currentSummaryAcceptsResolvedInput": False,
    "existingReusableOwnerLayer": "vars/securityManager.groovy; owner not implemented",
    "futurePreferredOwner": "Security Manager orchestration, one Node evaluation owner, trusted context keeps immutable reference",
    "scopeGap": "One Engine call accepts one component; no current multi-source final status API",
    "orderingGap": "Pre-approval Summary precedes Promotion completion; cannot use downstream successful approval outcome to authorize itself",
})
write("resolved-result-contract.design.json", {
    "classification": "DESIGN_ONLY_NOT_INSTALLED",
    "handoff": "immutable-intermediate-json",
    "schema": 1,
    "bindingFields": ["job", "build", "project", "source", "targetScope", "auditTargetImage", "policyVersion"],
    "snapshotFields": ["factsSha256", "configSha256"],
    "resultFieldsCopiedFromExistingEngine": ["policyVersion", "securityLevel", "profile", "effectivePolicy", "appliedOverrides", "status", "decision"],
    "errorReceipt": {"result": None, "error": {"status": "POLICY_ERROR", "message": "safe original Engine error"}},
    "metadataOnError": "explicit POLICY_ERROR without invented successful resolved fields",
    "expectedDigestSource": "trusted owner context, not payload self-report",
    "onceInvariantScopeProven": "single-source evaluation only",
    "wholePipelineCountOneProven": False,
    "summaryEvaluationCount": 0,
    "realAtomicIOTested": False,
    "sameUidCompromiseProtectionClaimed": False,
    "overrideSourceIntroduced": False,
})
write("migration-contract.design.json", {
    "classification": "DESIGN_ONLY_NOT_INSTALLED",
    "selectedStrategy": "C: explicit versioned integrity manifest/contract with pinned bundle delivery",
    "v1": {"labelIsDesignOnly": True, "producer": targets[0], "sha256": sha(ROOT / targets[0]), "summarySchema": 1, "oldLocksUnchanged": True},
    "v2": {"created": False, "registered": False, "actualSha256": None, "preferredSummarySchema": 1},
    "tupleFields": ["producer exact hash", "consumer exact hashes", "owner exact hash", "Engine/config exact hashes", "fixed source-root/revision", "metadata-required flag", "Summary schema"],
    "selection": "trusted pinned revision/descriptor chooses exactly one contract; no self-selection, auto fallback, wildcard, or future hash",
    "mixedVersionMatrix": [
        {"producer": "V1", "consumerContract": "V1", "expected": "ACCEPT"},
        {"producer": "V2", "consumerContract": "V2", "expected": "ACCEPT only after actual implementation verification"},
        {"producer": "V2", "consumerContract": "V1", "expected": "POLICY_ERROR in migration verifier; legacy runtime parser alone is not enforcement"},
        {"producer": "V1", "consumerContract": "V2", "expected": "POLICY_ERROR"},
        {"producer": "unknown hash", "expected": "POLICY_ERROR"},
        {"producer": "missing trusted identity", "expected": "POLICY_ERROR; V1 JSON does not need a new literal identity field"},
        {"producer": "tampered", "expected": "POLICY_ERROR"},
        {"producer": "valid V2", "metadata": "malformed", "expected": "POLICY_ERROR"},
    ],
    "rollback": "explicit complete V1 bundle in separate run/context; verify original hashes; never reuse V2 result in V1 run",
    "history": "Do not overwrite frozen #250-related evidence, old V1 oracles/locks or authoritative 2128 samples; current untracked Policy is not covered by HEAD alone",
})
tests = json.loads((OUT / "model-test-results.json").read_text())
exits = json.loads((OUT / "test-command-exits.json").read_text())
assert tests["tests"] == tests["pass"] == 32
assert exits == {"design-model": 0, "policy-core": 0}
assert not changed and not unexpected_new and not failures
write("readiness.json", {
    "SUMMARY_VERSION_MIGRATION_READINESS": "NOT_READY",
    "productionFilesChanged": False,
    "designDecisionsCompleted": [
        "Real production/compatibility call graphs distinguished",
        "Existing source-integrity contract and hash consumers inventoried",
        "Future owner selected; not misrepresented as current production caller",
        "Single-source immutable result contract and binding/error semantics defined",
        "Handoff options compared; artifact payload preferred for existing process/stage boundaries",
        "Migration strategies compared; versioned exact bundle selected",
        "Mixed-version, rollback and schema distinction defined",
        "Exact future changeset proposed without implementation",
    ],
    "blockers": [
        {"id": "B1", "capability": "pipeline-wide single actual evaluation and final Policy status", "evidence": "single-evaluation-scope-gap.json", "reason": "Existing single-component API cannot evaluate all production sources in one call; no approved aggregate status contract", "minimalNextStep": "Define a genuine multi-source evaluation API preserving current decisions, or explicitly revise invariant to once per source; do not implement/relabel N evaluations as one"},
        {"id": "B2", "capability": "one immutable result across pre-approval and final reporting", "evidence": "Jenkinsfile.security-audit:44-65,75 and promotion-evidence.mjs:9-18", "reason": "Pre-approval Summary precedes Promotion outcome; full pipeline result including that outcome cannot authorize its own creation", "minimalNextStep": "Define authorized result snapshot scope/cut and downstream outcome reporting without double evaluation or self-approval"},
    ],
    "tests": {"designAndReadonlyContracts": {"pass": 32, "total": 32}, "policyCore": {"pass": 5, "total": 5}},
    "actualV2Integration": "NOT_TESTED",
    "actualAtomicIO": "NOT_TESTED",
    "newParentScannerCompatibilitySamples": 0,
    "existingFilesPreserved": len(before),
    "sourceHashReferences": len(checks),
    "sourceHashFailures": 0,
    "stop": True,
    "nextPermittedIfReady": "NOT_APPLICABLE_NOT_READY",
})
(OUT / "REPORT.md").write_text(
    "# SUMMARY_VERSION_MIGRATION_READINESS = NOT_READY\n\n"
    "完整35项报告、真实调用图、交接契约、方案对比、版本矩阵、回滚和未来文件清单：\n\n"
    "[设计报告](" + str(DOC) + ")\n\n"
    "本轮32/32设计及只读契约检查、5/5 Policy core通过；不是实际V2验收。\n"
    "两个剩余设计阻塞：多来源全流水线一次实际求值接口、预审批与后续Promotion结果的时序/自批准边界。\n"
    "没有修改生产文件、更新接受的hash或生成Summary V2。source-integrity.json、"
    "no-production-mutation.json和readiness.json保存最终核验。\n"
)
entries = {
    str(p.relative_to(ROOT)): sha(p) for p in sorted(OUT.rglob("*"))
    if p.is_file() and p.name not in ("artifact-sha256.json", "final-validation.json")
}
entries[str(DOC.relative_to(ROOT))] = sha(DOC)
write("artifact-sha256.json", {"root": str(ROOT), "files": entries})
index_failures = [name for name, value in entries.items() if sha(ROOT / name) != value]
write("final-validation.json", {
    "artifactIndexSha256": sha(OUT / "artifact-sha256.json"),
    "indexEntries": len(entries), "indexHashFailures": index_failures,
    "existingFilesChecked": len(before), "existingChanges": changed,
    "unexpectedNewFiles": unexpected_new,
    "sourceHashReferences": len(checks), "distinctSourceFiles": len({c["path"] for c in checks}),
    "sourceHashFailures": failures, "productionFilesChanged": False,
    "designTests": "32/32 PASS", "policyCore": "5/5 PASS",
    "readiness": "NOT_READY", "evidenceValidation": "PASS" if not index_failures else "FAIL",
})
print(json.dumps({"existingFiles": len(before), "existingChanges": len(changed),
                  "unexpectedNewFiles": unexpected_new, "sourceRefs": len(checks),
                  "sourceFailures": len(failures), "indexEntries": len(entries),
                  "indexFailures": index_failures, "readiness": "NOT_READY"}))
