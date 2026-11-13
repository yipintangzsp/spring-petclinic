"""Evidence only; no producer, Policy, Gate, scanner, or release changes."""
import hashlib
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[3]
OUT = Path(__file__).resolve().parent
PRIOR = ROOT / "evidence/2026-11-02/summary-integration-readiness-audit"


def digest(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()


def put(name, data):
    (OUT / name).write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n")


groups = {
    "identity": "schema project pipeline build build_result source recorded_at missing scannerScopes",
    "manager": "securityMode securityProfile securityModules",
    "provenance": "provenance_status attestation_verification build_provenance_status build_attestation_verification",
    "target": "runtimeImage auditTargetImage targetScope",
    "promotion": "candidateDigest approvedDigest securityGitCommit gitOpsCommit runtimeDigest promotionResult argoSyncResult argoHealth rollbackOccurred",
    "gitleaks": "gitleaks_status gitleaks_findings gitleaks_raw",
    "semgrep": "semgrep_status semgrep_findings semgrep_blocking semgrep_warn",
    "trivy": "trivy_status trivy_critical trivy_high trivy_medium trivy_low trivy_medium_governance",
    "sbom": "sbom_status sbom_generated sbom_components",
    "cosign": "cosign_status cosign_verified",
    "zap": "zap_status zap_findings zap_high zap_confirmed_high zap_unconfirmed_high zap_auth_status zap_auth_fixture_cases zap_auth_public_observations",
    "kyverno": "kyverno_status kyverno_enforced_cases kyverno_warning_probes kyverno_audit_workloads kyverno_scope",
    "kubescape": "kubescape_status kubescape_scan_success kubescape_failed_controls kubescape_high_risk_findings kubescape_findings kubescape_frameworks kubescape_framework_summary",
    "defectdojo": "defectdojo_status defectdojo_import_success defectdojo_product defectdojo_engagement defectdojo_tests defectdojo_total_findings defectdojo_duplicates defectdojo_open_findings defectdojo_critical defectdojo_high defectdojo_medium defectdojo_low defectdojo_accepted_risk defectdojo_mitigated_closed defectdojo_false_positives defectdojo_url",
    "command": "command_audit_status command_audit_counts script_command_review script_command_blocking script_command_tests ssh_command_status ssh_command_counts ssh_command_blocking ssh_command_tests interpreter_status interpreter_counts interpreter_blocking interpreter_tests",
    "falco": "falco_status falco_live_checks falco_runtime_blocking falco_runtime_assessment falco_historical_exit",
    "sonar": "sonar_status sonar_vulnerabilities sonar_security_hotspots sonar_security_rating",
}
put("before-contract.json", {
    "classification": "READ_ONLY_BEFORE_CONTRACT_NO_IMPLEMENTATION",
    "producer": "infra/security/security-summary.mjs",
    "directHelpers": ["infra/security/audit-target.mjs", "infra/security/governance/scan-counts.mjs"],
    "frozenSourceIndex": "before-contract-source-index.json",
    "output": ".devsecops/security-summary.json",
    "schema": 1,
    "fieldGroups": {k: v.split() for k, v in groups.items()},
    "statusSemantics": {
        "build_result": "SECURITY_BUILD_RESULT verbatim, default UNKNOWN",
        "tool_status": "Source report status verbatim, default unknown when report exists without status; absent report enters missing",
        "counts": "Most tool counts emitted only for success; absent/failed scan is not fabricated as zero",
        "trivy": "Complete success OR policy-failed report with complete scan evidence retains counts; incomplete evidence returns null/no counts",
        "sonar": "queried_current_project only on successful query; errors add sonarqube to missing",
        "policy": "No Policy object or evaluation in current producer",
    },
    "evidenceReferences": {
        "root": ".devsecops/",
        "files": "security-manager.json provenance-status.json attestation-verification.json build-provenance-status.json build-attestation-verification.json trivy-audit.json promotion-result.json approved-release.json source-gate.json semgrep-gate.json sbom-summary.json signing-admission.json zap-gate.json admission-gate.json kubescape-gate.json defectdojo-import.json command-audit.json runtime-health.json runtime-baseline.json".split(),
        "source": ".git-sha",
        "externalRead": "Sonar current-project measures query; unchanged and not invoked",
    },
    "writeSemantics": "mkdir recursive; synchronous direct overwrite JSON.stringify(record,null,2); not atomic; write precedes optional Loki push",
    "errorSemantics": {
        "optionalRead": "Missing or malformed JSON -> null",
        "source": ".git-sha read errors propagate",
        "malformedSuccessReport": "Uncaught property/shape errors may propagate",
        "sonar": "credential/HTTP/network/parse errors -> missing entry",
        "loki": "Unless SECURITY_SUMMARY_WRITE_ONLY=true, push must return 204 or throw; local output already written",
        "transportHelper": "3 attempts for TypeError/TimeoutError/AbortError or HTTP408/429/502/503/504; waits2s/4s; timeout20s per attempt",
    },
    "generic": {
        "authoritative": "resources/security-manager/summary.mjs",
        "usage": "vars/securityManager.groovy:74-75 libraryResource -> .security-manager-summary.mjs -> node",
        "duplicate": "infra/security/manager/summary.mjs is byte-identical; no generator declaration found",
        "baseFields": "schema project pipeline build build_result mode profile recorded_at targetScope source modules missing optionalScansExecuted".split(),
        "conditionalFields": "Current-build enabled nine tool status/findings; trivy severity fields; sbom_generated; provenance fields",
        "errors": "Required security-manager report; directory must exist; Loki204 required; no generic WRITE_ONLY switch",
    },
})
consumers = [
    ("Promotion evidence loader", ["infra/security/promotion/evidence.mjs:3"], "A", "JSON.parse Summary; no closed field-set validation", "STATIC_INSPECTION"),
    ("Promotion contract/sign-approve/promote", ["infra/security/promotion/contract.mjs:2", "infra/security/promotion/sign-approve.mjs", "infra/security/promotion/promote.mjs"], "B", "Select known identity/build/targetScope/trivy C/H fields", "CONTROLLED_CONTRACT_ONLY; no approval/sign/release"),
    ("Jenkins archive", ["Jenkinsfile.security-audit:48", "Jenkinsfile.security-audit:75", "Jenkinsfile.security-audit:76"], "A", "Archive fixed path/name; no JSON field equality", "STATIC_INSPECTION_ONLY"),
    ("Shared Library invocation", ["vars/securityManager.groovy:74", "vars/securityManager.groovy:75"], "A", "Runs libraryResource script; no Summary parser at caller", "STATIC_INSPECTION_ONLY"),
    ("Loki publishing", ["infra/security/security-summary.mjs:30", "resources/security-manager/summary.mjs:8", "infra/security/manager/summary.mjs:8"], "A", "Complete record serialized as log-line string; labels independent of extra fields", "STATIC_INSPECTION_ONLY; no publish"),
    ("Grafana LogQL", ["infra/security/governance/grafana-panels.json"], "B", "Named extraction of existing Kubescape/Dojo fields", "STATIC_INSPECTION_ONLY; no query"),
    ("Promotion frozen source guard", ["infra/security/policy/promotion-evidence.mjs:4", "infra/security/policy/versions/promotion-baseline-v1.json:19"], "C/D", "Exact producer SOURCE SHA, distinct from JSON field equality", "CONTROLLED_IN_MEMORY_PROBE_CONFIRMED"),
    ("Regression frozen source guard", ["infra/security/policy/regression-evidence.mjs:5", "infra/security/policy/versions/regression-baseline-v1.json:60"], "C/D", "Exact producer SOURCE SHA, distinct from JSON field equality", "CONTROLLED_IN_MEMORY_PROBE_CONFIRMED"),
    ("Promotion parent tests/oracle", ["infra/security/policy/promotion-parent.test.mjs", "infra/security/policy/promotion-fixtures.mjs", "infra/security/policy/promotion-workflow-oracle.groovy"], "B/D", "Summary fixture JSON and missing/malformed input cases; source identity transitively frozen", "STATIC_INSPECTION_ONLY; no regeneration"),
    ("Workflow regression oracles", ["infra/security/policy/regression-workflow-oracle.groovy", "infra/security/policy/command-parent-workflow-oracle.groovy", "infra/security/policy/gitleaks-parent-workflow-oracle.groovy", "infra/security/policy/zap-parent-workflow-oracle.groovy", "infra/security/policy/trivy-parent-workflow-oracle.groovy", "infra/security/policy/sbom-workflow-oracle.groovy"], "A", "Treat generic Summary invocation as inert step, not real Summary integration", "STATIC_INSPECTION_ONLY"),
]
put("consumer-inventory.json", {
    "scope": "Repository-visible consumers; no claim about undisclosed external parsers",
    "closedJsonSchemaFound": False,
    "exactSourceConstraintFound": True,
    "consumers": [dict(zip(["consumer", "paths", "class", "behavior", "validation"], row)) for row in consumers],
})
for name, argv in [
    ("consumer-search.txt", ["rg", "-n", "security-summary\\.json|security-summary\\.mjs|security-manager-summary", "Jenkinsfile.security-audit", "vars", "resources", "infra"]),
    ("policy-caller-search.txt", ["rg", "-n", "evaluate\\(|evaluateAsync\\(|resolvePolicy\\(|policy/engine|policy-result", "vars", "resources", "infra/security", "--glob", "!*.test.mjs", "--glob", "!*.md", "--glob", "!*.json"]),
]:
    p = subprocess.run(argv, cwd=ROOT, capture_output=True, text=True)
    (OUT / name).write_text(p.stdout)
    if p.returncode not in (0, 1):
        raise RuntimeError(p.stderr)
put("evaluation-handoff-check.json", {
    "classification": "STATIC_INSPECTION_NO_IMPLEMENTATION",
    "productionPolicyEvaluationCallerFound": False,
    "existingResolvedResultArtifactHandoffFound": False,
    "currentCallSites": "Engine internals and compatibility test/evidence runners; none in production producer or Shared Library invocation",
    "constraint": "Summary serializes a prior authoritative result; must not introduce a second/new evaluation",
    "precondition": "Specify single evaluation result handoff; do not fabricate metadata or pretend a nonexistent input is authoritative",
    "newEvaluationIntroduced": False,
})
put("schema-and-metadata-disposition.json", {
    "implementation": "NOT_EXECUTED_PREIMPLEMENTATION_STOP",
    "preferredFutureShapeOnly": {"policy": ["policyVersion", "securityLevel", "effectivePolicy", "appliedOverrides", "status"]},
    "overrideSource": "Not introduced; existing appliedOverrides supplies provenance",
    "POLICY_ERROR": "Required but NOT IMPLEMENTED: valid Summary with explicit policy.status=POLICY_ERROR, without fake low/standard/PASS metadata",
    "schema": {"actual": 1, "changed": False, "provisionalPreferred": "keep1 for additive metadata", "proof": "validateGate accepts extra policy; full new Summary/schema regression NOT_EXECUTED"},
    "oldNewSummaryDifferential": "NOT_EXECUTED",
    "metadataCaseResults": {k: "NOT_EXECUTED_IN_REAL_SUMMARY" for k in ["PASS", "FAIL", "WARN", "SKIPPED", "NOT_CONFIGURED", "POLICY_ERROR", "default-standard", "low", "strict", "component-override", "project-override"]},
})
before = json.loads((OUT / "before-sha256.json").read_text())
changes = [{"path": p, "before": h, "after": digest(ROOT / p) if (ROOT / p).is_file() else None}
           for p, h in before.items() if not (ROOT / p).is_file() or digest(ROOT / p) != h]
put("no-mutation-proof.json", {"existingFilesChecked": len(before), "changedOrRemoved": changes, "allExistingBytesPreserved": not changes, "newFilesScope": str(OUT.relative_to(ROOT))})
checks = json.loads((PRIOR / "source-integrity.json").read_text())["checks"]
failures = []
for row in checks:
    actual = digest(ROOT / row["path"]) if (ROOT / row["path"]).is_file() else None
    if actual != row["expected"]:
        failures.append({**row, "actual": actual})
put("source-postcheck.json", {"references": len(checks), "distinctFiles": len({r["path"] for r in checks}), "failures": failures})
assert json.loads((OUT / "test-command-exits.json").read_text()) == {"preflight": 0, "core": 0}
proof = json.loads((OUT / "source-lock-blocker-proof.json").read_text())
assert proof["blockerConfirmed"] and len(proof["probes"]) == 2
assert not changes and not failures
put("verdict.json", {
    "POLICY_METADATA_SUMMARY_INTEGRATION": "INCOMPLETE",
    "productionFilesChanged": [],
    "actualSummaryIntegrated": False,
    "confirmedActualSemanticRegression": False,
    "blocker": "Producer pinned by Promotion/Regression frozen source guards; edit requires source-lock/version reconciliation outside Summary-only scope",
    "affectedCapabilities": ["security-approval-promotion", "regression", "actual-summary-metadata"],
    "additionalPrecondition": "No upstream authoritative evaluated Policy result handoff found for serialization-only integration",
    "tests": {"policyCore": {"pass": 5, "total": 5}, "preimplementationChecks": {"pass": 3, "total": 3}, "actualSummaryIntegration": "NOT_EXECUTED"},
    "newParentScannerCompatibilitySamples": 0,
    "priorParentSamplesUnchanged": 2128,
    "sourceHashFailures": 0,
    "releaseCount": 0,
    "rolloutCount": 0,
    "approvalSigningPromotionCount": 0,
    "minimalNextStep": "Separately scope versioned migration preserving original source/oracle/hash evidence and proving additive equivalence; define single-evaluation result handoff, then retry Summary integration. Do not merely replace pinned hashes.",
    "stop": True,
})
assert (OUT / "REPORT.md").is_file(), "Final report required before indexing"
files = {str(p.relative_to(OUT)): digest(p) for p in sorted(OUT.rglob("*"))
         if p.is_file() and p.name not in ("artifact-sha256.json", "final-validation.json")}
put("artifact-sha256.json", files)
errors = [p for p, h in files.items() if digest(OUT / p) != h]
put("final-validation.json", {"index": "artifact-sha256.json", "indexSha256": digest(OUT / "artifact-sha256.json"), "entries": len(files), "failures": errors, "existingFileHashFailures": len(changes), "sourceHashFailures": len(failures), "verdict": "INCOMPLETE", "validation": "PASS" if not errors else "FAIL"})
print(json.dumps({"evidenceEntries": len(files), "existingFilesChecked": len(before), "existingChanges": len(changes), "sourceChecks": len(checks), "sourceFailures": len(failures), "indexFailures": len(errors), "POLICY_METADATA_SUMMARY_INTEGRATION": "INCOMPLETE"}))
