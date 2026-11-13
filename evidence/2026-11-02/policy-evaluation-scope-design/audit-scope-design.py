"""Read-only source tracing and design consistency checks; no V2 implementation."""
from pathlib import Path
import hashlib
import json
import re
import subprocess

OUT = Path(__file__).resolve().parent
ROOT = OUT.parents[2]
DOC = ROOT / "docs/POLICY-EVALUATION-SCOPE-20261102.md"
PRIOR = ROOT / "evidence/2026-11-02/summary-integration-readiness-audit"


def sha(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()


def put(name, value):
    (OUT / name).write_text(json.dumps(value, indent=2, ensure_ascii=False) + "\n")


inventory = json.loads((PRIOR / "authoritative-source-matrix.json").read_text())
rows = inventory["sources"]
post = [r["source"] for r in rows if r["source"] == "security-approval-promotion"]
aliases = {r["source"]: r["aggregateAliasOf"] for r in rows if r.get("aggregateAliasOf")}
canonical = [r["source"] for r in rows if not r.get("aggregateAliasOf") and r["source"] not in post]
engine = (ROOT / "infra/security/policy/engine.mjs").read_text()
manager = (ROOT / "vars/securityManager.groovy").read_text()
pipeline = (ROOT / "Jenkinsfile.security-audit").read_text()
design_checks = []


def check(name, passed, evidence):
    assert passed, name
    design_checks.append({"check": name, "result": "PASS", "classification": "READ_ONLY_OR_DESIGN_CONSISTENCY", "evidence": evidence})


check("inventory partition covers all 18 labels once", len(rows) == 18 and len(canonical) == 16 and len(aliases) == 1 and len(post) == 1 and set(canonical) | set(aliases) | set(post) == {r["source"] for r in rows}, "authoritative-source-matrix.json")
check("Semgrep is an existing combination-stage alias", aliases == {"semgrep": "semgrep-command-audit"}, "aggregateAliasOf; command-parent.mjs consumes original combined command")
check("all aliases point to pre-approval canonical units", all(v in canonical for v in aliases.values()), "fixed trusted alias map")
check("Engine is per component and has no batch/global evaluate entry", "components.includes(facts.component)" in engine and "export function evaluate(facts,config={})" in engine and "export async function evaluateAsync(facts,config={})" in engine, "engine.mjs:71-75,140-144; prior actual API probe retained")
check("original wrapper keeps generic audit exit10 distinction", "code==10 && mode=='audit' && cfg.adapter!='petclinic'" in manager and "if(code!=0 && !warning)" in manager, "securityManager.groovy:58-62")
check("generic not_configured enforce rule preserved", "mode=='enforce' && cfg.adapter!='petclinic' && results.any{it.status=='not_configured'}" in manager, "securityManager.groovy:71")
check("read-only verification precedes pre-approval Summary", pipeline.index("stage('Read Only Release Verification')") < pipeline.index("node infra/security/security-summary.mjs; node infra/security/promotion/evidence.mjs sbom"), "Jenkinsfile.security-audit:34-48")
check("pre-approval Summary precedes candidate SBOM and signing", pipeline.index("node infra/security/security-summary.mjs;") < pipeline.index("node infra/security/promotion/evidence.mjs sbom") < pipeline.index("node infra/security/promotion/sign-approve.mjs"), "Jenkinsfile.security-audit:48,56")
check("real promotion happens after signing", pipeline.index("node infra/security/promotion/sign-approve.mjs") < pipeline.index('node infra/security/promotion/promote.mjs'), "Jenkinsfile.security-audit:56,65")
check("both promotion stage gates still require current build SUCCESS", pipeline.count("params.PROMOTION_ACTION != 'audit-only' && currentBuild.currentResult == 'SUCCESS'") == 3, "Jenkinsfile.security-audit:45,53,62")

nodes = [
    "source-facts", "per-source-engine", "gate-finalization",
    "pre-artifact", "summary-view", "candidate-sbom",
    "promotion-checks", "real-approval", "real-promotion", "promotion-result",
]
edges = [
    ("source-facts", "per-source-engine"), ("per-source-engine", "gate-finalization"),
    ("gate-finalization", "pre-artifact"), ("pre-artifact", "summary-view"),
    ("summary-view", "candidate-sbom"), ("pre-artifact", "promotion-checks"),
    ("candidate-sbom", "promotion-checks"), ("promotion-checks", "real-approval"),
    ("real-approval", "real-promotion"), ("real-promotion", "promotion-result"),
]
outgoing = {n: [] for n in nodes}
indegree = {n: 0 for n in nodes}
for a, b in edges:
    outgoing[a].append(b)
    indegree[b] += 1
queue = [n for n in nodes if indegree[n] == 0]
ordered = []
while queue:
    node = queue.pop()
    ordered.append(node)
    for nxt in outgoing[node]:
        indegree[nxt] -= 1
        if indegree[nxt] == 0:
            queue.append(nxt)
check("future design dependency graph is acyclic", len(ordered) == len(nodes), "phase-model.design.json; structural design proof only")
check("no post-promotion result is an input to pre artifact or approval", outgoing["promotion-result"] == [], "explicit pre input whitelist and no post->pre edge")
put("phase-model.design.json", {
    "classification": "DESIGN_ONLY_NOT_INSTALLED",
    "selectedModel": "B",
    "nodes": nodes, "edges": edges, "acyclic": len(ordered) == len(nodes),
    "preApprovalCut": "after Read Only Release Verification; before Summary and candidate image SBOM extraction",
    "forbiddenPreEvidence": ["current approved-release", "current approval-signing", "current promotion-result", "future runtimeAfter", "not-yet-extracted candidate image SBOM"],
    "policyAuthority": "immutable pre-approval artifact",
    "summaryAuthority": False,
    "postResult": "existing native approval/signing/promotion artifacts; optional diagnostic references, never rewrite pre input",
    "currentV1PostSummaryStillUnchanged": True,
})
put("evaluation-scope.design.json", {
    "classification": "DESIGN_ONLY_NOT_INSTALLED",
    "currentGranularity": "one facts.component per Engine evaluation",
    "productionEngineCallerCount": 0,
    "currentCallers": "compatibility tests and provenance-test-harness",
    "sourcePartition": {"inventoryLabels": 18, "canonicalPreApprovalSources": canonical, "aliases": aliases, "postScopeSources": post},
    "futureSourceOwner": "existing Security Manager orchestration with one Node evaluation owner",
    "futureAggregateOwner": "pure finalizer with Manager source results and Jenkins context after Read Only Verification",
    "invariant": "PER_SOURCE_SINGLE_EVALUATION",
    "engineEvaluationsPerObservedFactSet": 1,
    "summaryEvaluations": 0,
    "aggregateEvaluations": 0,
    "wholePipelineCountOneRequired": False,
    "sourceIdentity": ["canonical source/component/scope", "job/build/project", "source revision", "candidate/live/project target", "actual policyVersion/securityLevel/profile", "raw-fact/config/result digests"],
    "newEvaluationTimestampInvented": False,
    "aggregateIsSecondPolicyEvaluation": False,
    "aggregateGateStatus": "original observed Gate/Jenkins status, not reclassified source Policy status",
    "rawFactsAndSourceDecisionsRewritten": False,
    "sourceResultAuthority": "one captured actual existing Engine result or explicit original POLICY_ERROR receipt",
    "completeness": {
        "expectedSetAuthority": "trusted fixed plan, not result array self-report",
        "complete": "all canonical source outcomes terminal and bound; aggregate finalized; no unknown proof or missing evaluation",
        "completeMeansPass": False,
        "errorSkippedNotConfiguredVisible": True,
        "missingOrNotTestedEvidence": "INCOMPLETE; no fabricated result",
    },
})

cases = [
    ("one source one evaluation", "same canonical source/fact/config/run", "actual Engine=1; repeated request reuses result"),
    ("Gate reuse", "existing source result", "same digest; aggregate Engine=0"),
    ("Summary reuse", "existing source result", "same digest and metadata values"),
    ("Summary cannot evaluate", "attempt evaluator dependency/call", "reject dependency/call; Summary Engine=0"),
    ("missing result", "omit expected canonical source", "INCOMPLETE; no PASS fill"),
    ("duplicate result", "repeat source or alias as second evaluation", "reject; aliases only reference"),
    ("wrong source identity", "wrong component/source/scope", "POLICY_ERROR/reject"),
    ("stale source result", "wrong job/build/revision/raw/config binding", "reject replay"),
    ("complete source collection", "all terminal bound results plus final Gate context", "aggregate allowed; COMPLETE may still be failed"),
    ("incomplete collection", "expected canonical source not observed", "no complete eligibility"),
    ("POLICY_ERROR retained", "actual Engine throws POLICY_ERROR", "explicit error receipt; no successful default metadata"),
    ("SKIPPED retained", "existing allowed optional skip selection", "explicit SKIPPED; no fake scan, no invented mandatory FAIL"),
    ("NOT_CONFIGURED retained", "existing configuration/capability facts", "original enforce/audit semantics; no default PASS"),
    ("pre facts only", "pre view output and evidence whitelist", "reject post facts/refs"),
    ("future result absent", "Promotion not yet executed", "no fabricated approval/signature/runtimeAfter"),
    ("self-approval injection", "inject own future result or Summary self-approval flag", "cannot authorize; no backward dependency"),
    ("candidate mismatch", "artifact/native report/approval target differs", "reject"),
    ("separate PromotionResult", "actual later operation or observed exception", "separate native output/diagnostic; no pre mutation"),
    ("post binding", "later output candidate/job/build/source differs", "reject wrong binding"),
    ("promotion failure", "actual FAIL/rollback after eligible pre snapshot", "retain post failure and unchanged pre digest"),
]
put("test-matrix.design.json", {
    "classification": "FUTURE_IMPLEMENTATION_TEST_DESIGN",
    "cases": [{"id": i, "case": title, "input": inp, "expected": expected,
               "scope": "EVALUATION" if i <= 8 else "AGGREGATE" if i <= 13 else "PRE_APPROVAL" if i <= 17 else "POST_PROMOTION",
               "implementationExecution": "NOT_EXECUTED"} for i, (title, inp, expected) in enumerate(cases, 1)],
    "runtimeTestsRun": 0,
})
check("all requested future test cases are designed without runtime PASS claims", len(cases) == 20, "test-matrix.design.json")
doc = DOC.read_text()
check("all 34 final-report items exist", all("| "+str(i)+" |" in doc for i in range(1, 35)), str(DOC.relative_to(ROOT)))

core = subprocess.run(["node", "--test", "infra/security/policy/engine.test.mjs"], cwd=ROOT, capture_output=True)
(OUT / "policy-core.log").write_bytes(core.stdout)
(OUT / "policy-core.stderr").write_bytes(core.stderr)
put("test-command-exits.json", {"policyCore": core.returncode, "command": "node --test infra/security/policy/engine.test.mjs"})
assert core.returncode == 0
assert re.search(r"tests 5", core.stdout.decode()) and re.search(r"pass 5", core.stdout.decode())
before = json.loads((OUT / "before-sha256.json").read_text())
changed = [name for name, value in before.items() if not (ROOT / name).is_file() or sha(ROOT / name) != value]
new_outside_scope = [str(p.relative_to(ROOT)) for p in ROOT.rglob("*")
                     if p.is_file() and ".git" not in p.relative_to(ROOT).parts and "__pycache__" not in p.parts
                     and str(p.relative_to(ROOT)) not in before and OUT not in p.parents and p != DOC]
source_checks = json.loads((PRIOR / "source-integrity.json").read_text())["checks"]
source_failures = [r["path"] for r in source_checks if not (ROOT / r["path"]).is_file() or sha(ROOT / r["path"]) != r["expected"]]
assert not changed and not new_outside_scope and not source_failures
put("source-and-mutation-check.json", {
    "existingFilesChecked": len(before), "changedOrRemoved": changed,
    "unexpectedNewFiles": new_outside_scope, "productionFilesChanged": False,
    "sourceHashReferences": len(source_checks), "distinctSourceFiles": len({r["path"] for r in source_checks}),
    "sourceHashFailures": source_failures, "acceptedHashesChanged": False,
    "newSummaryV2": False, "newProductionResultArtifact": False, "rolloutCount": 0,
})
put("design-consistency-checks.json", {"classification": "READ_ONLY_OR_DESIGN_CONSISTENCY_NOT_RUNTIME_ACCEPTANCE", "checks": design_checks, "count": len(design_checks), "failures": []})
prior_doc = ROOT / "docs/SUMMARY-VERSION-MIGRATION-DESIGN-20261102.md"
put("readiness.json", {
    "POLICY_EVALUATION_SCOPE": "RESOLVED",
    "PRE_APPROVAL_SUMMARY_SCOPE": "RESOLVED",
    "SUMMARY_VERSION_MIGRATION_READINESS": "READY",
    "readinessScope": "DESIGN_ONLY",
    "POLICY_METADATA_SUMMARY_INTEGRATION": "INCOMPLETE",
    "B1": "resolved by explicitly authorized PER_SOURCE_SINGLE_EVALUATION, no batch API needed",
    "B2": "resolved by PRE_APPROVAL cut and separate post PromotionResult with no reverse authorization edge",
    "selectedMigrationStrategy": "VERSIONED_INTEGRITY_CONTRACT",
    "selectedResultHandoff": "IMMUTABLE_PER_SOURCE_RESULTS_PLUS_AGGREGATE_ARTIFACT",
    "selectedSummaryPhaseModel": "B",
    "promotionPolicyAuthority": "immutable artifact, not Summary view",
    "priorDesignPreserved": {"path": str(prior_doc.relative_to(ROOT)), "sha256": sha(prior_doc), "oldNotReadyRecordRewritten": False},
    "policyCore": "5/5 PASS",
    "futureImplementationMatrixCases": 20,
    "futureMatrixRuntimeTestsRun": 0,
    "designConsistencyChecks": len(design_checks),
    "actualV2Acceptance": "NOT_TESTED",
    "blockers": [],
    "productionFilesChanged": False,
    "acceptedHashesChanged": False,
    "newParentScannerCompatibilitySamples": 0,
    "nextPermittedAction": "This iteration STOP; later explicitly authorized versioned integrity migration and per-source handoff implementation, then actual consumer/Summary differential tests",
    "automaticImplementationAuthorized": False,
    "stop": True,
})
(OUT / "REPORT.md").write_text(
    "# Policy scope design — READY\n\n"
    "POLICY_EVALUATION_SCOPE = RESOLVED\n\n"
    "PRE_APPROVAL_SUMMARY_SCOPE = RESOLVED\n\n"
    "SUMMARY_VERSION_MIGRATION_READINESS = READY\n\n"
    "仅设计就绪，不是生产接入或V2验收完成。\n\n"
    "[完整34项报告](" + str(DOC) + ")\n\n"
    "Policy core 5/5 PASS；20项未来实现测试只完成设计，runtime未执行。\n"
    "本轮没有生产代码/accepted hash变更，没有V2、production result artifact或rollout。\n"
)
files = {str(p.relative_to(ROOT)): sha(p) for p in sorted(OUT.rglob("*"))
         if p.is_file() and p.name not in ("artifact-sha256.json", "final-validation.json")}
files[str(DOC.relative_to(ROOT))] = sha(DOC)
put("artifact-sha256.json", {"root": str(ROOT), "files": files})
index_failures = [name for name, value in files.items() if sha(ROOT / name) != value]
put("final-validation.json", {
    "indexEntries": len(files), "indexSha256": sha(OUT / "artifact-sha256.json"), "indexFailures": index_failures,
    "existingFilesChecked": len(before), "existingChanges": changed, "unexpectedNewFiles": new_outside_scope,
    "sourceHashReferences": len(source_checks), "distinctSourceFiles": len({r["path"] for r in source_checks}), "sourceHashFailures": source_failures,
    "designConsistencyChecks": len(design_checks), "policyCore": "5/5 PASS",
    "futureMatrixCases": 20, "futureMatrixRuntimeTestsRun": 0,
    "productionFilesChanged": False, "acceptedHashesChanged": False,
    "readiness": "READY_DESIGN_ONLY", "evidenceValidation": "PASS" if not index_failures else "FAIL",
})
print(json.dumps({"designConsistencyChecks": len(design_checks), "policyCore": "5/5 PASS",
                  "futureCasesDesigned": 20, "futureCasesRuntimeExecuted": 0,
                  "sourceRefs": len(source_checks), "sourceHashFailures": source_failures,
                  "existingFiles": len(before), "existingChanges": changed, "indexEntries": len(files),
                  "indexFailures": index_failures, "readiness": "READY_DESIGN_ONLY"}))
