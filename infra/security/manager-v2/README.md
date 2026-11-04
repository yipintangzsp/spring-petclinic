# Security Manager V2 Candidate

Independent, **offline-only**, non-release entry. Production Jenkins, V1 Summary,
frozen Gates and canonical Runtime ownership remain unchanged. This is not an
enabled Summary V2 migration or a production promotion mechanism.

## Run

Node 22+; no npm download, Docker socket, Kubernetes credential or scanner needed.
From repository root:

```sh
candidate_root=$(mktemp -d /private/tmp/security-candidate.XXXXXX)
PLUGIN_SELECTION=semgrep,cosign GLOBAL_MODE=audit \
node infra/security/manager-v2/cli.mjs \
  --project java-example --run-id offline-001 \
  --inputs infra/security/manager-v2/example-inputs.json \
  --output "$candidate_root/run"
node --test infra/security/manager-v2/*.test.mjs
```

Use a fresh output directory each time. The parent must be owned by the caller,
not group/world-writable, and have a canonical path without symlinks. Existing
outputs are never reused. `--config FILE` accepts JSON with the structure below
(the JSON subset of YAML); arbitrary YAML features are not interpreted.

Environment parameters: `SECURITY_ENABLED=true|false`, `GLOBAL_MODE=off|audit|enforce`,
`SECURITY_LEVEL=low|standard|strict`, `PROFILE`, `POLICY_VERSION`,
`PLUGIN_SELECTION=all|none|comma-separated-registered-IDs`. Environment parameters
explicitly replace matching global settings; Profile/Component/Project precedence
is then applied. Unknown/duplicate CLI flags, IDs, values or configuration keys fail.
Exit 0 means ordinary **candidate** build may continue, 1 means it is blocked,
2 means invocation/configuration was rejected. None of these grants promotion.

```json
{
  "security": {
    "enabled": true, "globalMode": "audit", "securityLevel": "standard",
    "profile": "java-web", "policyVersion": "baseline-v1",
    "plugins": {"gitleaks":{"enabled":true},"semgrep":{"enabled":true},
                "cosign":{"enabled":true},"trivy":{"enabled":false}}
  },
  "profilePolicies": {"python-api":{"securityLevel":"standard"}},
  "componentOverrides": {"semgrep":{"policy":{"Medium":"FAIL"}}},
  "projectOverrides": {
    "python-example":{"policyOverrides":{"semgrep":{"Medium":"WARN"}}}
  }
}
```

## Contracts and precedence

Global defaults → global explicit → selected Profile → Component → matching
Project. Master switch and globalMode cannot be re-enabled by plugin configuration.
Unselected profile/project configuration is validated too; invalid configuration
never falls back. Configuration provenance, effective configuration digest and
existing engine override evidence are recorded. Profiles: java-web, python-api,
container-service, infra-k8s, iac. Registry defaults are enabled unless explicitly
disabled; the registry is not the list of canonical Runtime sources.

`registry.mjs` declares code-owned descriptors and fixed runner/normalizer/adapter
identities. Configuration cannot supply functions, modules, shell or Docker options.
Adding a plugin requires reviewed source, an approved archive entry and an existing
Policy adapter, not changes to other plugin runners. DefectDojo is a future consumer,
not a scanner. Other known plugins remain registered with honest preflight-only
status until their runner and prerequisites are independently implemented.

Capabilities are explicitly **caller-declared offline context**, not fresh live
infrastructure attestations. Missing is NOT_CONFIGURED, unavailable is UNSUPPORTED,
unselected profile is SKIPPED, switch-off is DISABLED. No nonexecution becomes PASS.
Trivy is always preflight-only, even if a caller asserts its missing capabilities.

`archive.mjs` independently collects each fixed, SHA-approved archive in a bounded
Node Worker, with empty environment and no inherited execArgv. It joins that worker
on success/error/timeout/cancellation. It never loads project code or executes a
scanner, network operation, Docker API or arbitrary command. This is **not** a Linux
kernel sandbox, and makes no claim about Trivy process/filesystem/storage isolation.

The six reports preserve archived controlled compatibility inputs. Their origin is
`ARCHIVED_CONTROLLED_REPLAY`, never a new scanner execution, production incident or
current Runtime proof. Synthetic credential-looking values in the old Cosign
fixture are explicitly disposable placeholders, not production secrets. No user
report or secret material is accepted into this fixed catalogue.

`result.mjs` calls the **existing** Policy Engine once per plugin, claiming before
await. It uses the same safe decision-metadata projection as the existing candidate
owner. Gate and Summary share the exact frozen result object and resultDigest.
Raw report bytes are retained separately without severity changes. Audit uses the
engine's enforce decision and changes only candidate orchestration, keeping FAIL.
Operational/Policy errors block the candidate even in audit.

Policy descriptors are Git pins of the existing baseline-v1 engine and baseline
file. `baseline-v2` is explicitly a **candidate compatibility alias with identical
rules**, not a newly validated production policy. `strict-v1` pins the existing
engine's strict level; explicit conflicting levels are rejected. No auto-upgrade,
second interpreter or modification of frozen baseline-v1 occurs.

`artifactStore` creates a private exclusive directory, read-only files, raw/config/
result digests and a seal. Verification requires the caller's independently retained
sealDigest, validates every recorded file and rejects changed bytes. This is tamper
evidence for a Candidate; an owner/root can still chmod files, and it is not WORM or
canonical production ImmutableArtifact. V1 `security-summary.json` is a reserved,
forbidden output filename. Candidate output is `candidate-summary.json`.

`router.mjs` validates the pinned artifact and summary before delivery. Fixed
dry-run/local-evidence consumers preserve resultDigests, issue delivery receipts and
record errors independently. No consumer re-evaluates Policy. DefectDojo future
adapter always returns NOT_CONFIGURED if enabled; it never calls a live API.

## Versioned Gitleaks source identity and real validation

The original frozen manifest is preserved. The only historical source mismatch
was the separately reviewed Helm Shadow integration in Jenkinsfile.security-audit
(first commit 90b4fca). `gitleaks-source-lock.mjs` accepts only the original or
versioned exact source identity, verifies all nine dependencies, pins both adapter
identities and proves the frozen decision body is byte-identical. Removing exactly
four Helm marker blocks must recover the original Jenkinsfile bytes. Unknown source
changes remain POLICY_ERROR. 127 original/current parent and wrapper differential
samples match; this does not rewrite the original frozen evidence.

`realGitleaksRegistry()` is a separate code-owned opt-in registry: Gitleaks defaults
to disabled and is the only real runner. Explicit plugin enablement plus a trusted
root-owned approval and SOURCE_DIR are required. The CLI selects it only with
`--gitleaks-approval` / `--source-dir`. Every other plugin remains unchanged.
`gitleaks-real.mjs` uses the existing pinned tool/image version and exact production
`gitleaks dir ... --redact=100` command, built-in configuration and reviewed finding
classifier. It accepts only root-owned bounded disposable snapshots, their approved
Git revision/content identity, a SHA-pinned binary and owner-private outputs. The
non-root Linux identity must have no root/Docker group, zero effective capabilities,
NoNewPrivs, no Docker socket or administrator kubeconfig access, and a scrubbed env.
No project executable, Docker API, Kubernetes write or network scanner runs.

The original source classifier is executed unchanged on the real normalized
locations, with only a bijective temporary path-prefix mapping. The existing Policy
Engine evaluates that same fact once; raw native bytes, fact digest, result digest
and a separately classified REAL_CONTROLLED_EXECUTION receipt are sealed. Failure
or missing prerequisites never becomes PASS. The tool process group is terminated
and checked; this is for a trusted pinned directory scanner, **not** a general
adversarial descendant isolation backend or a solution to Trivy isolation/storage.

Two disposable validation projects (java-web fake credential and python-api clean
source) have actually scanned on Linux; old classifier and standard Policy match
FAIL/FAIL and PASS/PASS. This proves the standalone scanner/classifier path only.
Production Kubernetes Pod/Lease/network-canary prerequisites were covered separately
by frozen parent differential replay, not re-executed here. The Candidate facts are
not canonical production RuntimeSourceFacts and do not change 14/16. Historical raw
payload remains unavailable; new controlled reports do not recover that history.
Evidence: `evidence/2026-11-04/security-manager-v2-gitleaks-real`.

## Rollback and boundary

There is no production configuration to roll back. Stop invoking the candidate CLI
and retain its evidence. Remove only a disposable candidate directory you created
after recording its seal if desired; never remove historical evidence. Reverting
the local candidate commit can remove this entry without changing production;
do not revert unrelated user changes. No push, Jenkins job creation, DB refresh,
Trivy scan, Dojo import, GitOps change, signing, release or rollout is performed.

## Second real plugin: Semgrep (Candidate .3)

`realPluginsRegistry()` opts into fixed Gitleaks and Semgrep real runners. Both real
plugins default disabled and need explicit `security.plugins.<id>.enabled=true`.
The default replay registry and `realGitleaksRegistry()` remain compatible.
`semgrep-real.mjs` uses the existing pinned Semgrep CE 1.182.1 native core and
`infra/security/scan-rules.json` unchanged. No registry/network rule download,
Python CLI auto-update, arbitrary shell, project hooks, or user runner code.

The Semgrep capabilities are SOURCE_DIR, SEMGREP_BINARY, SEMGREP_RULESET,
OUTPUT_DIR, POLICY_VERSION, and TRUSTED_VALIDATION_WORKSPACE. These hints do not
authorize execution: the runner also requires the existing approved Linux ARM64
non-root/no-new-privs/capability-free tool-only context, root-owned bounded
synthetic input approval, fixed dependency hashes, source inode/device/content,
and a private output directory. Unsupported architectures and Python-only input
cannot become scan PASS. This is not a Jenkins Agent identity backend.

The rules are Java-only. Cross-project real tests use java-fixture/java-web and
service-fixture/container-service with distinct approved Java snapshots. They do
not claim Python SAST coverage. Normalization preserves the native finding and
severity, and the existing Policy owner evaluates each completed plugin once.
Each native stdout is retained byte-for-byte inside the independent Semgrep raw
collection with its SHA; runtime facts bind source, tool, rules, and commands.
Errors/disabled/missing capability have no Policy PASS; a single plugin error is
recorded while unrelated plugins continue. Semgrep's total deadline is separate
from Gitleaks's timeout. Candidate results add Manager/profile/mode/level metadata
without changing the existing Result Router or Gitleaks runner business logic.

Real-mode CLI adds `--semgrep-approval` and `--semgrep-source-dir`. Combine them
with the existing `--gitleaks-approval` / `--source-dir` for the same Manager run;
all paths must already belong to a trusted approved disposable domain. CLI flags
alone are not approval and cannot supply a binary path, rule URL or shell command.
Other plugins should be explicitly disabled when exercising only these two.

Compatibility scope is the existing `classifySemgrep` finding classification and
the tested clean/high-risk production acceptance branches. Warning-only finding
classification is WARN; the existing combined production shell stage can still
exit successfully with warnings. The combined command-audit, Lease, Pod, network,
and production lifecycle Gate was not executed by the local real runner. Those
semantics and all production Gate sources remain unchanged.

Evidence and exact test/incident scope:
[evidence/2026-11-04/security-manager-v2-semgrep-real/REPORT.md](../../../evidence/2026-11-04/security-manager-v2-semgrep-real/REPORT.md).
One legacy replay test wrote fixed historical output paths during this round;
original bytes were restored only after a full pre-round SHA match. The incident,
new outputs and recovery receipts are retained. Legacy replay tests must run in
a disposable checkout (`clean-checkout.py`), not against sealed evidence paths.

The old disabled Jenkins CI package stays pinned to Candidate .2. Its frozen
release manifest must not be rewritten to accept .3; a future CI stage needs its
own reviewed versioned package. No Agent, Jenkins build, production Summary V2,
Trivy/Dojo execution, production Security Manager, release or rollout is enabled.

## Third real plugin: Cosign (Candidate .4)

`realThreePluginsRegistry()` adds the static, disabled-by-default `cosign-real`
runner without changing the existing Gitleaks/Semgrep definitions or replay
registry. Explicitly enable the desired plugins in configuration. Cosign needs
COSIGN_BINARY, COSIGN_VERSION, OFFLINE_SIGNED_OBJECT,
TRUSTED_VERIFICATION_IDENTITY, SIGNATURE_SOURCE, POLICY_VERSION,
VALIDATION_OUTPUT_DIR and the trusted non-production workspace capability.
Capability hints never authorize a source or public key by themselves.

`cosign-real.mjs` runs the fixed offline Cosign 3.1.4 ARM64 binary. It performs
verification only, never signs or accepts private-key parameters. Project-scoped
root-owned approvals pin synthetic object, public key and signature hashes and
fixed tool identity. Test identities cannot create production trust or promotion
eligibility. Missing actual binary is NOT_CONFIGURED, unsupported identity is
UNSUPPORTED, operational failure is ERROR, nonzero actual signature verification
is a completed Policy FAIL. Disabled/off branches do not launch the verifier.

The original production `signing.mjs` and frozen source manifest are unchanged.
An explicit `candidate-offline-blob-v1` evidence branch in the existing
`cosign-parent.mjs` reuses the exact original verify-blob command checker via
`cosign-blob-evidence.mjs`. Removing only the two marked additive blocks must
reproduce the original parent bytes. Existing production stages remain under
the old checks; the full old Cosign regression runs in a disposable sandbox.
This proves command-acceptance compatibility for offline blob verification,
not registry/admission/signing authorization or keyless/transparency verification.
The pre-existing no-transparency-log option is preserved for local keyed test
objects; it must not be described as production Sigstore trust verification.

CLI opts into the third fixed runner with `--cosign-approval` and
`--cosign-object`. The existing Gitleaks and Semgrep approval/source flags may be
combined. No arbitrary command, rule URL, key path or private-key option exists.
The summary adds compatible `validationRunId` and `overallDecision` aliases;
results, artifacts and the existing offline Router reuse the single evaluated
Policy object and resultDigest. No Consumer or earlier real runner logic changes.

Before any regression, run the explicit evidence boundary preflight. Tests must
execute in a unique disposable checkout under `infra/security/testing/evidence-boundary.py`,
which uses the macOS OS sandbox to deny network and writes outside that temporary
tree. This is a test executor boundary, not a Linux scanner execution backend.
Legacy tests may generate evidence only inside the disposable tree. Never run
old fixed-output tests from the repository root. Pre/post content SHA, mtime,
ctime, permissions, ownership, inode and historical file-list checks are separate.

See [Cosign evidence and complete scope](../../../evidence/2026-11-05/security-manager-v2-cosign-real/REPORT.md).
Historical #32 remains HISTORICAL_ARCHIVE; the fresh three-tool native suite is
same-round REAL_CONTROLLED_EXECUTION. Prior original evidence integrity remains
FAILED. Production Manager, Jenkins CI, Summary V2 and Runtime 14/16 are unchanged.

## DefectDojo Consumer Candidate (offline only)

`consumers/defectdojo.mjs` consumes sealed Candidate Summary/Results, standard
per-plugin raw/fact references and their existing digests. It never starts a
scanner or evaluates Policy. `router.mjs` adds a static explicit opt-in consumer;
the original CONSUMERS defaults and future placeholder remain unchanged. It does
not import the frozen production `governance/defectdojo.mjs` or its Trivy private
files. Existing Runner, Policy and production governance code is unchanged.

The installed DefectDojo 3.4.301 Generic Findings Import JSON parser was read
without tokens. `dojo-mapping-v1.json` pins parser/source hashes and a strict
supported field subset. Gitleaks uses the installed current parser's High default
when the native tool has no severity; this is a labeled governance mapping, not
an invented scanner severity or Policy change. Semgrep uses the installed parser's
exact severity conversion. Raw secrets, matches, source lines, messages and author
information never enter payloads. Evidence is represented by digests.

Cosign verification PASS is not a vulnerability. Failures remain supply-chain
metadata with explicit UNSUPPORTED Finding mapping until a type/severity mapping
is separately approved. Trivy remains a future mapping and need not run for other
plugins to prepare payloads. Disabled/error/unconfigured plugins generate no import
or history-closing action. All close_old_findings/auto_create_context flags are
false; no production Product is automatically created or selected.

`dojo-projects-v1.json` whitelists java-fixture/java-web and
service-fixture/container-service as separate nonproduction aliases. Real Product
and Engagement IDs are deliberately null, remoteApproved=false, apiRequestReady=false.
Production Product1/Engagement1 are excluded. This validates Candidate project
isolation; remote binding still needs an independently approved nonproduction context.

Offline payload files and plan digests are deterministic for the same Result;
Finding identity includes project/plugin/scope/rule/relative location but excludes
run ID. Repeated local preparation reuses the verified sealed directory. Publish
prepares under a uniquely owned temporary directory and atomically promotes the
sealed output. Failure cannot modify Policy or other Consumer records.
Generic unique_id_from_tool is stored by the current parser, but its shipped
matching is hash-based: this does **not** prove remote deduplication/idempotency.

Run only against an already sealed approved Candidate artifact:

```sh
node infra/security/manager-v2/consumers/dojo-cli.mjs \
  --artifact /absolute/path/to/candidate \
  --seal-digest <verified-candidate-seal-digest> \
  --output /absolute/path/to/owned-private-output
```

The CLI has no token, URL, arbitrary Product ID or remote publish flag. It emits
OFFLINE_PAYLOAD_PREPARED, never an HTTP-import success. Remote delivery and remote
idempotency remain NOT_TESTED. Payload format is checked against installed parser
code in an isolated harness with Django model doubles; DB/API acceptance is not
claimed. Every prepared payload remains Candidate-only with Promotion BLOCKED.

[Consumer evidence, samples, limitations and test entry](../../../evidence/2026-11-05/security-manager-v2-dojo-consumer/REPORT.md).
Regressions use the existing OS write sandbox and unique temporary copies. Do not
run historical fixed-output suites from the workspace root. Previous original
integrity remains FAILED; Runtime is 14/16, no production Summary V2 migration.
