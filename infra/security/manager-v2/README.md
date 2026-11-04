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
