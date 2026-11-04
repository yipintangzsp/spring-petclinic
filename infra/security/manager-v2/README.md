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

## Known frozen compatibility blocker

The Gitleaks parent manifest still pins `Jenkinsfile.security-audit` SHA
`e6e7c1b8f838e42e8bc9b3aa35e731515e2e05feb300bd1833d64aa921c54ed2`.
Current source is
`6179859f70c1d6fec2560621ec1ae71dba20514de4ff430d84b7d60a1c319b3c`.
The authoritative engine rejects both archived Gitleaks inputs as POLICY_ERROR.
The candidate retains that result and blocks build continuation. Tests verifying
that fail-closed behavior **do not prove Gitleaks differential compatibility**.
No frozen hash was rewritten, old file restored over current source, or adapter
bypassed. This affected integration remains INCOMPLETE pending a separately reviewed
versioned source-compatibility proof. Semgrep/Cosign each have PASS/FAIL matches.

## Rollback and boundary

There is no production configuration to roll back. Stop invoking the candidate CLI
and retain its evidence. Remove only a disposable candidate directory you created
after recording its seal if desired; never remove historical evidence. Reverting
the local candidate commit can remove this entry without changing production;
do not revert unrelated user changes. No push, Jenkins job creation, DB refresh,
Trivy scan, Dojo import, GitOps change, signing, release or rollout is performed.
