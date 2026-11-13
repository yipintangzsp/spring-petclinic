# SOPS/age fixture prerequisite review — 2026-11-02

```text
SOPS_FIXTURE_PREPARATION_READINESS =
NOT_READY
```

Stopped at the user's steps 6/7: **the unchanged production entry does not force a dedicated kubeconfig or reject its absence before Kubernetes access**. This is a static compatibility/safety review, not a Gate run or a failed production attempt. No production API or Secret value was accessed. No fixture, executor, key, encrypted file, RBAC, Lease or namespace was created; no binary was downloaded.

## Verified isolated identity

Using only the existing explicit test kubeconfig and context, the owned Docker daemon/container and API binding were verified again before the two allowed read-only API queries:

| Item | Reconfirmed |
| --- | --- |
| Docker endpoint | `unix:///Users/zhangsir/.colima/security-test/docker.sock` |
| Daemon stable ID/name | `f0a9c4bb-ef14-4087-b0b1-7d5f02aa1ff8` / security-test |
| Cluster | security-test-sops |
| Node container | `9813796eee581bf765b2cd0fb93c26c632b4cb47a075b6c99a29e77597b19697` |
| API | `https://127.0.0.1:59645`, same owned container binding |
| Dedicated config | `/private/tmp/security-manager-kind-gdasvx1h/kubeconfig`, hash unchanged |
| kube-system UID | `54f300a4-5f1b-4e1e-86a1-d173e5a402d8`, same isolated cluster, different from historical production |
| Node / architecture | security-test-sops-control-plane / arm64, Ready |

No other Kubernetes context was queried. Existing user kubeconfig was hashed only, not used for API access.

## Exact blocker and evidence

1. `infra/security/scanner-runtime.mjs:9–15` calls `spawnSync` without an explicit child environment override; `kube` executes `kubectl --request-timeout=20s ...`. There is no `--kubeconfig`, `--context`, nonempty-path requirement, file identity check or local endpoint guard.
2. `infra/security/secrets-gate.mjs:5` calls `requireLease()` before any credential check. That immediately reaches `kubectl -n data-infra get lease platform-heavy`; the Gate has no preceding kubeconfig guard.
3. The `Encrypted Credentials` definition in `resources/security-manager/petclinic-adapter.json` invokes this same script and binds only the business age file. `vars/securityManager.groovy` propagates module environment/credentials but does not supply a test-only fail-closed boundary.
4. Version-matched [client-go v0.35.0 loader](https://github.com/kubernetes/client-go/blob/v0.35.0/tools/clientcmd/loader.go#L145) selects the default HOME kubeconfig when KUBECONFIG is unset/empty. Environment-path missing files are skipped/warned; an explicit `--kubeconfig` missing file instead errors. These are different cases: **this review does not claim a nonempty missing KUBECONFIG path itself necessarily falls back to HOME**.

The safe external driver used for this iteration explicitly pins the dedicated config/context. Its successful read-only queries do not prove the production script has the same property. No default/missing-config runtime probe was performed, to avoid any production-context or fixture use.

**User stop condition applies.** No production code was changed to remove this behavior, and the remaining design stages were not advanced after confirming it. Minimum next action is a separately scoped review of a test-only execution boundary that rejects unset/empty/missing/multiple/mismatched config paths, pins kubectl's exact dedicated file/context and validates local endpoint/CA/UID before Gate entry. Such a boundary is a proposal, not implemented or VERIFIED. It need not change frozen scanner/Gate comparisons.

## Frozen tool metadata already established

| Tool | Declared version | Expected file SHA256 |
| --- | --- | --- |
| sops | 3.13.3 | `53b0abacd38ef1b12a66d6c100956691b9cefce018d91f81e73ddf7438b94d77` |
| age | 1.3.2 | `41b072352f4561018949623c674d16ef704019b9108a9bbdbd21292efebfc94f` |
| age-keygen | age toolset 1.3.2 | `00b549cebf68302893fc489830f37e706712689ca877f84d85439d700d2997c7` |

`scanner-tools.json` SHA256 is `4fdb335010b9bf57d61d5e28d1397285c813bfa9bbf2ac008efddb8f27e3b703`, exactly matching `tools-lock.json`'s scanner-manifest pin. These prove frozen expected metadata, not an executed `--version`, ELF architecture or independent upstream artifact provenance. The inspected lock has no exact upstream download asset attestation; no URL or live binary source was guessed. Future binaries must match these exact file hashes. Linux/arm64 is the future executor requirement; it must be independently established for supplied tool bytes.

Production calls `/var/jenkins_home/platform-security/20261027/sops decrypt infra/security/secrets/<target>.enc.json`, with `SOPS_AGE_KEY_FILE=BUSINESS_AGE_FILE`, 15s timeout and 1MiB output bound. It verifies only sops at this entry; age/age-keygen are not called by the Gate. Synthetic key generation is a future fixture preparation activity, not part of the existing Gate. Tool download/source validation is unfinished after STOP.

## Partial contract inventory from unchanged source

This is **not** a finalized or executable fixture plan.

| Kind | Namespace/name | Current production consumer |
| --- | --- | --- |
| Namespace | petclinic | Three fixed Secret targets |
| Namespace | devsecops-system | Registry Secret and two impersonated identities |
| Namespace | data-infra | Existing outer heavy Lease; negative foreign-secret permission check |
| Secret | petclinic/petclinic-db | First encrypted target |
| Secret | petclinic/rabbitmq-client | Second encrypted target |
| Secret | petclinic/petclinic-harbor-pull | Third encrypted target |
| Secret | devsecops-system/kyverno-registry-pull | Fourth encrypted target |
| Lease | data-infra/platform-heavy | Holder must equal HEAVY_HOLDER or `jenkins-petclinic-${BUILD_NUMBER}`; no nested acquisition |
| ServiceAccount identity | devsecops-system/platform-secret-reconciler | Impersonated before/after Secret reads, optional SSA, and nine permission checks |
| ServiceAccount identity | devsecops-system/kyverno-admission-controller | Four verifier permission checks |

Four relative encrypted paths are fixed: `infra/security/secrets/petclinic-db.enc.json`, `rabbitmq-client.enc.json`, `petclinic-harbor-pull.enc.json`, `kyverno-registry-pull.enc.json` under the same directory. Do not copy production ciphertext/key into a future fixture workspace. A disposable test keypair is only a future proposal; no recipient/key was generated.

Gate validation is exactly:

- Desired kind/name/namespace must match; data must be truthy and stringData falsy. No particular label/annotation or hardcoded Secret type enum is checked here. Desired and live types must be equal; live/desired data must deep-equal. Exact future data types/keys are not finalized.
- Unless `DEVSECOPS_READ_ONLY=true`, apply server-side with field-manager `platform-secret-reconciler`. Read-only still decrypts and reads Secret data twice and cannot be used against production safely.
- After-operation UID must match the before-operation UID, and data must be unchanged. No additional desired-UID rule is invented.
- Reconciler must answer yes for named database and registry Secret get checks; all seven checked foreign/list/create operations must answer no. Verifier may get only its named registry Secret among its four checks; the other three must be no. Operational reads cover all four targets; write path needs exact named-target patch access. No broad create/list permission is inferred.
- Runtime import validates manifest hash; Lease, sops hash and credential-path prerequisites precede source read and Gate try/finally. Early prerequisite failures can exit without producing a JSON report.
- `.git-sha` supplies source identity. Report goes to `.devsecops/secrets-gate.json`. Final report write failure propagates. The adapter requires actual observations; incomplete evidence maps to NOT_CONFIGURED/null decision, not PASS. No policy evaluation was executed.

Counts confirmed from code: **3 namespaces / 4 target Secrets / 4 encrypted files / 1 Lease / 2 named SA identities**, plus a future disposable test keypair. This does **not** prove sufficiency of the full proposed fixture. Final RBAC object counts, restricted executor identity, tool provenance, synthetic data, key lifecycle, execution matrix and full cleanup contract remain unfinished after STOP. Existing kind admin kubeconfig is for the authorized identity inspection and is not approved as a future cluster-admin Gate executor.

## Requested 28-item disposition

| # | Item | Result |
| --- | --- | --- |
| 1 | Isolated cluster identity | RECONFIRMED as above |
| 2 | Implementation | secrets-gate.mjs, scanner-runtime.mjs, scanner-tools.json, tools-lock.json; Manager module/caller and existing adapter read only |
| 3 | SOPS version strategy | Locked expected 3.13.3; no tool execution/download |
| 4 | age version strategy | Locked expected 1.3.2; not invoked by Gate |
| 5 | Checksum | Manifest pin verified; exact expected file hashes recorded; upstream artifact proof unfinished |
| 6 | Executor design | Incomplete; stop before approving an executor; no container built/run |
| 7 | Kubeconfig forcing | Current Gate inherits environment, no forced explicit path/context |
| 8 | Fail-closed | NOT_ESTABLISHED; default HOME loading possible if env absent/empty |
| 9 | Namespaces | Three fixed names identified; none created |
| 10 | Secrets | Four fixed identities identified; values/types not finalized; none read/created |
| 11 | Lease | Fixed namespace/name/holder check identified; none created/read this iteration |
| 12 | SAs | Two fixed impersonated identities identified; none created |
| 13 | Exact RBAC | Checks inventoried; final Roles/Bindings and restricted executor not completed |
| 14 | Synthetic values | NOT_DESIGNED after STOP; no values generated/encoded |
| 15 | Key lifecycle | NOT_FINALIZED after STOP; zero key generation |
| 16 | Encrypted fixtures | Four filenames identified; zero files encrypted/copied/created |
| 17 | Execution matrix | NOT_COMPLETED after STOP; zero execution |
| 18 | Old decisions | No actual execution facts/decisions this iteration |
| 19 | Policy mapping | Existing adapter behavior read only; no new mapping or differential result |
| 20 | Cleanup plan | Final fixture lifecycle not completed; current iteration created no cluster fixture to clean |
| 21 | DNS restart | No restart performed; prospective executor remains unapproved, so no complete restart-dependency verdict; prior persistence limitation retained |
| 22 | Production API requests | 0 |
| 23 | Production Secret/credential values | 0; protected files hashed only; new test kubeconfig used for authorized read-only access |
| 24 | Resources created | 0; existing isolated cluster retained untouched |
| 25 | Files/config modified | New review evidence directory and this document only; no existing code/config modified |
| 26 | Readiness | NOT_READY |
| 27 | Blocker | Unresolved default kubeconfig/context fallback; production script not fail-closed |
| 28 | Next action | READY branch not entered; minimal scoped next review is test-only fail-closed boundary, then resume unfinished design |

Protection: all **3832 existing project files**, both Colima profiles/generated configurations, user SSH/kubeconfig/Docker config and host resolver hashes unchanged. Dedicated test kubeconfig hash unchanged. Global Docker context remains default. No Colima/VM restart, production Gate execution, binary download, Policy tests, Summary integration or rollout occurred.

Evidence directory: `evidence/2026-11-02/sops-fixture-prerequisite-review/`. Prior READY markers and SOPS compatibility NOT_TESTED/ENVIRONMENT_BLOCKED conclusions remain unchanged. Stop here.
