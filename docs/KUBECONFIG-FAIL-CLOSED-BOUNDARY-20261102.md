# Test-only fail-closed Kubernetes execution boundary — 2026-11-02

```text
TEST_WRAPPER_SUFFICIENT
KUBECONFIG_FAIL_CLOSED_BOUNDARY =
READY
```

Only the test boundary was implemented. Production scanner/Gate/Policy/Summary/Manager/release code remains unchanged. No SOPS/age execution, fixture objects, key generation or tool download occurred. The CLI deliberately exposes only `check` and fixed `sentinel` modes, and cannot launch the production Gate.

## 1–4. Call graph, fallback and chosen location

New files:

- `infra/security/testing/isolated_sops_executor.py`: guard, sanitized environment, private config snapshot, guarded kubectl shim and trusted-child library entry.
- `infra/security/testing/test_isolated_sops_executor.py`: guard-only controlled negative tests.

Existing path, read only:

```text
Manager Encrypted Credentials
  -> node infra/security/secrets-gate.mjs
  -> import scanner-runtime.mjs (manifest/lock check)
  -> requireLease()
  -> read() -> kube() -> run('kubectl', ['--request-timeout=20s', ...])
  -> spawnSync (inherits child environment)
```

Without an outer guard, the original helper delegates config loading to kubectl. It has no explicit path/context check; an unset/empty KUBECONFIG can select the default HOME configuration. Production code was not changed to address this.

Protected future entry, demonstrated with harmless children only:

```text
explicit input argument + KUBECONFIG
  -> offline mandatory/path/type/owner/mode/YAML/context/server/CA/digest validation
  -> private per-invocation config snapshot + clean HOME
  -> one pinned local TLS metadata GET -> expected kube-system UID
  -> sanitized child environment, shim first in PATH
  -> trusted child (this round: fixed sentinel only)
  -> future unchanged scanner-runtime `kubectl` would resolve to shim
  -> shim rejects missing/changed config/env and connection overrides
  -> absolute kubectl --kubeconfig <private snapshot> --context kind-security-test-sops ...
```

No subprocess or network function is called before offline validation succeeds. No kubectl was actually invoked by any boundary test; live identity is checked directly through Python HTTPS with mutual TLS. The existing production helper's literal `kubectl` lookup and inherited environment make wrapper-only protection sufficient for this reviewed call graph. Absolute kubectl bypasses or arbitrary malicious child code are not a sandbox guarantee; no production child was run or treated as verified here.

## 5–7. Enforcement and environment

Pinned source path: `/private/tmp/security-manager-kind-gdasvx1h/kubeconfig`.

Pinned context/cluster: `kind-security-test-sops`; server: `https://127.0.0.1:59645`; kube-system UID: `54f300a4-5f1b-4e1e-86a1-d173e5a402d8`; CA SHA256: `90507a6f34d0b4e9b31cf862d74b7c2694b465c2e959f99bb45705ef0c8a46d8`.

The exact original config SHA256 is also pinned. CLI cannot override these pins. Binding injection in unit tests changes only the owned temporary input path; it is not a CLI option. New cluster/config identities require a separate trusted rebind; they cannot silently replace this contract.

Validation rejects unset/whitespace-only KUBECONFIG, missing explicit argument, multiple files, relative/different paths, missing/non-regular files, wrong owner, permissions other than 0400/0600, oversized/empty input, unsafe YAML aliases/duplicates, wrong identity/server, connection overrides, external auth plugins/file references, wrong CA and changed config bytes. Errors expose stable codes, never config contents or parser/key values.

After validation, a byte-identical config is copied to a new mode0400 file beneath a mode0700 temporary directory. Child KUBECONFIG names **that explicit dedicated snapshot**, rather than the original mutable input or default HOME. Client cert/key copies for TLS are private and removed immediately after identity verification. The whole execution directory is removed on exit. Parent HOME and user kubeconfig are never renamed or edited.

| Rule | Names/behavior |
| --- | --- |
| Preserve | LANG, LC_ALL, TZ only if present |
| Explicitly set | HOME, KUBECONFIG, PATH, TMPDIR, XDG_CACHE_HOME, PYTHONDONTWRITEBYTECODE, ISOLATED_BOUNDARY_CONTEXT |
| HOME | New empty private home; no `.kube/config` |
| PATH | Private guarded kubectl shim first, then fixed system/Homebrew tool paths; inherited PATH ignored |
| Remove/default deny | All unrelated KUBE*, KUBERNETES_SERVICE_*, Docker, SOPS_*, AGE*, BUSINESS_AGE_FILE, AWS_*, SSH_*, Google/Azure/cloud credentials, proxy variables and all other inherited names |
| Docker | Outer evidence driver uses explicit security-test socket; child does not need/inherit DOCKER_HOST/DOCKER_CONFIG |
| Proxies | Not needed for the literal loopback identity request; not inherited |

Actual sentinel environment names are recorded. macOS/Python added `__CF_USER_TEXT_ENCODING` despite its removal from the constructed environment; it is ordinary platform metadata, not an inherited Kubernetes/cloud/secret variable. No credential values were logged.

The library supports an explicit trusted absolute executable and private working directory for later integration without changing Gate comparisons. No command is synthesized from shell text, no Gate invocation is built in, no new overall timeout is imposed on that future child, and its output is suppressed. Future fixture inputs/credentials/workspace remain separately scoped: this module does not implement them. The current CLI cannot select that generic library mode.

## 8–14,17. Negative and no-fallback proof

**18/18 guard tests passed**, containing **19 rejected input records** and one pure kubectl-proxy preparation record. Required cases:

| Case | Explicit rejection |
| --- | --- |
| KUBECONFIG unset | KUBECONFIG_UNSET |
| Empty/whitespace | KUBECONFIG_EMPTY |
| Nonexistent file | CONFIG_FILE_MISSING |
| Directory | CONFIG_NOT_REGULAR_FILE |
| Malformed config | MALFORMED_CONFIG |
| Wrong server | SERVER_MISMATCH |
| Wrong cluster identity | CLUSTER_IDENTITY_MISMATCH |
| Real default config exists, dedicated env absent | KUBECONFIG_UNSET; only existence checked, real default contents not read |
| Real default exists, explicit dedicated path missing | CONFIG_FILE_MISSING |
| Fake HOME/default present, env absent | KUBECONFIG_UNSET |
| Fake HOME/default present, dedicated path missing | CONFIG_FILE_MISSING |
| Multiple KUBECONFIG files | MULTIPLE_KUBECONFIG_FILES |

Additional tests cover empty config files, missing explicit argument, permissions, current-context, external exec auth, CA mismatch, duplicate YAML, sanitized env, changed child KUBECONFIG and forbidden kubectl connection/URL overrides.

Every rejected input independently trapped socket creation and subprocess run/Popen, with **zero calls** to all three. Guard audit counters also show zero API, kubectl and child execution. Semantic-invalid test samples use a temporary file binding to exercise parser/identity branches without changing the real dedicated kubeconfig; CLI cannot override that binding. These are real guard-validation/unit executions with controlled config samples, not SOPS/Policy differential evidence or production historical failures.

A separate **real CLI rejection**, with a fake default HOME but KUBECONFIG absent, exited 42 before any API/child invocation. The fake default file was never selected and remained unchanged.

Zero-API claims apply to offline-rejected configurations. A live namespace UID can only be measured by a request: once all offline pins pass, the guard may issue exactly one GET to the literal pinned loopback endpoint, using the pinned CA and test client identity. A live UID/TLS/network mismatch then prevents child execution. This is not claimed to be a zero-request live UID measurement.

## 15–16. Real positive and sentinel proof

1. Real CLI `check`: exact source accepted, local expected UID verified, wouldPermitChild=true, stopped before child. One read-only local metadata GET, zero kubectl calls.
2. Real CLI `sentinel`, with fake parent HOME/default config and synthetic hostile environment names: same identity check, fixed `ISOLATED_KUBECONFIG_SENTINEL_OK`, exit0, sanitized child env/clean HOME/private snapshot assertions passed. One local GET, zero kubectl calls.
3. Final trusted-child library entry: same guard and environment, absolute Python fixed harmless sentinel and private cwd, fixed marker observed, exit0; no Gate command. One local GET, zero kubectl calls. Generic output was suppressed.

All owned temporary directories, config snapshots and test-client cert/key copies were removed. Original dedicated config hash stayed unchanged. Fake/default target `192.0.2.1:65535` was never contacted; the implementation's sole metadata request is hardcoded to the approved loopback endpoint and does not consult proxies or follow redirects.

## 18–22. Counters, protection and files

| Item | Result |
| --- | --- |
| Test API requests | **3**, all read-only kube-system metadata on the pinned local endpoint |
| Actual kubectl invocation | **0** in this round; shim argv/override behavior tested without exec |
| Production API requests | **0** |
| Kubernetes Secret value reads | **0** |
| Production credential/private-key reads | **0** |
| Production Gate / SOPS / Policy differential | **0 / 0 / 0** |
| Fixture namespace/Secret/Lease/SA/RBAC | **0** |
| Colima/VM restart | **0** |
| User kubeconfig/SSH/default profile | Hash unchanged |
| Dedicated test config | Hash unchanged |
| Global Docker context | default, unchanged |
| Kind cluster | Same exact node container, owned volume and kind network; no Kubernetes mutation |
| Existing project files | **3843/3843** hashes unchanged |

Only the two new test-only Python files, this new document and `evidence/2026-11-02/kubeconfig-fail-closed-boundary/` were added. No production source/config file was modified. Tests used already installed Python/PyYAML and no downloads. Missing dependencies fail before Kubernetes access; future isolated-executor packaging remains a separate prerequisite review.

## 23–26. Decision and stop

**TEST_WRAPPER_SUFFICIENT** for the reviewed unchanged `scanner-runtime` call path; shared-runtime modification is not needed.

**KUBECONFIG_FAIL_CLOSED_BOUNDARY = READY**, limited to this test execution boundary. No blocker remains for this round's guard criteria. Full SOPS fixture preparation/compatibility was not re-evaluated or marked READY/VERIFIED, and no fixture design resumed.

Next eligible action, only in a separately scoped next iteration: resume the unfinished SOPS/age toolchain and fixture prerequisite **review**, using this fail-closed boundary as a prerequisite. Do not automatically create fixtures or run the Gate. Prior DNS restart-persistence limitation remains unchanged.

Evidence includes negative tests, live check/sentinel, fake HOME proof, final trusted sentinel, environment-name inventory, post-protection/resource identity and artifact hashes. Stop here.
