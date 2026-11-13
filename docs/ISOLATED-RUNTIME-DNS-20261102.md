# security-test DNS diagnosis and minimal recovery — 2026-11-02

**ISOLATED_RUNTIME_DNS = READY**

This result covers the existing dedicated `security-test` runtime only: VM DNS, verified public-registry HTTPS, direct anonymous Docker pull, pulled-image container execution/removal, and unchanged isolation controls. No Kubernetes cluster or SOPS execution was started. Runtime remains running; no service or VM restart was needed.

## Evidence and causal chain

Evidence directory: `evidence/2026-11-02/isolated-runtime-dns/`.

1. Host system DNS resolved `registry-1.docker.io` and `auth.docker.io`; TCP 443 succeeded. System curl, with certificate verification enabled and no proxy, returned registry HTTP 401 and auth-root HTTP 404. Those HTTP responses prove reachability; an anonymous registry challenge is expected. Python's independent trust store reported a missing issuer certificate; it was not changed or bypassed. Initial sandbox-restricted lookup failures are not classified as host DNS failure.
2. Dedicated VM `/etc/resolv.conf` was a symlink to `../run/systemd/resolve/stub-resolv.conf`. The target directory/file and `systemd-resolved` unit were absent. No DNS listener existed. VM `getent` failed. `networkctl` nevertheless showed an operational eth0, gateway and assigned DNS `192.168.5.2`.
3. With only DNS bypassed by curl `--resolve` for the same public registry hostname, VM routing/TLS worked and returned HTTP 401. No hosts file or TLS bypass was used.
4. The Docker daemon's real public pull failed at DNS: `[::1]:53: connection refused`. An already-loaded immutable BusyBox image independently resolved the public registry inside a disposable bridge container using Docker's fallback `8.8.8.8`/`8.8.4.4`. That container was removed.

**Classification: COLIMA_VM_DNS.** The proven immediate cause is the unusable VM resolver file coupled with the missing stub resolver implementation. This explains both VM lookup and daemon registry lookup failures. The historical origin of the missing service/package was not established; no claim is made that a particular image release introduced it. Host DNS, forwarding, container DNS and registry availability were not the failing layers in these observations.

## Supported configuration assessment and single-file fix

Before modifying, installed Colima **0.10.3** help, Lima **2.2.0** template, generated VM network configuration, and Lima's installed DNS bootstrap script were inspected. `--dns` / `network.dns` is supported, but supplies upstream DNS addresses through Lima's networking configuration. The VM already received a DNS address on eth0. An address-only change cannot recreate the missing stub resolver implementation or its target file. The installed `09-host-dns-setup.sh` manages DNS forwarding rules, not `/etc/resolv.conf` reconstruction.

Therefore no profile DNS field, network rule, package, service, proxy or route was changed. The one DNS variable changed was the dedicated guest's resolver file:

| Field | Before | After |
| --- | --- | --- |
| Target | VM `/etc/resolv.conf` | Same path, VM only |
| Type | Dangling symlink | Regular file |
| Owner/mode | root:root / symlink 0777 | root:root / 0644 |
| Resolver | Missing stub target | `nameserver 8.8.8.8` |
| SHA256 of new file | N/A | `a14900c18776adf824748ca5bf4410bdf00eb5e7a6afbb0f2de1639a237c0be6` |

New content:

```text
# security-test isolated runtime DNS recovery; 2026-11-02
nameserver 8.8.8.8
```

The original symlink was copied without dereferencing into guest `/var/tmp/security-test-dns-20261102/resolv.conf.before`, under a root-owned **0700** directory. Its original target and ownership were verified. The modification used an atomic replacement, not a write through the old symlink. The exact before/after/rollback plan was saved **before** applying. Both Colima profiles, generated Lima configurations and guest netplan hash remained unchanged.

## Rollback

Prepared guarded procedure, not executed:

```sh
sh evidence/2026-11-02/isolated-runtime-dns/rollback-resolver.sh
```

It selects only `security-test`, verifies hostname and machine-id, checks the repaired file's exact SHA256 and the saved symlink target, then atomically restores the original symlink. If anything differs, it stops. Restoring this exact pre-change state intentionally restores the known DNS failure. No daemon restart is needed. The symlink backup remains available; no claim of an executed rollback/reboot-persistence test is made.

## Ordered post-fix validation

| Order | Actual observation |
| --- | --- |
| VM DNS | `getent ahostsv4` for registry and auth both exit 0 |
| VM HTTPS | Registry `/v2/`: HTTP **401**, curl exit 0, TLS verify result **0**, no `--resolve` or insecure flag |
| Daemon lookup and pull | Direct `docker pull --platform linux/arm64 docker.io/library/busybox:1.37.0`: exit **0**, **22.049 seconds**; empty client config and sanitized environment; no login, archive or host-copy fallback |
| Pulled image | linux/arm64, local ID/repository digest `sha256:a7dbc319b1438115a207e11930dc4bb3e643dcb3ec0bdd694bb36cd8fad289ec` |
| Container | Created from that exact pulled ID; UID/GID 65534, no mounts, no privileged mode, read-only root, cap-drop ALL, no-new-privileges, pids16, memory32MiB, CPU0.25 |
| Container DNS | Public registry lookup succeeded using `8.8.8.8`; Docker reports resolver inherited from guest `/etc/resolv.conf`, rather than fallback |
| Container execution | `SECURITY_TEST_DNS_SMOKE_OK`, exit **0**, OOMKilled=false |
| Container removal | Normal `docker rm` exit 0, subsequent inspect says no such object; complete container list empty |

Container network was the existing bridge, solely to exercise public DNS; no ports were published and no network was created. Both this smoke and the pre-fix diagnostic container were removed. Zero containers and volumes remain; bridge/host/none network IDs and definitions match baseline. Public images remain cached inside the dedicated VM. The empty temporary Docker client config directory was removed. Text files holding historical container IDs are evidence, not active resources.

Post-verification script corrections were confined to this new evidence directory: compare unordered Docker lists by name; accept the installed generated Lima YAML's omitted empty `mounts` field and verify its unchanged hash plus actual `findmnt`. Earlier assertion failures were not runtime changes; final normalized verification passed.

## Protection, isolation and scope

| Protected item | Result |
| --- | --- |
| security-test profile | SHA256 unchanged `bf06fbc527e4b7dd50324d060a58c5f29485ddd2c8f918f22f8885aba14b1b25` |
| default profile | SHA256 unchanged `6d22b3bab6a1ab61101506683956b523cc323b9b37aa0cb4bd6d981b9f76ca8a`; not restarted |
| Both generated Lima configurations | SHA256 unchanged |
| User SSH config, kubeconfig, Docker config, host resolver file | All SHA256 unchanged; credential contents were not parsed or displayed |
| Global Docker context | `default`; all context definitions unchanged |
| Existing project files | **3278/3278** hashes unchanged, including previous Gate/code/docs/evidence |
| Host HOME / production mounts | Absent in actual VM mounts; known production credential paths absent |
| Kubernetes / sshConfig / autoActivate | All remain disabled |
| SSH key/agent forwarding | User keys not loaded, agent not forwarded; socket absent |
| Container credentials | Env only PATH; no host credentials/mounts |
| Endpoint / daemon | Exact dedicated Unix socket, owner current user/mode0600; daemon name and stable ID unchanged |
| Production API / Kubernetes API calls | **0 / 0** |
| Production credential/Secret/private-age value reads | **0**; requested host config hashes only |
| SOPS/age / fixture / Gate / Summary / rollout changes | **0** |

Guest login environment still exposes proxy variable **names** inherited from the existing runtime, as before; values were neither inspected nor changed. Dockerd has no proxy variable names, and the smoke env is only PATH. No claim of total network air-gap or universal credential absence beyond inspected paths/env names is made.

Actual mutations: guest `/etc/resolv.conf`; its root-only rollback directory/symlink; normal public image-cache/runtime operational state; this new evidence directory and this new document. No production/global configuration, default profile, host DNS, router, VPN/proxy, hosts file or existing project file was modified. Public response cookies were omitted from saved HTTP evidence.

## Final decision and stop

**ISOLATED_RUNTIME_DNS = READY**. No blocker remains for this iteration's specified DNS/pull/container/isolation criteria. This does not claim reboot/recreation persistence or a permanent fix for the unknown historical resolver loss.

The next eligible task is a **separately scoped disposable Kubernetes/tool-environment design and prerequisite review**. It was not started and this result does not authorize automatic cluster creation, SOPS fixture execution, Secret access, Policy/Summary integration or rollout. Stop here with `security-test` running.
