# Disposable kind cluster identity proof — 2026-11-02

**ISOLATED_KIND_CLUSTER = READY**

Scope: one new standard single-control-plane kind cluster on the already verified `security-test` Docker daemon, isolated kubeconfig, identity proof, and one disposable namespace smoke. No SOPS/age, application deployment, Gate/Summary integration, production Kubernetes request or production credential access occurred. The cluster remains running; the smoke namespace was removed.

## 1–4. Versions, official image and architecture

| Item | Actual result |
| --- | --- |
| kind | v0.31.0, go1.25.5, darwin/arm64 |
| kubectl client | v1.35.0, darwin/arm64 |
| Selected official node image | `docker.io/kindest/node:v1.35.0@sha256:452d707d4862f52530247495d180205e029056831160e22870e37e3f6c1ac31f` |
| Index SHA256 | Independently computed from raw manifest; exact match to pinned official digest |
| Actual platforms | linux/amd64 and linux/arm64 |
| Selected arm64 platform manifest | `sha256:0aa5e1a411b2c3197184286d7699424a123cd4d18c04c24317173dc5256c6110` |
| Daemon image pull | Anonymous, linux/arm64, exit 0; 54.589 seconds; no archive fallback |
| Local image inspection | arm64 / linux, pinned index image ID |

Sources: [kind v0.31.0 official release](https://github.com/kubernetes-sigs/kind/releases/tag/v0.31.0), [official kind configuration](https://kind.sigs.k8s.io/docs/user/configuration/).

Docker CLI `manifest inspect` reported a verification error. The installed skopeo initially rejected combined tag+digest syntax; retry used the exact same digest-only reference, with no change in image content. Its raw manifest bytes matched the official SHA256, included arm64, and the Docker daemon subsequently pulled the pinned image successfully. No TLS/digest verification was disabled. These precheck observations are retained, not reported as successful commands.

## 5–14. Runtime, cluster, endpoint and UID evidence

| Item | Actual result |
| --- | --- |
| Docker endpoint | `unix:///Users/zhangsir/.colima/security-test/docker.sock` |
| Docker server | security-test / stable ID `f0a9c4bb-ef14-4087-b0b1-7d5f02aa1ff8` |
| VM | colima-security-test / aarch64 / machine-id `a093ffaa4d594b5298d97235be9e69ae` |
| Cluster name | security-test-sops |
| Node container | security-test-sops-control-plane |
| Container ID | `9813796eee581bf765b2cd0fb93c26c632b4cb47a075b6c99a29e77597b19697` |
| API / kubeconfig server | `https://127.0.0.1:59645` |
| Dedicated kubeconfig | `/private/tmp/security-manager-kind-gdasvx1h/kubeconfig` |
| Kubeconfig / enclosing directory mode | 0600 / 0700 |
| Context inside dedicated file | kind-security-test-sops, sole context |
| CA certificate SHA256 fingerprint, DER | `90507a6f34d0b4e9b31cf862d74b7c2694b465c2e959f99bb45705ef0c8a46d8` |
| kube-system namespace UID | `54f300a4-5f1b-4e1e-86a1-d173e5a402d8` |
| default namespace UID | `95e89e62-5d99-4dab-be07-b8e86856f05d` |
| Node UID | `115f6029-63a1-4303-afb9-31afb3174705` |
| Kubernetes | v1.35.0, node Ready |
| Node architecture / runtime | arm64 / containerd://2.2.0 |
| Creation | exit 0, 32.455 seconds; kind reported Ready after 18 seconds in readiness phase |

All child operations received explicit DOCKER_HOST, DOCKER_CONFIG, HOME, KIND_EXPERIMENTAL_PROVIDER=docker and KUBECONFIG pointing only to private test paths. `kind create --kubeconfig` selected the dedicated output file; no user kubeconfig merge or global context switch occurred. The kind log's “Set kubectl context” refers to that dedicated file only.

Before explicit Kubernetes queries: daemon ID was revalidated; the exact owned Docker container was inspected; its `6443/tcp` binding was confirmed as `127.0.0.1:59645`; kubeconfig server matched; the public CA fingerprint extracted from the dedicated config matched the certificate inside that exact node container. A TLS connection to the new endpoint verified against this own CA. Only after that chain passed were nodes/namespaces/cluster-info/server version queried through the explicit dedicated kubeconfig/context.

`cluster-observations.json` preserves actual cluster-info and node/namespace/version responses. Test client keys/certificates and the whole raw kubeconfig were not copied into repository evidence. Only its path, mode and hash were retained. Public CA/leaf fingerprints are identity evidence, not Secret values.

## 15. Comparison against known production identity

Comparison used **existing historical evidence only**, primarily `evidence/2026-11-02/sops-isolation-design/identity-assessment.json` and `context-metadata.json`. No production API was contacted or refreshed.

| Dimension | Known production/history | New isolated cluster |
| --- | --- | --- |
| Endpoint | orbstack tunnel `https://127.0.0.1:26443` | `https://127.0.0.1:59645`, mapped to owned local container |
| kube-system UID | `639e5426-bc1f-4d37-a844-6a31b7685744` | `54f300a4-5f1b-4e1e-86a1-d173e5a402d8`, different |
| Nodes | devops / aliyun-worker / ucloud-worker | security-test-sops-control-plane, different |
| Config cluster identity | orbstack alias | kind-security-test-sops, different |
| Kubeconfig | user `~/.kube/config` | private dedicated temporary path, different |
| CA | No fingerprint available in existing archived metadata | New CA bound to exact owned container and TLS endpoint |

Production CA comparison is **NOT_COMPARABLE**, not falsely reported as different. No production certificate or credential was extracted to fill that optional comparison. Historical archive also has no production default-namespace UID; no direct comparison is claimed for it. The required namespace identity comparison is established by kube-system UID. Old `orbstack`, devops/aliyun/ucloud and old kind contexts were never used for API access. User kubeconfig was used only for requested precheck context names and hash protection, not as a client connection configuration.

## 16. Mount, credential and access boundary

- Host HOME/production directories remain absent from VM mounts; Colima profile has mounts=null, Kubernetes=false, sshConfig=false, autoActivate=false and forwardAgent=false. Generated Lima configuration still omits its empty mounts field and disables user key loading/agent forwarding.
- Node uses standard kind privileged behavior, **no additional privileges** and no host networking. Docker network is its new dedicated kind bridge. No extra mount or port mapping was configured.
- The only node bind is **VM-local `/lib/modules` read-only**, standard for kind; `/var` is its newly created VM-local anonymous Docker volume. Neither source is a macOS/production directory. No host kubeconfig or Docker socket is mounted into the node.
- Known AWS/SOPS/age/SSH/Docker credential paths in VM and node were checked for existence only and were absent; no credential contents were inspected. Sensitive host environment variable names were not inherited.
- Node HTTP_PROXY/HTTPS_PROXY/NO_PROXY names appear as unset/name-only entries. Boolean presence checks confirmed no nonempty value. The first helper assumed every env entry had `=` and failed; it was corrected for Docker's legitimate name-only entries without changing any node environment.
- Node KUBECONFIG is its standard self-generated `/etc/kubernetes/admin.conf`; these are **test cluster credentials**, not host/production credentials. Private test kubeconfig is necessarily used by kind/kubectl and remains mode0600; it is not published.
- This proves configuration/access isolation for the inspected execution. It does not claim an outbound network air gap. No production network probe was performed.

## 17–18. Namespace smoke and cleanup

Only the positively identified test kubeconfig/context was used:

1. `get nodes`, `get namespaces`, `cluster-info`, client/server version.
2. Create namespace `security-smoke`.
3. Read its name/UID metadata.
4. Normal namespace deletion with wait.
5. Get namespace list again: `security-smoke` absent.

Result: **PASS**. No application workload or SOPS/age/Secret/SA/RBAC/Lease **fixture** was manually created. Standard kind/kubeadm/controllers necessarily bootstrap their own system RBAC, ServiceAccounts, node Leases and system workloads; those are part of the authorized standard Kubernetes creation, not additional test fixtures. Their creation is not misreported as globally zero.

Retained deliberately: one owned control-plane container, its one `/var` volume, one kind bridge network, public image cache and private kubeconfig/workspace. No unrelated containers, volumes or networks were created. These exact IDs are in `owned-resources.json`. The cluster was not deleted, because this iteration requested creation/identity proof. A guarded future deletion script `delete-owned-cluster.py` verifies the exact daemon/container/kubeconfig identity before using `kind delete cluster` with the dedicated file; **not executed**. Final private workspace/network teardown must be checked against owned IDs after that future explicit deletion.

VM after creation: memory.available **1,277,628,416 bytes**, data-disk available **7,468,560,384 bytes**. No VM resource budget was increased.

## 19–23. Protection and actual changes

| Item | Result |
| --- | --- |
| User kubeconfig | Hash unchanged YES |
| User SSH config | Hash unchanged YES |
| default Colima profile/generated Lima config | Hash unchanged YES; no restart |
| security-test profile/generated Lima config | Hash unchanged YES; no VM restart |
| Global Docker context | default, unchanged YES |
| Host Docker config / resolver file | Hash unchanged YES |
| Existing production/project/evidence files | **3792/3792** hashes unchanged |
| Existing VM DNS repair | Same resolver hash; still working, no restart persistence claim |
| Production Kubernetes API requests | **0** |
| Production Secret/credential/private-key value reads | **0** |
| Manual SOPS/age/Secret/SA/RBAC/Lease fixtures | **0** |
| Gate / actual Summary / release / rollout changes | **0** |

Actual created resources/files: owned kind node/container data volume/network; official public node image cache; new private temporary kubeconfig and client workspace; ordinary dedicated VM/runtime operational state/logs/port forwarding; this new evidence directory and document. No existing repository file was modified. Production kubeconfig/context, host/global DNS and production platform configuration were not changed.

## 24–26. Decision, limits and next action

**ISOLATED_KIND_CLUSTER = READY**. No blocker remains for the requested cluster-creation/identity/smoke criteria. Production CA comparison remains unavailable, explicitly documented under the “where comparable” requirement; independent owned-container CA/TLS, endpoint and historical kube-system UID proofs passed.

Next eligible action: separately scope review of the isolated executor/locked toolchain and complete fixture prerequisites. This result does **not** start or authorize automatic SOPS/age execution, Secret/SA/RBAC/Lease fixtures, Summary integration or rollout. Runtime and cluster remain running. Stop here.

Evidence: `evidence/2026-11-02/isolated-kind-cluster/`, including pre/post protection, public manifest and pull, exact invocation, creation log, container/mount/environment proof, CA/endpoint/UID chain, production comparison, namespace smoke and owned-resource attribution.
