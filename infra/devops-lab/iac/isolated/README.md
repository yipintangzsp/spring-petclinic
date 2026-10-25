# Terraform execution sandbox

Status: full Jenkins CI197 SUCCESS plus independent plan/shared/recovery replay accepted. See docs/TERRAFORM-ISOLATION-20261025.md for exact Jobs, evidence, replay entrypoint and remaining security limitations.

Terraform 1.17.0 and Kubernetes provider 2.38.0 execute only in ephemeral native ARM64 Kubernetes Jobs. Jenkins builds, scans and submits a digest-pinned runtime; it does not execute Terraform. Legacy Jenkins/host automation entrypoints reject execution and preserve prior state.

The dedicated namespace has one Pod maximum, 100m/384Mi requests, 1 CPU/512Mi limits, bounded ephemeral storage and no PVCs or service secrets. Runtime identity is a projected 600-second token; orchestration identity cannot read state or exec into Pods. Runtime cannot create workloads. Existing remote state and ConfigMap retain their UIDs and lineage.

Read-only root, UID65532, dropped capabilities, no-new-privileges, AppArmor, runtime seccomp plus an additional socket filter and Landlock ABI>=6 are mandatory. The kernel permits TCP connection only to port6443; NetworkPolicy restricts that port to the numeric API endpoint. UDP/raw/vsock and io_uring are blocked. No DNS or package download is required: the provider is baked into an offline filesystem mirror. No Jenkins directory, host path, Docker socket, administrator token or credential environment is mounted.

Fail-closed admission validates Jobs and Pods, blocks entrypoint/lifecycle and termination-message token escapes, and prevents restoring the old runtime RoleBinding. This isolates execution from the trusted Jenkins deployment controller; it does not claim protection against a cluster administrator changing the policies or a kernel vulnerability.

Run the existing petclinic-ci pipeline. After original release gates, it runs isolated preview, shared-state lock contention/repeat checks, controlled failure and real Job deadline cleanup. Artifacts: target/platform/terraform-runtime.json and terraform-isolated-{plan,shared,recovery}.json. Owned Job/Pod logs are retained privately under Jenkins terraform-runs; artifacts contain sanitized reports and log hashes. Jobs and Pods are removed by UID after each run. State snapshots live in terraform-state/tfstate-latest-success-petclinic-remote-v1, separate from the active state Secret. Failed tests never overwrite the latest successful snapshot.

K3s Secret encryption at rest remains disabled. The demonstration state contains public ConfigMap data; this change does not enable global encryption or rotate unrelated credentials. Historical state files are preserved and must not be migrated or destroyed by this sandbox.

CNI rule programming is asynchronous per Pod. Before reading its projected token or starting Terraform, the fixed worker waits at most15 seconds for verified canary rejection; a reachable canary never authorizes work. Plain TCP refusal is insufficient: active rejects require kernel IP_RECVERR ICMP type3/code3 evidence. The controller confirms its listener before and after. Recovery runs controlled failure, a real successful plan retry, and a60-second Job deadline exercise.

Initial release admission reserves2048MiB above the unchanged runtime disk stop line for build/scan/pull growth. Later promotion gates retain their existing threshold.

Log observation starts while the owned Pod is running. A Job deadline may remove the Pod before the terminal Job read; cached evidence is accepted only for actual Failed/DeadlineExceeded, the same previously observed Pod UID and owner, a verified runtime digest, and the saved hold-ready marker. Unknown exit codes remain null. Ordinary success/failure cannot reuse a disappeared or replaced Pod. Transient log API responses are recorded and retried within the original Job timeout; missing final evidence or authorization failures still fail.
