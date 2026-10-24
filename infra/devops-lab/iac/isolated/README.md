# Terraform execution sandbox

Status: implementation under acceptance; CI191 failed. See docs/TERRAFORM-ISOLATION-20261025.md before treating any contract below as verified. Full isolated plan/shared-state/failure acceptance remains pending.

Terraform 1.17.0 and Kubernetes provider 2.38.0 execute only in ephemeral native ARM64 Kubernetes Jobs. Jenkins builds, scans and submits a digest-pinned runtime; it does not execute Terraform. Legacy Jenkins/host automation entrypoints reject execution and preserve prior state.

The dedicated namespace has one Pod maximum, 100m/384Mi requests, 1 CPU/512Mi limits, bounded ephemeral storage and no PVCs or service secrets. Runtime identity is a projected 600-second token; orchestration identity cannot read state or exec into Pods. Runtime cannot create workloads. Existing remote state and ConfigMap retain their UIDs and lineage.

Read-only root, UID65532, dropped capabilities, no-new-privileges, AppArmor, runtime seccomp plus an additional socket filter and Landlock ABI>=6 are mandatory. The kernel permits TCP connection only to port6443; NetworkPolicy restricts that port to the numeric API endpoint. UDP/raw/vsock and io_uring are blocked. No DNS or package download is required: the provider is baked into an offline filesystem mirror. No Jenkins directory, host path, Docker socket, administrator token or credential environment is mounted.

Fail-closed admission validates Jobs and Pods, blocks entrypoint/lifecycle and termination-message token escapes, and prevents restoring the old runtime RoleBinding. This isolates execution from the trusted Jenkins deployment controller; it does not claim protection against a cluster administrator changing the policies or a kernel vulnerability.

Run the existing petclinic-ci pipeline. After original release gates, it runs isolated preview, shared-state lock contention/repeat checks, controlled failure and real Job deadline cleanup. Artifacts: target/platform/terraform-runtime.json and terraform-isolated-{plan,shared,recovery}.json. Owned Job/Pod logs are retained privately under Jenkins terraform-runs; artifacts contain sanitized reports and log hashes. Jobs and Pods are removed by UID after each run. State snapshots live in terraform-state/tfstate-latest-success-petclinic-remote-v1, separate from the active state Secret. Failed tests never overwrite the latest successful snapshot.

K3s Secret encryption at rest remains disabled. The demonstration state contains public ConfigMap data; this change does not enable global encryption or rotate unrelated credentials. Historical state files are preserved and must not be migrated or destroyed by this sandbox.
