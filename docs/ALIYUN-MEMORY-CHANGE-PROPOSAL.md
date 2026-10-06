# Proposed aliyun worker memory protection — not applied

The worker recovered by the next session. Its current kubelet config has neither `systemReserved` nor `kubeReserved`. `evictionHard` contains only imagefs/nodefs thresholds; the memory threshold is missing and default merging is false. The scheduler therefore sees essentially the whole 1608.9MiB as allocatable, although the no-PetClinic baseline uses about 822MiB. Old/new JVM overlap was followed by about 67% full memory stall, 92% iowait, failed probes and kubelet heartbeat loss. OOM-kill counters stayed zero. Kernel cause and exact stalled processes still need corroboration; these metrics prove resource contention, not an OOM kill.

A zero-surge PetClinic rollout has already been committed. It does not solve inaccurate node allocatable memory before HPA. The proposed drop-in is [aliyun-memory-budget.yaml](../infra/observability/proposed/aliyun-memory-budget.yaml), **not installed**.

Proposed narrow change: reserve 768Mi for the OS/system and restore a 150Mi hard memory eviction threshold on aliyun only. Keep existing disk thresholds. Expected allocatable memory is about 691Mi; PetClinic 512Mi plus existing Alloy 50Mi requests fits once, whereas a second PetClinic cannot fit. This is an admission budget, not an application memory cap or proof of N-1 capacity. Recompute from live configz and Node status before further decisions.

Execution after explicit approval: inventory current Pods; cordon aliyun; server-side dry-run and normally evict only the single PetClinic Pod under PDB if present; verify its replacement Ready and no PetClinic/local application data there; read relevant config argument names without credential values; back up any existing drop-in privately; install only this drop-in; restart only k3s-agent; wait for Ready, compare configz/allocatable and collector health; uncordon. Existing credentials, WireGuard, CNI, disks, PVCs, databases and other node configs are outside this change.

SSH credentials currently cannot authenticate. An alternative requires a short-lived privileged operations Pod using the existing cached amd64 PetClinic image, host PID namespace and a read-only host filesystem mount for diagnosis; any approved host write would be limited by command to the named drop-in and agent restart. This has host-level privileges and is part of the requested approval, not a routine application Pod. Remove it after verification.

Risk: agent restart temporarily interrupts heartbeat and may delay logs from four existing DaemonSets. Restoring memory eviction permits genuine memory-pressure Pod eviction, which can also affect those collectors. No such change will be applied without approval because the user explicitly prohibited unapproved global settings affecting other workloads.

Rollback: remove only the new drop-in (or restore its private prior copy), restart only k3s-agent, verify original configz and allocatable, uncordon. Do not use `k3s-killall.sh`, reboot the physical machine, clear data directories or delete PV/PVC.

Sources: [K3s configuration merging](https://docs.k3s.io/installation/configuration), [Kubernetes node reservation](https://kubernetes.io/docs/tasks/administer-cluster/reserve-compute-resources/), [memory eviction defaults](https://kubernetes.io/docs/concepts/scheduling-eviction/node-pressure-eviction/).
