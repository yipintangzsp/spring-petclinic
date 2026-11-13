| Property | Classification | Requirement |
|---|---|---|
| architecture/tool | MUST_MATCH_PRODUCTION | Linux arm64; exact c7586c image and d860 binary; UID/GID10000; same Node runtime version for frozen JS, record version before execution |
| filesystem type / features | MUST_MATCH_PRODUCTION | ext4 on lab Linux block device; record kernel, feature flags, journal/reserved-block ratio/delalloc and mount options; production cache mount is ext4 /dev/vda2 |
| block and inode accounting | MUST_MATCH_PRODUCTION | 4096-byte fundamental block observed; compare statvfs f_bavail/f_bfree, inode counts, ext4 reserved blocks. PVC nominal5Gi is NOT an enforced quota here |
| cache/temp placement | MUST_MATCH_PRODUCTION | PVC-style bind at /home/scanner/.cache; /tmp on container overlay; same underlying ext4 device as cache; controller os.tmpdir manifests on controller filesystem tracked separately |
| rename / copy boundary | MUST_MATCH_PRODUCTION | Preserve production device relationships; never move temp to tmpfs or different disk. Do not implement a replacement rename or wrapper backup |
| overlay container layer | MUST_MATCH_PRODUCTION | Same containerd snapshotter overlayfs and image lower layers; fresh writable upperdir per case, same backing ext4. Collect upperdir, workdir and deleted-open-file accounting |
| guest filesystem capacity | MUST_MATCH_PRODUCTION | For guard classification compare same measured capacityBytes270430261248 and reserve ratio; differing capacity only supplementary sensitivity run |
| sparse / host COW | MUST_MATCH_PRODUCTION | For end-to-end backing-space safety use dedicated qcow2 on APFS with adequate physical space and matched COW policy. ext4-only lab proves guest peak only; cannot validate production host/backup safety |
| hypervisor/host version | SHOULD_MATCH | Match existing UTM/QEMU/APFS where possible; record differences; no claim of backing-store equivalence if not matched |
| DNS / proxy / throughput | SHOULD_MATCH | Independent egress, same official source and digest; record latency/retries; production mutable proxy excluded |
| business namespace labels / production registry tags | NOT_RELEVANT | No PetClinic or production registry needed; isolated kube API can use same harbor/data-infra/devops names solely because frozen IO hardcodes them |
