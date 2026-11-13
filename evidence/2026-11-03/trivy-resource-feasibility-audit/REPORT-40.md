# Trivy Guard 现有资源一次性可行性审计

**NOT_AVAILABLE / RESOURCE_BLOCKED。7 个真实候选均 INELIGIBLE；无选中候选。本次审计 CLOSED，只有实质资源变化才允许重开。**

设计仍为 READY；生产代理不是实验依赖。原有代理债务直接沿用，不重新调查。未运行 Trivy 实验、未刷新 DB、未创建/扩容/清理任何资源。

| Candidate | Production class | Free GiB | Disk | FS | Topology | Measurement | Network | Credentials | Isolation | Failure safety | Repeatability | Overall |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| mac-host | PRODUCTION_CRITICAL | 22.76 | FAIL | FAIL | FAIL | UNKNOWN | UNKNOWN | UNKNOWN | FAIL | FAIL | FAIL | INELIGIBLE |
| node-aliyun-worker | PRODUCTION_SHARED | 9.41 | FAIL | FAIL | UNKNOWN | UNKNOWN | UNKNOWN | UNKNOWN | FAIL | FAIL | FAIL | INELIGIBLE |
| utm-devops | PRODUCTION_CRITICAL | 42.23 | FAIL | FAIL | PASS | UNKNOWN | UNKNOWN | UNKNOWN | FAIL | FAIL | FAIL | INELIGIBLE |
| node-ucloud-worker | PRODUCTION_SHARED | 52.91 | FAIL | FAIL | UNKNOWN | UNKNOWN | UNKNOWN | UNKNOWN | FAIL | FAIL | FAIL | INELIGIBLE |
| colima-security-test | VALIDATION_SAFE | 6.89 | FAIL | FAIL | FAIL | UNKNOWN | UNKNOWN | UNKNOWN | FAIL | FAIL | FAIL | INELIGIBLE |
| kind-security-test-sops | VALIDATION_SAFE | 6.89 | FAIL | FAIL | FAIL | UNKNOWN | UNKNOWN | UNKNOWN | FAIL | FAIL | FAIL | INELIGIBLE |
| colima-default | UNKNOWN | UNKNOWN | FAIL | FAIL | UNKNOWN | UNKNOWN | UNKNOWN | UNKNOWN | FAIL | FAIL | FAIL | INELIGIBLE |

Colima guest OS root 可用约17.16GiB，Docker 数据盘可用约6.89GiB；二者不能合并为同一个生产等价 filesystem。各候选还共享 Mac 物理 backing，不能相加为独立空间。UTM 与 devops 是同一候选。

1. **sealed experiment requirement source**

   {
     "path": "evidence/2026-11-03/trivy-guard-experiment-design/experiment-plan.json",
     "sha256": "c6641e3518ef4aa0c99fd70d196ff272fe4405d8560ed99473ecdb9271e4ef6e"
   }

   Evidence: `EXPERIMENT_RESOURCE_REQUIREMENTS.json`

2. **experiment resource requirements**

   {
     "primaryGuestFilesystemCapacityBytes": 270430261248,
     "independentPhysicalAvailableBytes": 322122547200,
     "observerBytes": 8589934592,
     "initialFreeBands": {
       "belowGuard1GiB": 52375699252,
       "belowGuard4KiB": 53449436980,
       "nearAbove4KiB": 53449445172,
       "aboveGuard8GiB": 62039375668
     },
     "frozenGuardBytesCeil": 53449441076,
     "allMUST_MATCH": [
       {
         "property": "architecture/tool",
         "classification": "MUST_MATCH_PRODUCTION",
         "requirement": "Linux arm64; exact c7586c image and d860 binary; UID/GID10000; same Node runtime version for frozen JS, record version before execution"
       },
       {
         "property": "filesystem type / features",
         "classification": "MUST_MATCH_PRODUCTION",
         "requirement": "ext4 on lab Linux block device; record kernel, feature flags, journal/reserved-block ratio/delalloc and mount options; production cache mount is ext4 /dev/vda2"
       },
       {
         "property": "block and inode accounting",
         "classification": "MUST_MATCH_PRODUCTION",
         "requirement": "4096-byte fundamental block observed; compare statvfs f_bavail/f_bfree, inode counts, ext4 reserved blocks. PVC nominal5Gi is NOT an enforced quota here"
       },
       {
         "property": "cache/temp placement",
         "classification": "MUST_MATCH_PRODUCTION",
         "requirement": "PVC-style bind at /home/scanner/.cache; /tmp on container overlay; same underlying ext4 device as cache; controller os.tmpdir manifests on controller filesystem tracked separately"
       },
       {
         "property": "rename / copy boundary",
         "classification": "MUST_MATCH_PRODUCTION",
         "requirement": "Preserve production device relationships; never move temp to tmpfs or different disk. Do not implement a replacement rename or wrapper backup"
       },
       {
         "property": "overlay container layer",
         "classification": "MUST_MATCH_PRODUCTION",
         "requirement": "Same containerd snapshotter overlayfs and image lower layers; fresh writable upperdir per case, same backing ext4. Collect upperdir, workdir and deleted-open-file accounting"
       },
       {
         "property": "guest filesystem capacity",
         "classification": "MUST_MATCH_PRODUCTION",
         "requirement": "For guard classification compare same measured capacityBytes270430261248 and reserve ratio; differing capacity only supplementary sensitivity run"
       },
       {
         "property": "sparse / host COW",
         "classification": "MUST_MATCH_PRODUCTION",
         "requirement": "For end-to-end backing-space safety use dedicated qcow2 on APFS with adequate physical space and matched COW policy. ext4-only lab proves guest peak only; cannot validate production host/backup safety"
       },
       {
         "property": "hypervisor/host version",
         "classification": "SHOULD_MATCH",
         "requirement": "Match existing UTM/QEMU/APFS where possible; record differences; no claim of backing-store equivalence if not matched"
       },
       {
         "property": "DNS / proxy / throughput",
         "classification": "SHOULD_MATCH",
         "requirement": "Independent egress, same official source and digest; record latency/retries; production mutable proxy excluded"
       },
       {
         "property": "business namespace labels / production registry tags",
         "classification": "NOT_RELEVANT",
         "requirement": "No PetClinic or production registry needed; isolated kube API can use same harbor/data-infra/devops names solely because frozen IO hardcodes them"
       }
     ],
     "sourceNoRelaxation": true
   }

   Evidence: `EXPERIMENT_RESOURCE_REQUIREMENTS.json`

3. **candidate inventory**

   {
     "actualCandidates": [
       "mac-host",
       "node-aliyun-worker",
       "utm-devops",
       "node-ucloud-worker",
       "colima-security-test",
       "kind-security-test-sops",
       "colima-default"
     ],
     "aliases": [
       {
         "alias": "devops Ubuntu host / current UTM devops.utm",
         "candidateId": "utm-devops",
         "reason": "Same node/PVC/physical backing, not two independent hosts"
       },
       {
         "alias": "/Volumes/Macintosh HD and /Volumes/Recovery",
         "candidateId": "mac-host",
         "reason": "Same internal APFS physical container; df rows not additive; no external device discovered"
       },
       {
         "alias": "Docker default and desktop-linux contexts",
         "candidateId": null,
         "reason": "Socket paths absent; configuration entries are not accessible running engines"
       },
       {
         "alias": "security-test Docker engine",
         "candidateId": "colima-security-test",
         "reason": "Same10GiB data disk; no duplicate capacity"
       }
     ],
     "limitations": [
       "No provider-management API identity used; provisioning size/unused attached disks on cloud hosts UNKNOWN. Existing SSH read unavailable. Production role+amd64+root space already decisively reject these hosts.",
       "No claim about every resource in all cloud accounts. No undiscovered or inaccessible hypothetical candidate is treated as available.",
       "No restart, mount, attach, clone, resize, delete, workload move or Trivy download performed."
     ]
   }

   Evidence: `candidate-inventory.json`, `local-candidate-inventory.json`, `node-candidate-inventory.json`

4. **Mac evaluation**

   {
     "candidateId": "mac-host",
     "classification": "PRODUCTION_CRITICAL",
     "availableBytes": 24440545280,
     "capacityChecks": [
       {
         "scope": "independent physical backing available",
         "requiredBytes": 322122547200,
         "availableBytes": 24440545280,
         "headroomBytes": -297682001920,
         "totalBytes": 494384795648,
         "usedBytes": 469944250368,
         "status": "FAIL",
         "evidence": "local-candidate-inventory.json"
       }
     ],
     "overall": "INELIGIBLE",
     "reasons": [
       "Actual available backing below sealed300GiB floor",
       "macOS/APFS native environment is not frozen Linux arm64/ext4/overlay topology",
       "Low-space/failure test threatens production VM backing"
     ],
     "note": null
   }

5. **production UTM evaluation**

   {
     "candidateId": "utm-devops",
     "classification": "PRODUCTION_CRITICAL",
     "availableBytes": 45347446784,
     "capacityChecks": [
       {
         "scope": "guest initial available >= frozen guard +8GiB band",
         "requiredBytes": 62039375668,
         "availableBytes": 45347446784,
         "headroomBytes": -16691928884,
         "totalBytes": 270430261248,
         "usedBytes": 211898433536,
         "status": "FAIL",
         "evidence": "node-candidate-inventory.json"
       },
       {
         "scope": "independent physical backing available",
         "requiredBytes": 322122547200,
         "availableBytes": 24440545280,
         "headroomBytes": -297682001920,
         "totalBytes": 494384795648,
         "usedBytes": 469944250368,
         "status": "FAIL",
         "evidence": "local-candidate-inventory.json"
       }
     ],
     "overall": "INELIGIBLE",
     "reasons": [
       "Production node and runtime share filesystem; interrupted/extraction/low-space tests can cause DiskPressure, eviction or runtime instability",
       "Guest initial free headroom below sealed above-guard+8GiB full-matrix band",
       "Existing sealed production VM exclusion: no safe backing/validated backup; no cleanup or expansion reopened"
     ],
     "note": "UTM/devops are the same production resource, not duplicate capacity"
   }

6. **devops host evaluation**

   {
     "candidateId": "utm-devops",
     "classification": "PRODUCTION_CRITICAL",
     "availableBytes": 45347446784,
     "capacityChecks": [
       {
         "scope": "guest initial available >= frozen guard +8GiB band",
         "requiredBytes": 62039375668,
         "availableBytes": 45347446784,
         "headroomBytes": -16691928884,
         "totalBytes": 270430261248,
         "usedBytes": 211898433536,
         "status": "FAIL",
         "evidence": "node-candidate-inventory.json"
       },
       {
         "scope": "independent physical backing available",
         "requiredBytes": 322122547200,
         "availableBytes": 24440545280,
         "headroomBytes": -297682001920,
         "totalBytes": 494384795648,
         "usedBytes": 469944250368,
         "status": "FAIL",
         "evidence": "local-candidate-inventory.json"
       }
     ],
     "overall": "INELIGIBLE",
     "reasons": [
       "Production node and runtime share filesystem; interrupted/extraction/low-space tests can cause DiskPressure, eviction or runtime instability",
       "Guest initial free headroom below sealed above-guard+8GiB full-matrix band",
       "Existing sealed production VM exclusion: no safe backing/validated backup; no cleanup or expansion reopened"
     ],
     "note": "UTM/devops are the same production resource, not duplicate capacity"
   }

7. **aliyun evaluation**

   {
     "candidateId": "node-aliyun-worker",
     "classification": "PRODUCTION_SHARED",
     "availableBytes": 10100510720,
     "capacityChecks": [
       {
         "scope": "guest initial available >= frozen guard +8GiB band",
         "requiredBytes": 62039375668,
         "availableBytes": 10100510720,
         "headroomBytes": -51938864948,
         "totalBytes": 41882943488,
         "usedBytes": 29846695936,
         "status": "FAIL",
         "evidence": "node-candidate-inventory.json"
       }
     ],
     "overall": "INELIGIBLE",
     "reasons": [
       "Production node and runtime share filesystem; interrupted/extraction/low-space tests can cause DiskPressure, eviction or runtime instability",
       "Guest initial free headroom below sealed above-guard+8GiB full-matrix band",
       "amd64 cannot match frozen Linux arm64 exact image/binary requirement",
       "No equivalent guest filesystem capacity; provider attached-disk inventory UNKNOWN because existing trusted host read unavailable, no privilege escalation/bypass"
     ],
     "note": null
   }

8. **ucloud evaluation**

   {
     "candidateId": "node-ucloud-worker",
     "classification": "PRODUCTION_SHARED",
     "availableBytes": 56811704320,
     "capacityChecks": [
       {
         "scope": "guest initial available >= frozen guard +8GiB band",
         "requiredBytes": 62039375668,
         "availableBytes": 56811704320,
         "headroomBytes": -5227671348,
         "totalBytes": 83053432832,
         "usedBytes": 26224951296,
         "status": "FAIL",
         "evidence": "node-candidate-inventory.json"
       }
     ],
     "overall": "INELIGIBLE",
     "reasons": [
       "Production node and runtime share filesystem; interrupted/extraction/low-space tests can cause DiskPressure, eviction or runtime instability",
       "Guest initial free headroom below sealed above-guard+8GiB full-matrix band",
       "amd64 cannot match frozen Linux arm64 exact image/binary requirement",
       "No equivalent guest filesystem capacity; provider attached-disk inventory UNKNOWN because existing trusted host read unavailable, no privilege escalation/bypass"
     ],
     "note": null
   }

9. **any other real candidate**

   [
     {
       "id": "colima-security-test",
       "actualAvailableBytes": 7400390656,
       "classification": "VALIDATION_SAFE",
       "reasons": [
         "Data available~6.89GiB, primary270430261248B FS not present",
         "OS /tmp lives on vda, Docker data on vdb: required same-backing topology not met",
         "Production host APFS backing is shared and cannot tolerate low-space/COW failure tests"
       ]
     },
     {
       "id": "kind-security-test-sops",
       "actualAvailableBytes": 7400386560,
       "classification": "VALIDATION_SAFE",
       "reasons": [
         "kind /tmp is1GiB tmpfs, explicit MUST_MATCH storage mismatch",
         "All allocations share small Colima data disk and production Mac backing",
         "Cannot safely reproduce full disk-failure/low-space matrix; existing cluster not disposable by this authorization"
       ]
     },
     {
       "id": "colima-default",
       "actualAvailableBytes": null,
       "classification": "UNKNOWN",
       "reasons": [
         "Stopped VM not started; no attested mount/topology/workload isolation",
         "Configured virtual data disk100GiB is not measured usable/free capacity and not primary251.865GiB FS",
         "Actual shared host backing fails300GiB requirement"
       ]
     }
   ]

   Evidence: `validation-existing-detail.json`

10. **disk matrix**

   [
     {
       "candidate": "mac-host",
       "Disk": "FAIL",
       "checks": [
         {
           "scope": "independent physical backing available",
           "requiredBytes": 322122547200,
           "availableBytes": 24440545280,
           "headroomBytes": -297682001920,
           "totalBytes": 494384795648,
           "usedBytes": 469944250368,
           "status": "FAIL",
           "evidence": "local-candidate-inventory.json"
         }
       ]
     },
     {
       "candidate": "node-aliyun-worker",
       "Disk": "FAIL",
       "checks": [
         {
           "scope": "guest initial available >= frozen guard +8GiB band",
           "requiredBytes": 62039375668,
           "availableBytes": 10100510720,
           "headroomBytes": -51938864948,
           "totalBytes": 41882943488,
           "usedBytes": 29846695936,
           "status": "FAIL",
           "evidence": "node-candidate-inventory.json"
         }
       ]
     },
     {
       "candidate": "utm-devops",
       "Disk": "FAIL",
       "checks": [
         {
           "scope": "guest initial available >= frozen guard +8GiB band",
           "requiredBytes": 62039375668,
           "availableBytes": 45347446784,
           "headroomBytes": -16691928884,
           "totalBytes": 270430261248,
           "usedBytes": 211898433536,
           "status": "FAIL",
           "evidence": "node-candidate-inventory.json"
         },
         {
           "scope": "independent physical backing available",
           "requiredBytes": 322122547200,
           "availableBytes": 24440545280,
           "headroomBytes": -297682001920,
           "totalBytes": 494384795648,
           "usedBytes": 469944250368,
           "status": "FAIL",
           "evidence": "local-candidate-inventory.json"
         }
       ]
     },
     {
       "candidate": "node-ucloud-worker",
       "Disk": "FAIL",
       "checks": [
         {
           "scope": "guest initial available >= frozen guard +8GiB band",
           "requiredBytes": 62039375668,
           "availableBytes": 56811704320,
           "headroomBytes": -5227671348,
           "totalBytes": 83053432832,
           "usedBytes": 26224951296,
           "status": "FAIL",
           "evidence": "node-candidate-inventory.json"
         }
       ]
     },
     {
       "candidate": "colima-security-test",
       "Disk": "FAIL",
       "checks": [
         {
           "scope": "guest data available",
           "requiredBytes": 62039375668,
           "availableBytes": 7400390656,
           "headroomBytes": -54638985012,
           "totalBytes": 10461925376,
           "usedBytes": 2507993088,
           "status": "FAIL",
           "evidence": null
         },
         {
           "scope": "independent physical backing available",
           "requiredBytes": 322122547200,
           "availableBytes": 24440545280,
           "headroomBytes": -297682001920,
           "totalBytes": 494384795648,
           "usedBytes": 469944250368,
           "status": "FAIL",
           "evidence": "local-candidate-inventory.json"
         }
       ]
     },
     {
       "candidate": "kind-security-test-sops",
       "Disk": "FAIL",
       "checks": [
         {
           "scope": "kind backing available",
           "requiredBytes": 62039375668,
           "availableBytes": 7400386560,
           "headroomBytes": -54638989108,
           "totalBytes": 10461925376,
           "usedBytes": 2507997184,
           "status": "FAIL",
           "evidence": null
         },
         {
           "scope": "independent physical backing available",
           "requiredBytes": 322122547200,
           "availableBytes": 24440545280,
           "headroomBytes": -297682001920,
           "totalBytes": 494384795648,
           "usedBytes": 469944250368,
           "status": "FAIL",
           "evidence": "local-candidate-inventory.json"
         }
       ]
     },
     {
       "candidate": "colima-default",
       "Disk": "FAIL",
       "checks": [
         {
           "scope": "guest available not inspected because stopped",
           "requiredBytes": 62039375668,
           "availableBytes": null,
           "headroomBytes": null,
           "totalBytes": null,
           "usedBytes": null,
           "status": "UNKNOWN",
           "evidence": null
         },
         {
           "scope": "independent physical backing available",
           "requiredBytes": 322122547200,
           "availableBytes": 24440545280,
           "headroomBytes": -297682001920,
           "totalBytes": 494384795648,
           "usedBytes": 469944250368,
           "status": "FAIL",
           "evidence": "local-candidate-inventory.json"
         }
       ]
     }
   ]

   Evidence: `strict-matrices.json`

11. **filesystem matrix**

   [
     {
       "candidate": "mac-host",
       "overall": "FAIL",
       "MUST_MATCH": [
         {
           "property": "architecture/tool",
           "classification": "MUST_MATCH_PRODUCTION",
           "requirement": "Linux arm64; exact c7586c image and d860 binary; UID/GID10000; same Node runtime version for frozen JS, record version before execution",
           "result": "FAIL",
           "evidence": "local-candidate-inventory.json"
         },
         {
           "property": "filesystem type / features",
           "classification": "MUST_MATCH_PRODUCTION",
           "requirement": "ext4 on lab Linux block device; record kernel, feature flags, journal/reserved-block ratio/delalloc and mount options; production cache mount is ext4 /dev/vda2",
           "result": "FAIL",
           "evidence": "local-candidate-inventory.json"
         },
         {
           "property": "block and inode accounting",
           "classification": "MUST_MATCH_PRODUCTION",
           "requirement": "4096-byte fundamental block observed; compare statvfs f_bavail/f_bfree, inode counts, ext4 reserved blocks. PVC nominal5Gi is NOT an enforced quota here",
           "result": "UNKNOWN",
           "evidence": "local-candidate-inventory.json"
         },
         {
           "property": "cache/temp placement",
           "classification": "MUST_MATCH_PRODUCTION",
           "requirement": "PVC-style bind at /home/scanner/.cache; /tmp on container overlay; same underlying ext4 device as cache; controller os.tmpdir manifests on controller filesystem tracked separately",
           "result": "UNKNOWN",
           "evidence": "local-candidate-inventory.json"
         },
         {
           "property": "rename / copy boundary",
           "classification": "MUST_MATCH_PRODUCTION",
           "requirement": "Preserve production device relationships; never move temp to tmpfs or different disk. Do not implement a replacement rename or wrapper backup",
           "result": "UNKNOWN",
           "evidence": "local-candidate-inventory.json"
         },
         {
           "property": "overlay container layer",
           "classification": "MUST_MATCH_PRODUCTION",
           "requirement": "Same containerd snapshotter overlayfs and image lower layers; fresh writable upperdir per case, same backing ext4. Collect upperdir, workdir and deleted-open-file accounting",
           "result": "UNKNOWN",
           "evidence": "local-candidate-inventory.json"
         },
         {
           "property": "guest filesystem capacity",
           "classification": "MUST_MATCH_PRODUCTION",
           "requirement": "For guard classification compare same measured capacityBytes270430261248 and reserve ratio; differing capacity only supplementary sensitivity run",
           "result": "FAIL",
           "evidence": "local-candidate-inventory.json"
         },
         {
           "property": "sparse / host COW",
           "classification": "MUST_MATCH_PRODUCTION",
           "requirement": "For end-to-end backing-space safety use dedicated qcow2 on APFS with adequate physical space and matched COW policy. ext4-only lab proves guest peak only; cannot validate production host/backup safety",
           "result": "UNKNOWN",
           "evidence": "local-candidate-inventory.json"
         }
       ],
       "SHOULD_MATCH": [
         {
           "property": "hypervisor/host version",
           "classification": "SHOULD_MATCH",
           "requirement": "Match existing UTM/QEMU/APFS where possible; record differences; no claim of backing-store equivalence if not matched"
         },
         {
           "property": "DNS / proxy / throughput",
           "classification": "SHOULD_MATCH",
           "requirement": "Independent egress, same official source and digest; record latency/retries; production mutable proxy excluded"
         }
       ],
       "NOT_RELEVANT": [
         {
           "property": "business namespace labels / production registry tags",
           "classification": "NOT_RELEVANT",
           "requirement": "No PetClinic or production registry needed; isolated kube API can use same harbor/data-infra/devops names solely because frozen IO hardcodes them"
         }
       ]
     },
     {
       "candidate": "node-aliyun-worker",
       "overall": "FAIL",
       "MUST_MATCH": [
         {
           "property": "architecture/tool",
           "classification": "MUST_MATCH_PRODUCTION",
           "requirement": "Linux arm64; exact c7586c image and d860 binary; UID/GID10000; same Node runtime version for frozen JS, record version before execution",
           "result": "FAIL",
           "evidence": "node-candidate-inventory.json"
         },
         {
           "property": "filesystem type / features",
           "classification": "MUST_MATCH_PRODUCTION",
           "requirement": "ext4 on lab Linux block device; record kernel, feature flags, journal/reserved-block ratio/delalloc and mount options; production cache mount is ext4 /dev/vda2",
           "result": "UNKNOWN",
           "evidence": "node-candidate-inventory.json"
         },
         {
           "property": "block and inode accounting",
           "classification": "MUST_MATCH_PRODUCTION",
           "requirement": "4096-byte fundamental block observed; compare statvfs f_bavail/f_bfree, inode counts, ext4 reserved blocks. PVC nominal5Gi is NOT an enforced quota here",
           "result": "UNKNOWN",
           "evidence": "node-candidate-inventory.json"
         },
         {
           "property": "cache/temp placement",
           "classification": "MUST_MATCH_PRODUCTION",
           "requirement": "PVC-style bind at /home/scanner/.cache; /tmp on container overlay; same underlying ext4 device as cache; controller os.tmpdir manifests on controller filesystem tracked separately",
           "result": "UNKNOWN",
           "evidence": "node-candidate-inventory.json"
         },
         {
           "property": "rename / copy boundary",
           "classification": "MUST_MATCH_PRODUCTION",
           "requirement": "Preserve production device relationships; never move temp to tmpfs or different disk. Do not implement a replacement rename or wrapper backup",
           "result": "UNKNOWN",
           "evidence": "node-candidate-inventory.json"
         },
         {
           "property": "overlay container layer",
           "classification": "MUST_MATCH_PRODUCTION",
           "requirement": "Same containerd snapshotter overlayfs and image lower layers; fresh writable upperdir per case, same backing ext4. Collect upperdir, workdir and deleted-open-file accounting",
           "result": "UNKNOWN",
           "evidence": "node-candidate-inventory.json"
         },
         {
           "property": "guest filesystem capacity",
           "classification": "MUST_MATCH_PRODUCTION",
           "requirement": "For guard classification compare same measured capacityBytes270430261248 and reserve ratio; differing capacity only supplementary sensitivity run",
           "result": "FAIL",
           "evidence": "node-candidate-inventory.json"
         },
         {
           "property": "sparse / host COW",
           "classification": "MUST_MATCH_PRODUCTION",
           "requirement": "For end-to-end backing-space safety use dedicated qcow2 on APFS with adequate physical space and matched COW policy. ext4-only lab proves guest peak only; cannot validate production host/backup safety",
           "result": "UNKNOWN",
           "evidence": "node-candidate-inventory.json"
         }
       ],
       "SHOULD_MATCH": [
         {
           "property": "hypervisor/host version",
           "classification": "SHOULD_MATCH",
           "requirement": "Match existing UTM/QEMU/APFS where possible; record differences; no claim of backing-store equivalence if not matched"
         },
         {
           "property": "DNS / proxy / throughput",
           "classification": "SHOULD_MATCH",
           "requirement": "Independent egress, same official source and digest; record latency/retries; production mutable proxy excluded"
         }
       ],
       "NOT_RELEVANT": [
         {
           "property": "business namespace labels / production registry tags",
           "classification": "NOT_RELEVANT",
           "requirement": "No PetClinic or production registry needed; isolated kube API can use same harbor/data-infra/devops names solely because frozen IO hardcodes them"
         }
       ]
     },
     {
       "candidate": "utm-devops",
       "overall": "FAIL",
       "MUST_MATCH": [
         {
           "property": "architecture/tool",
           "classification": "MUST_MATCH_PRODUCTION",
           "requirement": "Linux arm64; exact c7586c image and d860 binary; UID/GID10000; same Node runtime version for frozen JS, record version before execution",
           "result": "UNKNOWN",
           "evidence": "node-candidate-inventory.json"
         },
         {
           "property": "filesystem type / features",
           "classification": "MUST_MATCH_PRODUCTION",
           "requirement": "ext4 on lab Linux block device; record kernel, feature flags, journal/reserved-block ratio/delalloc and mount options; production cache mount is ext4 /dev/vda2",
           "result": "UNKNOWN",
           "evidence": "node-candidate-inventory.json"
         },
         {
           "property": "block and inode accounting",
           "classification": "MUST_MATCH_PRODUCTION",
           "requirement": "4096-byte fundamental block observed; compare statvfs f_bavail/f_bfree, inode counts, ext4 reserved blocks. PVC nominal5Gi is NOT an enforced quota here",
           "result": "UNKNOWN",
           "evidence": "node-candidate-inventory.json"
         },
         {
           "property": "cache/temp placement",
           "classification": "MUST_MATCH_PRODUCTION",
           "requirement": "PVC-style bind at /home/scanner/.cache; /tmp on container overlay; same underlying ext4 device as cache; controller os.tmpdir manifests on controller filesystem tracked separately",
           "result": "PASS",
           "evidence": "node-candidate-inventory.json"
         },
         {
           "property": "rename / copy boundary",
           "classification": "MUST_MATCH_PRODUCTION",
           "requirement": "Preserve production device relationships; never move temp to tmpfs or different disk. Do not implement a replacement rename or wrapper backup",
           "result": "PASS",
           "evidence": "node-candidate-inventory.json"
         },
         {
           "property": "overlay container layer",
           "classification": "MUST_MATCH_PRODUCTION",
           "requirement": "Same containerd snapshotter overlayfs and image lower layers; fresh writable upperdir per case, same backing ext4. Collect upperdir, workdir and deleted-open-file accounting",
           "result": "PASS",
           "evidence": "node-candidate-inventory.json"
         },
         {
           "property": "guest filesystem capacity",
           "classification": "MUST_MATCH_PRODUCTION",
           "requirement": "For guard classification compare same measured capacityBytes270430261248 and reserve ratio; differing capacity only supplementary sensitivity run",
           "result": "PASS",
           "evidence": "node-candidate-inventory.json"
         },
         {
           "property": "sparse / host COW",
           "classification": "MUST_MATCH_PRODUCTION",
           "requirement": "For end-to-end backing-space safety use dedicated qcow2 on APFS with adequate physical space and matched COW policy. ext4-only lab proves guest peak only; cannot validate production host/backup safety",
           "result": "FAIL",
           "evidence": "node-candidate-inventory.json"
         }
       ],
       "SHOULD_MATCH": [
         {
           "property": "hypervisor/host version",
           "classification": "SHOULD_MATCH",
           "requirement": "Match existing UTM/QEMU/APFS where possible; record differences; no claim of backing-store equivalence if not matched"
         },
         {
           "property": "DNS / proxy / throughput",
           "classification": "SHOULD_MATCH",
           "requirement": "Independent egress, same official source and digest; record latency/retries; production mutable proxy excluded"
         }
       ],
       "NOT_RELEVANT": [
         {
           "property": "business namespace labels / production registry tags",
           "classification": "NOT_RELEVANT",
           "requirement": "No PetClinic or production registry needed; isolated kube API can use same harbor/data-infra/devops names solely because frozen IO hardcodes them"
         }
       ]
     },
     {
       "candidate": "node-ucloud-worker",
       "overall": "FAIL",
       "MUST_MATCH": [
         {
           "property": "architecture/tool",
           "classification": "MUST_MATCH_PRODUCTION",
           "requirement": "Linux arm64; exact c7586c image and d860 binary; UID/GID10000; same Node runtime version for frozen JS, record version before execution",
           "result": "FAIL",
           "evidence": "node-candidate-inventory.json"
         },
         {
           "property": "filesystem type / features",
           "classification": "MUST_MATCH_PRODUCTION",
           "requirement": "ext4 on lab Linux block device; record kernel, feature flags, journal/reserved-block ratio/delalloc and mount options; production cache mount is ext4 /dev/vda2",
           "result": "UNKNOWN",
           "evidence": "node-candidate-inventory.json"
         },
         {
           "property": "block and inode accounting",
           "classification": "MUST_MATCH_PRODUCTION",
           "requirement": "4096-byte fundamental block observed; compare statvfs f_bavail/f_bfree, inode counts, ext4 reserved blocks. PVC nominal5Gi is NOT an enforced quota here",
           "result": "UNKNOWN",
           "evidence": "node-candidate-inventory.json"
         },
         {
           "property": "cache/temp placement",
           "classification": "MUST_MATCH_PRODUCTION",
           "requirement": "PVC-style bind at /home/scanner/.cache; /tmp on container overlay; same underlying ext4 device as cache; controller os.tmpdir manifests on controller filesystem tracked separately",
           "result": "UNKNOWN",
           "evidence": "node-candidate-inventory.json"
         },
         {
           "property": "rename / copy boundary",
           "classification": "MUST_MATCH_PRODUCTION",
           "requirement": "Preserve production device relationships; never move temp to tmpfs or different disk. Do not implement a replacement rename or wrapper backup",
           "result": "UNKNOWN",
           "evidence": "node-candidate-inventory.json"
         },
         {
           "property": "overlay container layer",
           "classification": "MUST_MATCH_PRODUCTION",
           "requirement": "Same containerd snapshotter overlayfs and image lower layers; fresh writable upperdir per case, same backing ext4. Collect upperdir, workdir and deleted-open-file accounting",
           "result": "UNKNOWN",
           "evidence": "node-candidate-inventory.json"
         },
         {
           "property": "guest filesystem capacity",
           "classification": "MUST_MATCH_PRODUCTION",
           "requirement": "For guard classification compare same measured capacityBytes270430261248 and reserve ratio; differing capacity only supplementary sensitivity run",
           "result": "FAIL",
           "evidence": "node-candidate-inventory.json"
         },
         {
           "property": "sparse / host COW",
           "classification": "MUST_MATCH_PRODUCTION",
           "requirement": "For end-to-end backing-space safety use dedicated qcow2 on APFS with adequate physical space and matched COW policy. ext4-only lab proves guest peak only; cannot validate production host/backup safety",
           "result": "UNKNOWN",
           "evidence": "node-candidate-inventory.json"
         }
       ],
       "SHOULD_MATCH": [
         {
           "property": "hypervisor/host version",
           "classification": "SHOULD_MATCH",
           "requirement": "Match existing UTM/QEMU/APFS where possible; record differences; no claim of backing-store equivalence if not matched"
         },
         {
           "property": "DNS / proxy / throughput",
           "classification": "SHOULD_MATCH",
           "requirement": "Independent egress, same official source and digest; record latency/retries; production mutable proxy excluded"
         }
       ],
       "NOT_RELEVANT": [
         {
           "property": "business namespace labels / production registry tags",
           "classification": "NOT_RELEVANT",
           "requirement": "No PetClinic or production registry needed; isolated kube API can use same harbor/data-infra/devops names solely because frozen IO hardcodes them"
         }
       ]
     },
     {
       "candidate": "colima-security-test",
       "overall": "FAIL",
       "MUST_MATCH": [
         {
           "property": "architecture/tool",
           "classification": "MUST_MATCH_PRODUCTION",
           "requirement": "Linux arm64; exact c7586c image and d860 binary; UID/GID10000; same Node runtime version for frozen JS, record version before execution",
           "result": "UNKNOWN",
           "evidence": "local-candidate-inventory.json + validation-existing-detail.json"
         },
         {
           "property": "filesystem type / features",
           "classification": "MUST_MATCH_PRODUCTION",
           "requirement": "ext4 on lab Linux block device; record kernel, feature flags, journal/reserved-block ratio/delalloc and mount options; production cache mount is ext4 /dev/vda2",
           "result": "UNKNOWN",
           "evidence": "local-candidate-inventory.json + validation-existing-detail.json"
         },
         {
           "property": "block and inode accounting",
           "classification": "MUST_MATCH_PRODUCTION",
           "requirement": "4096-byte fundamental block observed; compare statvfs f_bavail/f_bfree, inode counts, ext4 reserved blocks. PVC nominal5Gi is NOT an enforced quota here",
           "result": "UNKNOWN",
           "evidence": "local-candidate-inventory.json + validation-existing-detail.json"
         },
         {
           "property": "cache/temp placement",
           "classification": "MUST_MATCH_PRODUCTION",
           "requirement": "PVC-style bind at /home/scanner/.cache; /tmp on container overlay; same underlying ext4 device as cache; controller os.tmpdir manifests on controller filesystem tracked separately",
           "result": "FAIL",
           "evidence": "local-candidate-inventory.json + validation-existing-detail.json"
         },
         {
           "property": "rename / copy boundary",
           "classification": "MUST_MATCH_PRODUCTION",
           "requirement": "Preserve production device relationships; never move temp to tmpfs or different disk. Do not implement a replacement rename or wrapper backup",
           "result": "FAIL",
           "evidence": "local-candidate-inventory.json + validation-existing-detail.json"
         },
         {
           "property": "overlay container layer",
           "classification": "MUST_MATCH_PRODUCTION",
           "requirement": "Same containerd snapshotter overlayfs and image lower layers; fresh writable upperdir per case, same backing ext4. Collect upperdir, workdir and deleted-open-file accounting",
           "result": "UNKNOWN",
           "evidence": "local-candidate-inventory.json + validation-existing-detail.json"
         },
         {
           "property": "guest filesystem capacity",
           "classification": "MUST_MATCH_PRODUCTION",
           "requirement": "For guard classification compare same measured capacityBytes270430261248 and reserve ratio; differing capacity only supplementary sensitivity run",
           "result": "FAIL",
           "evidence": "local-candidate-inventory.json + validation-existing-detail.json"
         },
         {
           "property": "sparse / host COW",
           "classification": "MUST_MATCH_PRODUCTION",
           "requirement": "For end-to-end backing-space safety use dedicated qcow2 on APFS with adequate physical space and matched COW policy. ext4-only lab proves guest peak only; cannot validate production host/backup safety",
           "result": "FAIL",
           "evidence": "local-candidate-inventory.json + validation-existing-detail.json"
         }
       ],
       "SHOULD_MATCH": [
         {
           "property": "hypervisor/host version",
           "classification": "SHOULD_MATCH",
           "requirement": "Match existing UTM/QEMU/APFS where possible; record differences; no claim of backing-store equivalence if not matched"
         },
         {
           "property": "DNS / proxy / throughput",
           "classification": "SHOULD_MATCH",
           "requirement": "Independent egress, same official source and digest; record latency/retries; production mutable proxy excluded"
         }
       ],
       "NOT_RELEVANT": [
         {
           "property": "business namespace labels / production registry tags",
           "classification": "NOT_RELEVANT",
           "requirement": "No PetClinic or production registry needed; isolated kube API can use same harbor/data-infra/devops names solely because frozen IO hardcodes them"
         }
       ]
     },
     {
       "candidate": "kind-security-test-sops",
       "overall": "FAIL",
       "MUST_MATCH": [
         {
           "property": "architecture/tool",
           "classification": "MUST_MATCH_PRODUCTION",
           "requirement": "Linux arm64; exact c7586c image and d860 binary; UID/GID10000; same Node runtime version for frozen JS, record version before execution",
           "result": "UNKNOWN",
           "evidence": "validation-existing-detail.json"
         },
         {
           "property": "filesystem type / features",
           "classification": "MUST_MATCH_PRODUCTION",
           "requirement": "ext4 on lab Linux block device; record kernel, feature flags, journal/reserved-block ratio/delalloc and mount options; production cache mount is ext4 /dev/vda2",
           "result": "FAIL",
           "evidence": "validation-existing-detail.json"
         },
         {
           "property": "block and inode accounting",
           "classification": "MUST_MATCH_PRODUCTION",
           "requirement": "4096-byte fundamental block observed; compare statvfs f_bavail/f_bfree, inode counts, ext4 reserved blocks. PVC nominal5Gi is NOT an enforced quota here",
           "result": "UNKNOWN",
           "evidence": "validation-existing-detail.json"
         },
         {
           "property": "cache/temp placement",
           "classification": "MUST_MATCH_PRODUCTION",
           "requirement": "PVC-style bind at /home/scanner/.cache; /tmp on container overlay; same underlying ext4 device as cache; controller os.tmpdir manifests on controller filesystem tracked separately",
           "result": "FAIL",
           "evidence": "validation-existing-detail.json"
         },
         {
           "property": "rename / copy boundary",
           "classification": "MUST_MATCH_PRODUCTION",
           "requirement": "Preserve production device relationships; never move temp to tmpfs or different disk. Do not implement a replacement rename or wrapper backup",
           "result": "FAIL",
           "evidence": "validation-existing-detail.json"
         },
         {
           "property": "overlay container layer",
           "classification": "MUST_MATCH_PRODUCTION",
           "requirement": "Same containerd snapshotter overlayfs and image lower layers; fresh writable upperdir per case, same backing ext4. Collect upperdir, workdir and deleted-open-file accounting",
           "result": "UNKNOWN",
           "evidence": "validation-existing-detail.json"
         },
         {
           "property": "guest filesystem capacity",
           "classification": "MUST_MATCH_PRODUCTION",
           "requirement": "For guard classification compare same measured capacityBytes270430261248 and reserve ratio; differing capacity only supplementary sensitivity run",
           "result": "FAIL",
           "evidence": "validation-existing-detail.json"
         },
         {
           "property": "sparse / host COW",
           "classification": "MUST_MATCH_PRODUCTION",
           "requirement": "For end-to-end backing-space safety use dedicated qcow2 on APFS with adequate physical space and matched COW policy. ext4-only lab proves guest peak only; cannot validate production host/backup safety",
           "result": "FAIL",
           "evidence": "validation-existing-detail.json"
         }
       ],
       "SHOULD_MATCH": [
         {
           "property": "hypervisor/host version",
           "classification": "SHOULD_MATCH",
           "requirement": "Match existing UTM/QEMU/APFS where possible; record differences; no claim of backing-store equivalence if not matched"
         },
         {
           "property": "DNS / proxy / throughput",
           "classification": "SHOULD_MATCH",
           "requirement": "Independent egress, same official source and digest; record latency/retries; production mutable proxy excluded"
         }
       ],
       "NOT_RELEVANT": [
         {
           "property": "business namespace labels / production registry tags",
           "classification": "NOT_RELEVANT",
           "requirement": "No PetClinic or production registry needed; isolated kube API can use same harbor/data-infra/devops names solely because frozen IO hardcodes them"
         }
       ]
     },
     {
       "candidate": "colima-default",
       "overall": "FAIL",
       "MUST_MATCH": [
         {
           "property": "architecture/tool",
           "classification": "MUST_MATCH_PRODUCTION",
           "requirement": "Linux arm64; exact c7586c image and d860 binary; UID/GID10000; same Node runtime version for frozen JS, record version before execution",
           "result": "UNKNOWN",
           "evidence": "local-candidate-inventory.json"
         },
         {
           "property": "filesystem type / features",
           "classification": "MUST_MATCH_PRODUCTION",
           "requirement": "ext4 on lab Linux block device; record kernel, feature flags, journal/reserved-block ratio/delalloc and mount options; production cache mount is ext4 /dev/vda2",
           "result": "UNKNOWN",
           "evidence": "local-candidate-inventory.json"
         },
         {
           "property": "block and inode accounting",
           "classification": "MUST_MATCH_PRODUCTION",
           "requirement": "4096-byte fundamental block observed; compare statvfs f_bavail/f_bfree, inode counts, ext4 reserved blocks. PVC nominal5Gi is NOT an enforced quota here",
           "result": "UNKNOWN",
           "evidence": "local-candidate-inventory.json"
         },
         {
           "property": "cache/temp placement",
           "classification": "MUST_MATCH_PRODUCTION",
           "requirement": "PVC-style bind at /home/scanner/.cache; /tmp on container overlay; same underlying ext4 device as cache; controller os.tmpdir manifests on controller filesystem tracked separately",
           "result": "UNKNOWN",
           "evidence": "local-candidate-inventory.json"
         },
         {
           "property": "rename / copy boundary",
           "classification": "MUST_MATCH_PRODUCTION",
           "requirement": "Preserve production device relationships; never move temp to tmpfs or different disk. Do not implement a replacement rename or wrapper backup",
           "result": "UNKNOWN",
           "evidence": "local-candidate-inventory.json"
         },
         {
           "property": "overlay container layer",
           "classification": "MUST_MATCH_PRODUCTION",
           "requirement": "Same containerd snapshotter overlayfs and image lower layers; fresh writable upperdir per case, same backing ext4. Collect upperdir, workdir and deleted-open-file accounting",
           "result": "UNKNOWN",
           "evidence": "local-candidate-inventory.json"
         },
         {
           "property": "guest filesystem capacity",
           "classification": "MUST_MATCH_PRODUCTION",
           "requirement": "For guard classification compare same measured capacityBytes270430261248 and reserve ratio; differing capacity only supplementary sensitivity run",
           "result": "UNKNOWN",
           "evidence": "local-candidate-inventory.json"
         },
         {
           "property": "sparse / host COW",
           "classification": "MUST_MATCH_PRODUCTION",
           "requirement": "For end-to-end backing-space safety use dedicated qcow2 on APFS with adequate physical space and matched COW policy. ext4-only lab proves guest peak only; cannot validate production host/backup safety",
           "result": "FAIL",
           "evidence": "local-candidate-inventory.json"
         }
       ],
       "SHOULD_MATCH": [
         {
           "property": "hypervisor/host version",
           "classification": "SHOULD_MATCH",
           "requirement": "Match existing UTM/QEMU/APFS where possible; record differences; no claim of backing-store equivalence if not matched"
         },
         {
           "property": "DNS / proxy / throughput",
           "classification": "SHOULD_MATCH",
           "requirement": "Independent egress, same official source and digest; record latency/retries; production mutable proxy excluded"
         }
       ],
       "NOT_RELEVANT": [
         {
           "property": "business namespace labels / production registry tags",
           "classification": "NOT_RELEVANT",
           "requirement": "No PetClinic or production registry needed; isolated kube API can use same harbor/data-infra/devops names solely because frozen IO hardcodes them"
         }
       ]
     }
   ]

12. **topology matrix**

   {
     "matrix": [
       {
         "candidate": "mac-host",
         "result": "FAIL",
         "evidence": "local-candidate-inventory.json"
       },
       {
         "candidate": "node-aliyun-worker",
         "result": "UNKNOWN",
         "evidence": "node-candidate-inventory.json"
       },
       {
         "candidate": "utm-devops",
         "result": "PASS",
         "evidence": "node-candidate-inventory.json"
       },
       {
         "candidate": "node-ucloud-worker",
         "result": "UNKNOWN",
         "evidence": "node-candidate-inventory.json"
       },
       {
         "candidate": "colima-security-test",
         "result": "FAIL",
         "evidence": "local-candidate-inventory.json + validation-existing-detail.json"
       },
       {
         "candidate": "kind-security-test-sops",
         "result": "FAIL",
         "evidence": "validation-existing-detail.json"
       },
       {
         "candidate": "colima-default",
         "result": "UNKNOWN",
         "evidence": "local-candidate-inventory.json"
       }
     ],
     "limitation": "Frozen tool uses destination removal/copy, not assumed atomic rename. Kind/tmp tmpfs and Colima OS/data device split are disqualifying. No replacement/extraction failure injected."
   }

   Evidence: `strict-matrices.json`

13. **measurement matrix**

   {
     "matrix": [
       {
         "candidate": "mac-host",
         "result": "UNKNOWN",
         "evidence": "local-candidate-inventory.json"
       },
       {
         "candidate": "node-aliyun-worker",
         "result": "UNKNOWN",
         "evidence": "node-candidate-inventory.json"
       },
       {
         "candidate": "utm-devops",
         "result": "UNKNOWN",
         "evidence": "node-candidate-inventory.json"
       },
       {
         "candidate": "node-ucloud-worker",
         "result": "UNKNOWN",
         "evidence": "node-candidate-inventory.json"
       },
       {
         "candidate": "colima-security-test",
         "result": "UNKNOWN",
         "evidence": "local-candidate-inventory.json + validation-existing-detail.json"
       },
       {
         "candidate": "kind-security-test-sops",
         "result": "UNKNOWN",
         "evidence": "validation-existing-detail.json"
       },
       {
         "candidate": "colima-default",
         "result": "UNKNOWN",
         "evidence": "local-candidate-inventory.json"
       }
     ],
     "samplerOnly": {
       "exit": 0,
       "result": {
         "classification": "READ_ONLY_SAMPLER_CALIBRATION_ONLY",
         "samples": 100,
         "clockResolutionSeconds": 1e-09,
         "wallMs": 1105.575083,
         "cpuMs": 13.351786,
         "cpuFraction": 0.012076779049478632,
         "minGapMs": 10.111227,
         "maxGapMs": 15.779097,
         "meanGapMs": 11.036545868686868,
         "statvfsPath": "/mnt/lima-colima-security-test",
         "minAvailableBytes": 7400386560,
         "allocationTraceAvailableTools": {
           "bpftrace": false,
           "trace-cmd": false,
           "perf": false
         },
         "zeroDBRefreshes": true,
         "fullPeakMeasurementProven": false
       }
     },
     "limitation": "100 read-only samples demonstrate timer/statvfs availability only; not full per-directory/event accounting, no true-peak proof or overhead under refresh load."
   }

   Evidence: `strict-matrices.json`

14. **network matrix**

   {
     "matrix": [
       {
         "candidate": "mac-host",
         "result": "UNKNOWN",
         "evidence": "local-candidate-inventory.json"
       },
       {
         "candidate": "node-aliyun-worker",
         "result": "UNKNOWN",
         "evidence": "node-candidate-inventory.json"
       },
       {
         "candidate": "utm-devops",
         "result": "UNKNOWN",
         "evidence": "node-candidate-inventory.json"
       },
       {
         "candidate": "node-ucloud-worker",
         "result": "UNKNOWN",
         "evidence": "node-candidate-inventory.json"
       },
       {
         "candidate": "colima-security-test",
         "result": "UNKNOWN",
         "evidence": "local-candidate-inventory.json + validation-existing-detail.json"
       },
       {
         "candidate": "kind-security-test-sops",
         "result": "UNKNOWN",
         "evidence": "validation-existing-detail.json"
       },
       {
         "candidate": "colima-default",
         "result": "UNKNOWN",
         "evidence": "local-candidate-inventory.json"
       }
     ],
     "limitation": "No metadata reachability test from eligible isolated target because none exists. UNKNOWN is not unreachable and not PASS; production proxy not used."
   }

   Evidence: `strict-matrices.json`

15. **credential matrix**

   {
     "matrix": [
       {
         "candidate": "mac-host",
         "result": "UNKNOWN",
         "evidence": "local-candidate-inventory.json"
       },
       {
         "candidate": "node-aliyun-worker",
         "result": "UNKNOWN",
         "evidence": "node-candidate-inventory.json"
       },
       {
         "candidate": "utm-devops",
         "result": "UNKNOWN",
         "evidence": "node-candidate-inventory.json"
       },
       {
         "candidate": "node-ucloud-worker",
         "result": "UNKNOWN",
         "evidence": "node-candidate-inventory.json"
       },
       {
         "candidate": "colima-security-test",
         "result": "UNKNOWN",
         "evidence": "local-candidate-inventory.json + validation-existing-detail.json"
       },
       {
         "candidate": "kind-security-test-sops",
         "result": "UNKNOWN",
         "evidence": "validation-existing-detail.json"
       },
       {
         "candidate": "colima-default",
         "result": "UNKNOWN",
         "evidence": "local-candidate-inventory.json"
       }
     ],
     "limitation": "Public pulls require anonymous token path plus least-privilege lab API/Lease identity. No candidate validation identity/expiry proof, no new token/Secret minted. Existing production read-only access is not experiment authorization."
   }

   Evidence: `strict-matrices.json`

16. **isolation matrix**

   {
     "matrix": [
       {
         "candidate": "mac-host",
         "result": "FAIL",
         "evidence": "local-candidate-inventory.json"
       },
       {
         "candidate": "node-aliyun-worker",
         "result": "FAIL",
         "evidence": "node-candidate-inventory.json"
       },
       {
         "candidate": "utm-devops",
         "result": "FAIL",
         "evidence": "node-candidate-inventory.json"
       },
       {
         "candidate": "node-ucloud-worker",
         "result": "FAIL",
         "evidence": "node-candidate-inventory.json"
       },
       {
         "candidate": "colima-security-test",
         "result": "FAIL",
         "evidence": "local-candidate-inventory.json + validation-existing-detail.json"
       },
       {
         "candidate": "kind-security-test-sops",
         "result": "FAIL",
         "evidence": "validation-existing-detail.json"
       },
       {
         "candidate": "colima-default",
         "result": "FAIL",
         "evidence": "local-candidate-inventory.json"
       }
     ]
   }

   Evidence: `strict-matrices.json`

17. **failure-safety matrix**

   {
     "matrix": [
       {
         "candidate": "mac-host",
         "result": "FAIL",
         "evidence": "local-candidate-inventory.json"
       },
       {
         "candidate": "node-aliyun-worker",
         "result": "FAIL",
         "evidence": "node-candidate-inventory.json"
       },
       {
         "candidate": "utm-devops",
         "result": "FAIL",
         "evidence": "node-candidate-inventory.json"
       },
       {
         "candidate": "node-ucloud-worker",
         "result": "FAIL",
         "evidence": "node-candidate-inventory.json"
       },
       {
         "candidate": "colima-security-test",
         "result": "FAIL",
         "evidence": "local-candidate-inventory.json + validation-existing-detail.json"
       },
       {
         "candidate": "kind-security-test-sops",
         "result": "FAIL",
         "evidence": "validation-existing-detail.json"
       },
       {
         "candidate": "colima-default",
         "result": "FAIL",
         "evidence": "local-candidate-inventory.json"
       }
     ]
   }

   Evidence: `strict-matrices.json`

18. **repeatability matrix**

   {
     "matrix": [
       {
         "candidate": "mac-host",
         "result": "FAIL",
         "evidence": "local-candidate-inventory.json"
       },
       {
         "candidate": "node-aliyun-worker",
         "result": "FAIL",
         "evidence": "node-candidate-inventory.json"
       },
       {
         "candidate": "utm-devops",
         "result": "FAIL",
         "evidence": "node-candidate-inventory.json"
       },
       {
         "candidate": "node-ucloud-worker",
         "result": "FAIL",
         "evidence": "node-candidate-inventory.json"
       },
       {
         "candidate": "colima-security-test",
         "result": "FAIL",
         "evidence": "local-candidate-inventory.json + validation-existing-detail.json"
       },
       {
         "candidate": "kind-security-test-sops",
         "result": "FAIL",
         "evidence": "validation-existing-detail.json"
       },
       {
         "candidate": "colima-default",
         "result": "FAIL",
         "evidence": "local-candidate-inventory.json"
       }
     ]
   }

   Evidence: `strict-matrices.json`

19. **candidate overall classifications**

   [
     {
       "candidate": "mac-host",
       "productionClass": "PRODUCTION_CRITICAL",
       "overall": "INELIGIBLE"
     },
     {
       "candidate": "node-aliyun-worker",
       "productionClass": "PRODUCTION_SHARED",
       "overall": "INELIGIBLE"
     },
     {
       "candidate": "utm-devops",
       "productionClass": "PRODUCTION_CRITICAL",
       "overall": "INELIGIBLE"
     },
     {
       "candidate": "node-ucloud-worker",
       "productionClass": "PRODUCTION_SHARED",
       "overall": "INELIGIBLE"
     },
     {
       "candidate": "colima-security-test",
       "productionClass": "VALIDATION_SAFE",
       "overall": "INELIGIBLE"
     },
     {
       "candidate": "kind-security-test-sops",
       "productionClass": "VALIDATION_SAFE",
       "overall": "INELIGIBLE"
     },
     {
       "candidate": "colima-default",
       "productionClass": "UNKNOWN",
       "overall": "INELIGIBLE"
     }
   ]

20. **eligible candidates**

   []

21. **selected candidate**

   NONE

22. **exact rejection reason per ineligible candidate**

   [
     {
       "candidateId": "mac-host",
       "classification": "PRODUCTION_CRITICAL",
       "overall": "INELIGIBLE",
       "reasons": [
         "Actual available backing below sealed300GiB floor",
         "macOS/APFS native environment is not frozen Linux arm64/ext4/overlay topology",
         "Low-space/failure test threatens production VM backing"
       ],
       "capacityChecks": [
         {
           "scope": "independent physical backing available",
           "requiredBytes": 322122547200,
           "availableBytes": 24440545280,
           "headroomBytes": -297682001920,
           "totalBytes": 494384795648,
           "usedBytes": 469944250368,
           "status": "FAIL",
           "evidence": "local-candidate-inventory.json"
         }
       ]
     },
     {
       "candidateId": "node-aliyun-worker",
       "classification": "PRODUCTION_SHARED",
       "overall": "INELIGIBLE",
       "reasons": [
         "Production node and runtime share filesystem; interrupted/extraction/low-space tests can cause DiskPressure, eviction or runtime instability",
         "Guest initial free headroom below sealed above-guard+8GiB full-matrix band",
         "amd64 cannot match frozen Linux arm64 exact image/binary requirement",
         "No equivalent guest filesystem capacity; provider attached-disk inventory UNKNOWN because existing trusted host read unavailable, no privilege escalation/bypass"
       ],
       "capacityChecks": [
         {
           "scope": "guest initial available >= frozen guard +8GiB band",
           "requiredBytes": 62039375668,
           "availableBytes": 10100510720,
           "headroomBytes": -51938864948,
           "totalBytes": 41882943488,
           "usedBytes": 29846695936,
           "status": "FAIL",
           "evidence": "node-candidate-inventory.json"
         }
       ]
     },
     {
       "candidateId": "utm-devops",
       "classification": "PRODUCTION_CRITICAL",
       "overall": "INELIGIBLE",
       "reasons": [
         "Production node and runtime share filesystem; interrupted/extraction/low-space tests can cause DiskPressure, eviction or runtime instability",
         "Guest initial free headroom below sealed above-guard+8GiB full-matrix band",
         "Existing sealed production VM exclusion: no safe backing/validated backup; no cleanup or expansion reopened"
       ],
       "capacityChecks": [
         {
           "scope": "guest initial available >= frozen guard +8GiB band",
           "requiredBytes": 62039375668,
           "availableBytes": 45347446784,
           "headroomBytes": -16691928884,
           "totalBytes": 270430261248,
           "usedBytes": 211898433536,
           "status": "FAIL",
           "evidence": "node-candidate-inventory.json"
         },
         {
           "scope": "independent physical backing available",
           "requiredBytes": 322122547200,
           "availableBytes": 24440545280,
           "headroomBytes": -297682001920,
           "totalBytes": 494384795648,
           "usedBytes": 469944250368,
           "status": "FAIL",
           "evidence": "local-candidate-inventory.json"
         }
       ]
     },
     {
       "candidateId": "node-ucloud-worker",
       "classification": "PRODUCTION_SHARED",
       "overall": "INELIGIBLE",
       "reasons": [
         "Production node and runtime share filesystem; interrupted/extraction/low-space tests can cause DiskPressure, eviction or runtime instability",
         "Guest initial free headroom below sealed above-guard+8GiB full-matrix band",
         "amd64 cannot match frozen Linux arm64 exact image/binary requirement",
         "No equivalent guest filesystem capacity; provider attached-disk inventory UNKNOWN because existing trusted host read unavailable, no privilege escalation/bypass"
       ],
       "capacityChecks": [
         {
           "scope": "guest initial available >= frozen guard +8GiB band",
           "requiredBytes": 62039375668,
           "availableBytes": 56811704320,
           "headroomBytes": -5227671348,
           "totalBytes": 83053432832,
           "usedBytes": 26224951296,
           "status": "FAIL",
           "evidence": "node-candidate-inventory.json"
         }
       ]
     },
     {
       "candidateId": "colima-security-test",
       "classification": "VALIDATION_SAFE",
       "overall": "INELIGIBLE",
       "reasons": [
         "Data available~6.89GiB, primary270430261248B FS not present",
         "OS /tmp lives on vda, Docker data on vdb: required same-backing topology not met",
         "Production host APFS backing is shared and cannot tolerate low-space/COW failure tests"
       ],
       "capacityChecks": [
         {
           "scope": "guest data available",
           "requiredBytes": 62039375668,
           "availableBytes": 7400390656,
           "headroomBytes": -54638985012,
           "totalBytes": 10461925376,
           "usedBytes": 2507993088,
           "status": "FAIL",
           "evidence": null
         },
         {
           "scope": "independent physical backing available",
           "requiredBytes": 322122547200,
           "availableBytes": 24440545280,
           "headroomBytes": -297682001920,
           "totalBytes": 494384795648,
           "usedBytes": 469944250368,
           "status": "FAIL",
           "evidence": "local-candidate-inventory.json"
         }
       ]
     },
     {
       "candidateId": "kind-security-test-sops",
       "classification": "VALIDATION_SAFE",
       "overall": "INELIGIBLE",
       "reasons": [
         "kind /tmp is1GiB tmpfs, explicit MUST_MATCH storage mismatch",
         "All allocations share small Colima data disk and production Mac backing",
         "Cannot safely reproduce full disk-failure/low-space matrix; existing cluster not disposable by this authorization"
       ],
       "capacityChecks": [
         {
           "scope": "kind backing available",
           "requiredBytes": 62039375668,
           "availableBytes": 7400386560,
           "headroomBytes": -54638989108,
           "totalBytes": 10461925376,
           "usedBytes": 2507997184,
           "status": "FAIL",
           "evidence": null
         },
         {
           "scope": "independent physical backing available",
           "requiredBytes": 322122547200,
           "availableBytes": 24440545280,
           "headroomBytes": -297682001920,
           "totalBytes": 494384795648,
           "usedBytes": 469944250368,
           "status": "FAIL",
           "evidence": "local-candidate-inventory.json"
         }
       ]
     },
     {
       "candidateId": "colima-default",
       "classification": "UNKNOWN",
       "overall": "INELIGIBLE",
       "reasons": [
         "Stopped VM not started; no attested mount/topology/workload isolation",
         "Configured virtual data disk100GiB is not measured usable/free capacity and not primary251.865GiB FS",
         "Actual shared host backing fails300GiB requirement"
       ],
       "capacityChecks": [
         {
           "scope": "guest available not inspected because stopped",
           "requiredBytes": 62039375668,
           "availableBytes": null,
           "headroomBytes": null,
           "totalBytes": null,
           "usedBytes": null,
           "status": "UNKNOWN",
           "evidence": null
         },
         {
           "scope": "independent physical backing available",
           "requiredBytes": 322122547200,
           "availableBytes": 24440545280,
           "headroomBytes": -297682001920,
           "totalBytes": 494384795648,
           "usedBytes": 469944250368,
           "status": "FAIL",
           "evidence": "local-candidate-inventory.json"
         }
       ]
     }
   ]

   Evidence: `blocker-receipt.json`

23. **ISOLATED_TRIVY_EXECUTION_RESOURCE**

   NOT_AVAILABLE (within the existing accessible project resources actually inventoried; no global cloud-account inventory claim)

24. **future pre-flight if applicable**

   NOT_APPLICABLE: no ELIGIBLE candidate. Existing accepted preflight schema retained byte-identical for future material-change review; not a selected-candidate preflight or execution approval.

   Evidence: `future-preflight.schema.json`

25. **exact resource blocker if unavailable**

   All7 actual candidates INELIGIBLE: insufficient available space, primary filesystem/topology mismatch, production failure blast radius and/or no independent physical backing. Do not use smaller CASE A or change guard.

   Evidence: `blocker-receipt.json`

26. **material-change conditions**

   {
     "changes": [
       "Independent attached/mounted storage with materially sufficient actual free bytes and safe backing/backup budget becomes available",
       "Existing candidate actual free capacity increases enough AND all mandatory equivalence/isolation properties can be proved without production changes",
       "New independently available non-production arm64 VM with primary filesystem/overlay/cache-temp equivalence appears",
       "Equivalent validation host plus loss-free measurement/evidence storage becomes accessible"
     ],
     "notChanges": [
       "Time elapsed or user asks continue with unchanged resource facts",
       "Production proxy switch/restart/hash change (not dependency)",
       "Sparse virtual capacity declaration, symlink/mount alias, theoretical APFS total",
       "Run CASE A only, smaller experiment, lower guard, deletion/resize proposal without authorization"
     ]
   }

27. **TRIVY_RESOURCE_AUDIT_CLOSED**

   YES. This one audit is CLOSED. Do not rescan same candidates until material resource change is supplied/evidenced; no background polling or automatic follow-on work.

28. **production proxy debt state**

   {
     "CURRENT_PRODUCTION_PROXY_STATE": "DIFFERS_FROM_EPOCH",
     "PRODUCTION_CHECKPOINT_CONTINUITY": "BROKEN",
     "source": "evidence/2026-11-03/trivy-guard-dependency-boundary-review/production-continuity.json",
     "sourceSha256": "4ce25572ba7213576f379a2ca7bf1d7e67178280dfb77da24209106bf3b4f28d",
     "thisIterationReinvestigation": false,
     "agentWrites": 0,
     "agentRestarts": 0,
     "experimentEligibilityDependency": false
   }

   Evidence: `production-proxy-debt.json`

29. **Trivy status**

   {
     "environment": "ENVIRONMENT_BLOCKED",
     "runtime": "INCOMPLETE",
     "guardValidity": "GUARD_REQUIRES_REVALIDATION",
     "experimentReadiness": "RESOURCE_BLOCKED",
     "guardChanged": false,
     "refreshes": 0
   }

30. **Dojo status**

   {
     "dependency": "TRIVY_HARD_DEPENDENCY",
     "state": "BLOCKED_BY_TRIVY",
     "runtime": "INCOMPLETE",
     "writes": 0
   }

31. **final wired capability**

   14/16; Cosign VERIFIED; no new runtime result or Policy evaluation; canonical runtime and SummaryV2 remain blocked. Security Manager implementation not authorized by roadmap.

32. **test results**

   {
     "tests": 42,
     "pass": 42,
     "fail": 0,
     "type": "NON_MUTATING_SCHEMA_SCORING_CAPACITY_TOPOLOGY_ISOLATION_DEPENDENCY_PREFLIGHT_BLOCKER_INTEGRITY_TESTS",
     "syntheticFixturesAreNotCandidateEvidence": true,
     "samplerOnlyCalibration": 100,
     "DBRefreshes": 0
   }

   Evidence: `audit-tests.log`

33. **evidence integrity**

   {
     "status": "VERIFIED",
     "sealedPriorBundles": [
       {
         "path": "evidence/2026-11-03/trivy-guard-experiment-design/evidence-sha256.json",
         "sha256": "bc60c85686bf6c8d2a9367dadbf10a41fc33865976c36b86037ea124fea51e8a",
         "filesVerified": 40
       },
       {
         "path": "evidence/2026-11-03/trivy-guard-dependency-boundary-review/evidence-sha256.json",
         "sha256": "1941a09be4807004a3be168e42cd44611984ba172bf85b33dc8d928cd171662d",
         "filesVerified": 44
       },
       {
         "path": "evidence/2026-11-03/runtime-checkpoint-epoch-v2/evidence-sha256.json",
         "sha256": "52209072295e2e590333214f9585d0fda67987afa149210232c97e531992d0f9",
         "filesVerified": 86
       }
     ],
     "currentPriorBundleFilesVerified": 170,
     "historicalOlderFilesVerified": 1065,
     "existingSourceFiles": 77,
     "epochTools": 9,
     "frozenGateReferences": 455,
     "uniqueFrozenGateFiles": 229,
     "compatibilitySamplesUnchanged": 2202,
     "oldFailedCheckpointUnchanged": true
   }

   Evidence: `integrity-preservation.json`

34. **production Jenkins state**

   {
     "build": 270,
     "result": "SUCCESS",
     "newBuilds": 0
   }

   Evidence: `live-jenkins-final.json`

35. **V1 state**

   {
     "sha256": "ec9ee51a06d4b9f61c6c0eaf50b374d1e25e6d3ca687908b7596d3a2c794f5d8",
     "unchanged": true
   }

36. **nodes state**

   [
     "aliyun-worker",
     "devops",
     "ucloud-worker"
   ]

   Evidence: `node-lease-postflight.json`

37. **PetClinic state**

   {
     "ready": 3,
     "ReadyEndpoints": 3,
     "HTTP": 200,
     "generation": 175,
     "revision": "164"
   }

   Evidence: `health-final.json`, `live-protected-final.json`

38. **release count**

   0

39. **rollout count**

   0

40. **exact next permitted action**

   STOP. No repeat search on unchanged resources. Await material independently available storage/host/free-capacity/equivalence change. No resource purchase/provision/resize/delete/workload move/proxy or guard change/DB refresh/Dojo/SummaryV2/roadmap skip. Existing evidence immutable.

## Final verdicts

```text
EXPERIMENT_DESIGN_COMPLETENESS=READY
PRODUCTION_PROXY_REQUIRED_FOR_EXPERIMENT=NO
ISOLATED_TRIVY_EXECUTION_RESOURCE=NOT_AVAILABLE
SELECTED_EXPERIMENT_CANDIDATE=NONE
TRIVY_GUARD_EXPERIMENT_EXECUTION_READINESS=RESOURCE_BLOCKED
TRIVY_RESOURCE_AUDIT_CLOSED=YES
TRIVY_STORAGE_ENVIRONMENT=ENVIRONMENT_BLOCKED
TRIVY_RUNTIME_FACT_CAPTURE=INCOMPLETE
DEFECTDOJO_RUNTIME_DEPENDENCY=BLOCKED_BY_TRIVY
DEFECTDOJO_RUNTIME_FACT_CAPTURE=INCOMPLETE
FINAL_WIRED_CAPABILITY=14/16
REAL_RUNTIME_FACT_CAPTURE=INCOMPLETE
REAL_POLICY_OWNER=INCOMPLETE
IMMUTABLE_ARTIFACT_RUNTIME=INCOMPLETE
SUMMARY_V2_MIGRATION=INCOMPLETE
```

STOP。无变化不重扫，无部分实验，无 Guard 降级。
