# Trivy 磁盘 guard 隔离实验设计（未执行）

结论：**NOT_READY**。实验要求与 A–H 测量计划已完整定义；当前代理与封存 epoch 基线发生未归因差异，不能通过“代理未变”的保护检查。原 checkpoint 文件及其有界历史验收保持不变。本轮实验次数、生产刷新、release、rollout 均为 0。

本文件中的容量和压力参数仅为未来隔离实验预算，不是新 guard 提案。现有公式保持 `capacity × 15% + 12 GiB`。实际峰值尚未测得。

1. **frozen Trivy refresh path**

   {
     "entry": "release-preflight.mjs: preflight collect → assessPreflight → only productionCollection && assessment.ok calls ensureScannerDatabases(snapshot.scannerMetadata, scannerRefreshIO()). This round did NOT run preflight CLI because it can refresh.",
     "wrapper": "Loop db(schema2) then java-db(schema1). Invalid Version/UpdatedAt/DownloadedAt/NextUpdate rejects. Fresh NextUpdate skips. Expired → assertOwner → upstream → download → read → require fresh metadata, then final requireFreshScannerMetadata. No outer force flag.",
     "prerequisites": "platform-heavy Lease data-infra must be owned by HEAVY_HOLDER or jenkins-petclinic-BUILD_NUMBER; node devops stats nodefs AND imagefs must be fresh[-5s,+90s] and available >= capacity*.15+12GiB; ps must show no other trivy CLI. Both guards unchanged.",
     "upstream": "For each kind: GHCR anonymous scoped pull token → official /v2/aquasecurity/trivy-{db,java-db}/manifests/{2,1} → compute SHA256 of response and compare Docker-Content-Digest → require schema2/single layer/correct media type/sha256/0<size<=1610612736. Return ghcr.nju.edu.cn/aquasecurity/trivy-{kind}@official_manifest_digest; mirror content addressed; no Harbor write.",
     "commandTemplate": "kubectl -n harbor exec harbor-trivy-0 -c trivy -- sh -c [set -eu; umask077; random owned pidfile; exec env HTTP_PROXY= HTTPS_PROXY= ALL_PROXY= NO_PROXY=ghcr.nju.edu.cn PETCLINIC_DB_REFRESH_OWNER=<nonce> trivy image (--download-db-only | --download-java-db-only) (--db-repository | --java-db-repository) <mirror@digest> --cache-dir /home/scanner/.cache/trivy --timeout 3m --no-progress]",
     "cache": "/home/scanner/.cache/trivy/{db,java-db}; wrapper allows default path or /tmp/petclinic-db-check-[a-f0-9]+ only. Main experiment keeps default path and topology, not /tmp cache shortcut.",
     "controllerTemp": "fs.mkdtempSync(path.join(os.tmpdir(),clinic-db-manifest-)); curl headers saved here; finally fs.rmSync recursive force. Controller actual os.tmpdir/TMPDIR placement must be captured in future isolated runner, not assumed to be Harbor /tmp.",
     "containerTemp": "TMPDIR=UNSET in live pod; Go uses container default /tmp. Upstream v0.69.3 OCI path creates oci-download-* compressed layer then passes archive filename and destination to downloader. Exact nested go-getter temp names/allocation/rename calls must be traced in lab; not invented.",
     "replacement": "Same-version upstream downloader.Download removes destination (RemoveAll) before getter.Client.Get, with file getter Copy:true. No atomic old→new rename or rollback copy in inspected wrapper/upstream path. Destination may be absent or partially written after extraction error. Unknown nested dependency temp allocation is a future trace prerequisite, not a proven additional copy.",
     "oldRetention": "Old DB may coexist with full compressed archive before destination removal. It is not retained as a guaranteed backup after removal. Other-kind DB remains because wrapper is sequential. rollback_copy=0 unless observed, no new backup inserted inside measured path.",
     "cleanup": "upstream normal-return/error defer after file creation closes archive and removes oci-download temp. Failure before defer registration can leave temp directory; signal/kill need not run Go defers. Wrapper finally only stops same random-owner process, waits10 checks1s then removes pidfile; does not restore DB or guarantee cleaning archive/extraction. kube/stop failures themselves may interrupt finally. Freeze and observe all paths.",
     "proxy": "Official manifest curl tries PACKAGE_HTTPS_PROXY then direct fallback; download CLI explicitly clears HTTP_PROXY/HTTPS_PROXY/ALL_PROXY and sets NO_PROXY only mirror. Future isolated network must support this exact split. Do not point at mutable production v2rayN runtime.",
     "provenanceLimit": "Live version/image digest/binary SHA observed; inspected public v0.69.3 source corroborates expected behavior, not proof image was reproducibly built from tag. Future lab must use exact image and binary and trace actual operations. Four upstream sources fetched and hashed; two missing source files + go.mod explicitly unavailable via local fetch; operation.go was inspected using official web source. No complete dependency tree/build attestation claim."
   }

   Evidence: `frozen-path-reconstruction.json`

2. **frozen implementation hash**

   {
     "gitRevision": "741ea2866ea142b24c7838e1ef25c8327c79d279",
     "files": {
       "infra/observability/scanner-db-refresh.mjs": "6e49e8e3d79264e916f0c3c424181ab6e8d15342fcca24a811e3f78de89f306a",
       "infra/observability/release-preflight.mjs": "ed7fd6439bba1036937024c98228c61c6e1c088eceb9e12ae3543e946cbaefb7",
       "infra/observability/scanner-db-refresh.test.mjs": "ad0797c66bcbba7707934d3b78cde771d700913520fc59b544169e50ab754ef0",
       "infra/harbor/Dockerfile.trivy-arm64": "042cac5601807385ea2748d7370e9fce7b537cb2e9fc25c4a9844d5a4edeaf67"
     },
     "binarySha256": "d860265c7ebd8128c349d063c91e8f32b26b730d14c2ce85e187fef8be70d72d",
     "image": "192.168.1.58:30050/platform-repair/harbor-trivy-arm64@sha256:c7586c7d21d967a5c652827256f1b357761c4384f6b5c7e7f459dcbda01e2355",
     "version": "0.69.3",
     "sameSourceTagNotBinaryBuildProvenance": true,
     "existingImplementationFilesVerified": 77,
     "newEpochToolsVerified": 9,
     "frozenGateReferences": 455,
     "uniqueFrozenGateFiles": 229,
     "newEpochEvidenceFilesPreserved": 86
   }

   Evidence: `frozen-implementation.json`

3. **Trivy version**

   0.69.3; /usr/local/bin/trivy SHA256 d860265c7ebd8128c349d063c91e8f32b26b730d14c2ce85e187fef8be70d72d; production UID10000, same immutable image required

   Evidence: `live-tool-filesystem.stdout`

4. **DB sources**

   For each kind: GHCR anonymous scoped pull token → official /v2/aquasecurity/trivy-{db,java-db}/manifests/{2,1} → compute SHA256 of response and compare Docker-Content-Digest → require schema2/single layer/correct media type/sha256/0<size<=1610612736. Return ghcr.nju.edu.cn/aquasecurity/trivy-{kind}@official_manifest_digest; mirror content addressed; no Harbor write.

5. **cache paths**

   /home/scanner/.cache/trivy/{db,java-db}; wrapper allows default path or /tmp/petclinic-db-check-[a-f0-9]+ only. Main experiment keeps default path and topology, not /tmp cache shortcut.

6. **temp paths**

   fs.mkdtempSync(path.join(os.tmpdir(),clinic-db-manifest-)); curl headers saved here; finally fs.rmSync recursive force. Controller actual os.tmpdir/TMPDIR placement must be captured in future isolated runner, not assumed to be Harbor /tmp. TMPDIR=UNSET in live pod; Go uses container default /tmp. Upstream v0.69.3 OCI path creates oci-download-* compressed layer then passes archive filename and destination to downloader. Exact nested go-getter temp names/allocation/rename calls must be traced in lab; not invented.

7. **replacement behavior**

   Same-version upstream downloader.Download removes destination (RemoveAll) before getter.Client.Get, with file getter Copy:true. No atomic old→new rename or rollback copy in inspected wrapper/upstream path. Destination may be absent or partially written after extraction error. Unknown nested dependency temp allocation is a future trace prerequisite, not a proven additional copy. Old DB may coexist with full compressed archive before destination removal. It is not retained as a guaranteed backup after removal. Other-kind DB remains because wrapper is sequential. rollback_copy=0 unless observed, no new backup inserted inside measured path.

8. **failure cleanup behavior**

   upstream normal-return/error defer after file creation closes archive and removes oci-download temp. Failure before defer registration can leave temp directory; signal/kill need not run Go defers. Wrapper finally only stops same random-owner process, waits10 checks1s then removes pidfile; does not restore DB or guarantee cleaning archive/extraction. kube/stop failures themselves may interrupt finally. Freeze and observe all paths.

9. **isolation architecture**

   Disposable Linux arm64 VM on independent external backing; no prod kubeconfig, Secret, PVC, registry writes, PetClinic workloads, Lease or proxy. Isolated kube API with only lab harbor-trivy-0/harbor and platform-heavy/data-infra/devops stats identity, because frozen IO hardcodes these names. Exact immutable source copied read-only; record schema, imageID, binary hash, UID10000, Node version. DNS/network isolation must deny prod control plane/registry addresses before any execution. Only anonymous official GHCR read + digest-addressed mirror fetch allowed. No change to frozen hardcoded command sequence.

10. **filesystem equivalence matrix**

   [
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
   ]

11. **experiment disk sizing**

   {
     "units": "GiB=2^30 bytes",
     "productionFilesystemCapacityBytes": 270430261248,
     "currentFrozenGuardBytesCeil": 53449441076,
     "currentFrozenGuardGiB": 49.77867107391357,
     "currentAvailableGiB": 42.3257942199707,
     "guardFormulaUnchanged": "C*0.15 + 12GiB; 8GiB platform +4GiB DB refresh reserve",
     "labEnvelopeOnlyNotMeasuredPeak": {
       "OSAndToolImageGiB": 16,
       "existingPublicDBFixtureGiB": 4,
       "OCICompressedTwoKindsMaxGiB": 3,
       "extractionAndFailureWorkspaceGiB": 16,
       "observabilityOutsideDataFsGiB": 8,
       "additionalAboveGuardGiB": 8
     },
     "minimumIllustrativeDataFsGiB": 70,
     "minimumFormula": "C >= (B + 12GiB + above_guard_delta)/0.85 with B=OS/tool + seed + compressed + extraction allowance; illustrative B=39GiB gives C>=69.412GiB →70GiB filesystem. Recompute after authentic lab artifact expansion measurement; not a production guard proposal.",
     "primaryDesign": "Match measured filesystem capacity270430261248B on disposable258GiB virtual disk with production partition/features, not illustrative70GiB lab; guard then remains49.77867GiB. /tmp overlay + cache bind share same backing. Separate observer disk >=8GiB.",
     "physicalAllocation": "Use external dedicated storage, no creation on current constrained production Mac/APFS. Reserve at least full258GiB virtual disk physical backing +8GiB observer + measured snapshot/COW budget + host safety; planning floor300GiB usable with ONE active base and no snapshots. Snapshot/backup copies require additional proven unique-block budget, e.g. independent full backup adds258GiB. Sparse capacity is not free physical headroom.",
     "bounds": "Compressed layer <=1.5GiB each proven wrapper bound; decompressed size NOT bounded by that. The16GiB extraction allowance is planning-only. Future lab preflight must inspect authentic tar manifest/expansion and safe quotas before fill-to-band; if larger, recalc B/re-size external lab. No undersizing to force ENOSPC."
   }

12. **measurement tooling**

   {
     "baseline": [
       "timestamp UTC + monotonic_ns",
       "statvfs every distinct device: capacity, used/free/available, inode free",
       "df -B1/du -B1 (allocated) and du --apparent-size",
       "cache/db/java-db, overlay upper/work, controller manifest temp, /tmp, qcow2/APFS physical allocation",
       "DB checksum+metadata on isolated public seed only; block allocation st_blocks*512; device+inode"
     ],
     "fastSampler": {
       "periodMs": 10,
       "fields": [
         "monotonic_ns",
         "device",
         "f_blocks",
         "f_bfree",
         "f_bavail",
         "block_size",
         "inodesFree"
       ],
       "scheduler": "prestarted independent sampler on observer filesystem; record actual gaps, dropped samples, execution overhead; >50ms gap invalid unless event reconstruction bounds it"
     },
     "directorySampler": {
       "periodMs": 100,
       "method": "stat tracked files/inodes and allocation deltas from watcher events; full recursive du at start/end and >=1s cadence to avoid workload perturbation"
     },
     "eventTrace": "Lab-only trace ext4 block allocation/free, delayed-allocation reservations, truncate/unlink/open-close, overlay copy-up and process phase events. Observer buffers/logs outside measured filesystem; validate event accounting against statvfs and allocated-inode snapshots; track open-unlinked blocks. No eBPF privileges requested or installed this round.",
     "peakValidity": "10ms sampling alone is a lower bound, NOT exact true peak. Reconstruct filesystem allocation high-water incl transient created/deleted files from loss-free allocation/free trace and reservation accounting. Record trace counters and lost events. If kernel instrumentation cannot account for short-lived peaks, report SAMPLED_PEAK_LOWER_BOUND / PEAK_NOT_PROVEN, no guard decision or reduction; improve isolated instrumentation under future authorization. Do not use max(bytesWritten), apparent-size or before/after as allocation peak.",
     "formula": "per device: incremental_peak=max_t(available_before - available_t), absolute_peak_used=max_t(used_t); combined concurrency only for SAME instant and shared backing. Report f_bfree and f_bavail separately, safety reserves excluded from MEASURED_PEAK. Guest physical blocks, overlay and host qcow2 peaks reported independently without double counting.",
     "peakComponents": [
       "existing_db",
       "compressed_download",
       "extracted_new_db",
       "temporary_archive",
       "temporary_extraction",
       "old_db_retained",
       "rollback_copy",
       "filesystem_overhead",
       "container_overlay_overhead"
     ],
     "componentRules": "OCI compressed_download and temporary_archive may be the same inode: count once. old_db_retained is existing_db until deletion, not an additional copy. rollback_copy=0 unless observed implementation creates it (wrapper has none). extraction temporary path only if observed dependency uses it. Sequential db/java-db peaks not summed. Retained other-kind DB stays in baseline.",
     "failureCleanup": "Observe without manual cleanup; seal artifacts; destroy disposable lab only. Cleanup insufficiency is evidence, never patch frozen tool to make experiment pass.",
     "repeatability": ">=3 real successful full B refreshes with identical seed+new digest; A/C supplemental >=3 attempts. Each failure mode >=2 where reproducible, include TERM and KILL with different cleanup guarantees. Restore clean lab snapshot between runs outside measured window; 3 repeats per free-space band. Record min/max/median/population variance, every sample and censored run. Controlled changed-digest successor run if upstream changes, separate cohort, do not merge.",
     "labStop": "Abort owned updater if physical host budget exhausted, observer drops events, unexpected target/API/production address appears, unowned process exists, or device available <8GiB (lab emergency stop only, NOT new guard). Censored peak cannot support guard reduction; re-size external lab and repeat."
   }

13. **sampling interval**

   10ms statvfs +100ms tracked allocation snapshots +1s recursive reconciliation +loss-free events. Actual timestamps/gaps recorded. Sampled-only maximum is NOT exact peak; no guard classification if true peak cannot be bounded.

14. **peak-space metrics**

   per device: incremental_peak=max_t(available_before - available_t), absolute_peak_used=max_t(used_t); combined concurrency only for SAME instant and shared backing. Report f_bfree and f_bavail separately, safety reserves excluded from MEASURED_PEAK. Guest physical blocks, overlay and host qcow2 peaks reported independently without double counting. OCI compressed_download and temporary_archive may be the same inode: count once. old_db_retained is existing_db until deletion, not an additional copy. rollback_copy=0 unless observed implementation creates it (wrapper has none). extraction temporary path only if observed dependency uses it. Sequential db/java-db peaks not summed. Retained other-kind DB stays in baseline.

15. **test case A**

   {
     "case": "A",
     "name": "empty cache fresh download",
     "setup": "New lab cache. Full ensureScannerDatabases with missing/invalid metadata must reject SCANNER_METADATA_INVALID, NOT silently succeed. Separately label DOWNLOAD_SUBPATH: call unchanged IO assertOwner → upstream → download → read with valid pinned artifact in lab, then validate DB. Do not invent bootstrap wrapper support.",
     "trigger": "none",
     "expected": "Full wrapper prerequisite failure; download subpath success measured separately",
     "components": [
       "compressed OCI layer in /tmp",
       "new extracted DB in cache",
       "Java download sequential, db retained"
     ],
     "repeats": 3
   }

16. **test case B**

   {
     "case": "B",
     "name": "existing valid naturally expired DB → newer DB",
     "setup": "Use public historical DB + authentic metadata expired by NextUpdate and CLI recency window; seed both DB kinds on lab cache. Do not edit production metadata or fake freshness. Record seed checksum and new artifact digest.",
     "trigger": "normal frozen full wrapper",
     "expected": "Full current wrapper success, both DBs fresh and valid; exactly same bytes/commands/guard",
     "components": [
       "old DB until downloader replacement phase",
       "compressed layer",
       "new extracted DB",
       "unrefreshed other-kind DB",
       "overlay/temp allocations"
     ],
     "repeats": 3
   }

17. **test case C**

   {
     "case": "C",
     "name": "existing DB + explicitly requested refresh",
     "setup": "No force flag exists in frozen wrapper. Fresh DB full wrapper remains NO_ACTION and must be recorded. For forced attempt test frozen io.assertOwner → upstream → download on disposable lab only, labelled subpath. If CLI decides cache still fresh, NO_DOWNLOAD, not peak refresh success. For actual refresh use valid naturally expired seed; no trivy clean or forced flag added.",
     "trigger": "existing supported download subpath; guard still required",
     "expected": "Record genuine skip OR download. Count only actual download/extraction toward >=3 successful refreshes.",
     "components": [
       "existing valid DB",
       "compressed layer only if CLI downloads",
       "new extracted DB only if CLI updates"
     ],
     "repeats": 3
   }

18. **test case D**

   {
     "case": "D",
     "name": "interrupted download",
     "setup": "Pin official artifact, detect compressed archive growth and no extraction writes; apply lab-only egress cut scoped to lab process or owned SIGTERM. Network retry must not turn case into a success. Preserve wrapper timeout210s/CLI3m.",
     "trigger": "pause/drop at 25%,75% observed archive bytes; SIGTERM separately",
     "expected": "Nonzero error, ownership cleanup observed; record temp and old DB state rather than assuming cleanup",
     "components": [
       "old cache",
       "partial archive",
       "open deleted files"
     ],
     "repeats": 2
   }

19. **test case E**

   {
     "case": "E",
     "name": "interrupted extraction",
     "setup": "After complete compressed download, trigger owned SIGTERM on first new destination write and mid-extraction; confirm phase from filesystem events. Lab-only SIGKILL supplementary to expose deferred-cleanup loss.",
     "trigger": "owned lab process only; never pkill -f broad match",
     "expected": "Observe partial destination / missing old DB / leftover archive; any residue explicitly measured and isolated, no false rollback claim",
     "components": [
       "complete archive",
       "partial new extraction",
       "other-kind DB",
       "potential deleted-open blocks"
     ],
     "repeats": 2
   }

20. **test case F**

   {
     "case": "F",
     "name": "replacement/remove/copy failure",
     "setup": "Same image nonroot10000. On disposable destination use narrowly scoped permission deny before remove/write, or lab-only syscall fault injection at unlink/open/write; record exact errno and phase. No global remount or production RBAC change.",
     "trigger": "EACCES at actual supported destination operation. Rename-only fault NOT_APPLICABLE unless trace proves rename.",
     "expected": "Nonzero and faithful cleanup observations; do not pretend atomic rename exists",
     "components": [
       "existing destination if delete denied",
       "archive",
       "partial destination if later write fails"
     ],
     "repeats": 2
   }

21. **test case G**

   {
     "case": "G",
     "name": "cleanup after failure",
     "setup": "For every D/E/F keep the failed filesystem unchanged while measuring after exit, +1s,+10s,+60s. Check ownership pidfile, open deleted blocks, archives, cache/metadata and CLI absence. Then destroy isolated disk/snapshot only after evidence sealed.",
     "trigger": "no repair before evidence",
     "expected": "CLEAN or RESIDUE or OLD_DB_LOST/PARTIAL, never equate process cleanup to DB cleanup",
     "components": [
       "residual archive",
       "partial cache",
       "deleted-open files",
       "pidfile"
     ],
     "repeats": "all failures"
   }

22. **test case H**

   {
     "case": "H",
     "name": "guard rejection / near / above",
     "setup": "Use fully allocated lab filler, no sparse-only files, same guest capacity. Initial min(nodefsAvail,imagefsAvail) at ceil(G)-1GiB, ceil(G)-4KiB, ceil(G)+4KiB and ceil(G)+8GiB. Quiesce background writes; guard checks both fresh stats <=90s.",
     "trigger": "unchanged assertOwner, actual lab owned platform-heavy Lease, same stats API semantics",
     "expected": "Below guard rejected before manifest/download; near guard may race and reject (record), above allows only if all other checks pass. NO below-guard bypass to force DB execution.",
     "components": [
       "lab filler constant",
       "no download if rejected",
       "normal refresh if admitted"
     ],
     "repeats": 3
   }

23. **repeatability strategy**

   >=3 real successful full B refreshes with identical seed+new digest; A/C supplemental >=3 attempts. Each failure mode >=2 where reproducible, include TERM and KILL with different cleanup guarantees. Restore clean lab snapshot between runs outside measured window; 3 repeats per free-space band. Record min/max/median/population variance, every sample and censored run. Controlled changed-digest successor run if upstream changes, separate cohort, do not merge.

24. **proxy strategy**

   Prefer direct egress; independent validation-only proxy if required, no production proxy listener/runtime dependency. Production proxy was used only to GET four small public source files read-only this design round, not for a lab run; no state mutation. All future experimental routes must be isolated and logged sans credentials.

25. **credential strategy**

   Anonymous public token scoped repository pull only as frozen upstream uses. No production registry/age/SA secrets. Lab-only ephemeral Kube identity + Lease in isolated control plane; no prod RBAC writes. Redact Authorization/curl stdin/env, no set -x; secret references only. No credentials archived.

26. **evidence schema**

   future-evidence.schema.json; future real outputs required; no invented runs/results. Measurement confidence and absent truePeak remain explicit.

   Evidence: `future-evidence.schema.json`

27. **success criteria**

   [
     "exact image/binary/frozen wrapper/Node identity pinned and effective commands match",
     "same sources/digests/media types and applicable filesystem semantics",
     ">=3 actual full refreshes validated with real fresh metadata and DB readable by same Trivy (isolated offline known fixture scan); no production scan",
     "loss-free peak reconstruction OR explicitly NOT_PROVEN; no single-sample decision",
     "representative failure cleanup outcomes captured including residual bytes and DB loss",
     "repeatability stats and all evidence sealed; no silent discarded runs",
     "independent backing-space/backup safety assessed separately from guest peak; no production impact"
   ]

28. **future guard decision model**

   {
     "MEASURED_PEAK": "event-accounted high-water incremental allocation above authentic seed, per-device and physical host separately; no reserve hidden in peak",
     "SAFETY_MARGIN": "separate documented DB growth horizon, artifact size variability, failure residue, measurement uncertainty, concurrent controller/container writes; each quantified by evidence, no new number this iteration",
     "PLATFORM_RESERVE": "separate current8GiB plus capacity15% term as currently implemented; any future rationale must explain both, and avoid double-counting old cache",
     "GUARD_VALIDATED": "repeated supported worst-case peak + documented margins fits protection, confidence/coverage sufficient",
     "GUARD_CONSERVATIVE_BUT_JUSTIFIED": "material surplus justified by explicit growth/failure/concurrency/backing margins",
     "GUARD_REDUCTION_CANDIDATE": "only repeated loss-free evidence and complete failures show material excess after all margins; NOT approval to change",
     "GUARD_INSUFFICIENT": "peak/margins or safely observed failure exceed current protection; abort, no unsafe production proof",
     "NO_VERDICT": "missing source equivalence, censored peak, skipped failures or limited sampled lower bound → no classification"
   }

29. **change-control requirement**

   A future reduction candidate requires separate formula/number proposal, old/new risk, compatibility tests and explicit approval, versioned guard change, rollback to original sha/formula; no activation this round.

30. **checkpoint preservation**

   {
     "sealedCheckpointSha256": "a4c910144aee4d917345d27ad945a0b1ab2d6befc1eed3405ed7ccb4d19dabe1",
     "artifactMeaning": "Original epoch remains VERIFIED as historical bounded acceptance; latest proxy does NOT match, no live resume authorization",
     "oldCheckpoint": "FAILED",
     "historicalContinuity": "NOT_PROVEN",
     "filesPreserved": 86
   }

   Evidence: `checkpoint-preservation.json`, `proxy-current-delta.json`

31. **production protection**

   {
     "classification": "READ_ONLY_CURRENT_PROTECTION_CHECK",
     "jenkinsBuild": 270,
     "jenkinsResult": "SUCCESS",
     "v1Unchanged": true,
     "v1Sha256": "ec9ee51a06d4b9f61c6c0eaf50b374d1e25e6d3ca687908b7596d3a2c794f5d8",
     "checkpointArtifactIntegrity": "VERIFIED",
     "checkpointHistoricalAcceptance": "VERIFIED",
     "checkpointCurrentLiveStateMatch": false,
     "proxyUnchangedSinceEpoch": false,
     "proxyAgentWrites": 0,
     "proxyAgentRestarts": 0,
     "proxyWriterAttribution": "UNKNOWN",
     "trivyDBFileMetadataUnchanged": true,
     "trivyMetadataJsonBytesUnchanged": true,
     "fullDBChecksumRecomputed": false,
     "TrivyPodAndSpecUnchanged": true,
     "dojoSelectedMetadataAndIdentityUnchanged": true,
     "nodesReady": 3,
     "petclinicReady": 3,
     "HTTP": 200,
     "release": 0,
     "rollout": 0,
     "experimentRuns": 0,
     "productionDBRefreshes": 0,
     "productionImpact": "ZERO",
     "impactMeaning": "No production mutations by this work; externally observed proxy drift is NOT attributed or declared harmless"
   }

   Evidence: `production-protection.json`

32. **exact blockers**

   {
     "designAcceptance": "CURRENT_PROXY_BASELINE_MISMATCH: runtime hash/GUI+DB semantics/core identity changed; writer UNKNOWN. Never rewrite epoch or normalize drift.",
     "oldRaw": "b702ff16eae6f27f0cc84e11e59565b1dded8e2c197778f0b888297266593d62",
     "currentRaw": "e7be9244614003614b2e919a4f66008d05f55d610d731ea95e75897718d691d2",
     "observedAt": "2026-11-03T14:08:56.157075+00:00",
     "beforeExecution": [
       "independent external lab/physical backing and image read access not provisioned; this round prohibited execution",
       "source-tag to running-binary build relationship and nested extraction/rename behavior require exact-image lab trace; no substitution",
       "controller Node/temp and full mount/overlay features must be recorded and matched",
       "peak accounting instrumentation must be calibrated and prove no missed transient allocations"
     ],
     "overallRuntime": [
       "ENVIRONMENT_BLOCKED",
       "BLOCKED_BY_TRIVY"
     ]
   }

33. **TRIVY_GUARD_REVALIDATION_EXPERIMENT_DESIGN**

   NOT_READY: requirements/plans complete; current proxy-preservation check failed. No experiment readiness approval or new guard number.

34. **exact next permitted action**

   STOP. Present proxy delta for separately scoped read-only attribution/management decision; preserve original epoch. Future separately authorized isolated provisioning/preflight may validate source, filesystem and telemetry. No experiment, threshold change, DB refresh, Dojo work, COMPLETE, Summary V2, build/release/rollout now.

## 只读源码依据

公开同版本源码仅用于交叉核对，不能替代精确镜像运行取证。OCI 下载会先落压缩层临时文件，再调用 downloader；后者会先移除目标。失败后不能假设旧库可回滚。

[Trivy OCI artifact](https://github.com/aquasecurity/trivy/blob/v0.69.3/pkg/oci/artifact.go), [downloader](https://github.com/aquasecurity/trivy/blob/v0.69.3/pkg/downloader/download.go), [漏洞库客户端](https://github.com/aquasecurity/trivy/blob/v0.69.3/pkg/db/db.go), [Java DB](https://github.com/aquasecurity/trivy/blob/v0.69.3/pkg/javadb/client.go)。本地已获取四份公开源码和 SHA；其余获取失败详见 source-research 记录。

## Final verdicts

```text
TRIVY_GUARD_REVALIDATION_EXPERIMENT_DESIGN=NOT_READY
ISOLATED_ENVIRONMENT_REQUIREMENTS=COMPLETE
FILESYSTEM_EQUIVALENCE_REQUIREMENTS=COMPLETE
MEASUREMENT_PLAN=COMPLETE
FAILURE_CASE_PLAN=COMPLETE
REPEATABILITY_PLAN=COMPLETE
PRODUCTION_IMPACT=ZERO
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

STOP。
