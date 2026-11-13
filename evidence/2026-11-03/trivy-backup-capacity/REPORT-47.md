# 备份目标与宿主空间收口：47项验收

本轮只做实际存储/清理证据调查、纯防护测试及只读平台验收；capability保持13/16，compatibility2202未提升。读数有时间波动，执行前必须重新实测。无生产写入、无用户文件删除、无冷备份、无扩盘。

1. **backup destination inventory**：16个实际候选记录：11个宿主挂载、3个现有节点root、2个File Provider路径。无外置磁盘/USB存储、SMB共享或NFS挂载。现有SSH配置未识别其他独立备份服务器；不扫描、不索取新权限。逐项见destination-inventory.json。

2. **selected backup destination**：NONE；未接受任何目标。

3. **destination filesystem**：无选定目标。内部APFS共享container，伪FS不能存储备份；云端同步目录不是已验证独立挂载；remote node fs仅有容量stats，未验证格式/文件能力。

4. **destination free space**：无选定目标。宿主before 25.25 GiB；aliyun root约9.43GiB、ucloud约52.83GiB，不足本轮观测205GiB数据/完整复制方案。压缩可否适配未证实，不能以推定压缩比接受。devops root是源VM自身。

5. **destination suitability**：全部NO。没有目标具备空间、稳定挂载、大文件/稀疏往返、独立恢复读取和完整窗口可用证明。云同步完成/限额/离线恢复均未知；不把可写当适合。

6. **BACKUP_DESTINATION_READINESS**：NOT_READY

7. **host free before cleanup**：25.25 GiB（27117309952 bytes），APFS+df取较小值；purgeable不计。

8. **host safe reclaim candidates**：44项候选带path/size/owner/tool/last-use/reproducibility/current FD/project dependency/recovery/safe_delete证据。正容量候选均REVIEW_REQUIRED/RETAIN/UNKNOWN；Homebrew和Gradle为空，无可回收量。tier顺序明确，Tier4不执行。

9. **safe reclaim total**：SAFE_RECLAIM_TOTAL=0。Chrome/CloudKit/当前Codex日志不能按缓存名删除；Colima default停止不等于可丢弃；Documents内镜像、cache checkpoint、CI205/206归档为离线/回滚保留。22个归档均无重复/可丢弃证明。

10. **actual deleted host paths**：[]；未执行任何宿主用户文件删除，也未docker prune、colima delete、清空Trash或删镜像。

11. **actual reclaimed space**：0 bytes；free自然波动不记为清理收益。

12. **host free after cleanup**：未cleanup，audit后复测 25.21 GiB（27065999360 bytes）。仍比37GiB低约11.79GiB；preferred45–50GiB需更多。

13. **HOST_CAPACITY_READINESS**：NOT_READY；独立备份条件下+16预算37GiB（growth16+metadata1+temp4+hostreserve16），+32需53GiB；本地完整备份还另加约342.69GiB。

14. **HOST_RECLAMATION_EXECUTION**：INCOMPLETE；安全集不足则STOP在删除前，未将0次删除称为执行成功。

15. **selected backup format**：FULL_COLD_UTM_BUNDLE_COPY_PENDING_DESTINATION。A完整bundle、B盘+全部config/EFI、C稀疏、D无损压缩、Eclone/snapshot的logical/allocated/temp/metadata/空间/时长与依赖见backup-representation-models.json。

16. **backup consistency model**：计划clean shutdown后的完整静态bundle，不接受live copy。保守上限约342.69GiB；当前allocated约205.01GiB，若冷源/目标稀疏与恢复实证成立，可能采用约207.01GiB预算，尚未验证。压缩比/实际传输速度/停机时长未实测。

17. **source VM shutdown required**：YES，冷备份需要。实际shutdown=0，因为目标和容量前提未通过；不是缺少用户重复授权。

18. **image-released proof**：未取得：VM仍Running，当前QEMULauncher PID18121 / FD18 read-write。guard明确拒绝。source SEEK_DATA/HOLE只读普查133054区间完成，但期间mtime变化，不能当静止源/冷备证据。

19. **backup command/tool**：未执行。拟用现有rsync -aS --extended-attributes SOURCE_BUNDLE/ PRECREATED_EMPTY_BACKUP_BUNDLE/；具体目标先验证。无--delete、无转换、无网络下载依赖。

20. **backup bytes written**：0；本目录日志/报告写入不是backup bytes。

21. **backup path**：NONE；原bundle路径固定于RESTORE-AND-COLD-BACKUP-PLAN.md，不虚构备份目录。

22. **backup validation checks**：Backup exists=false；源停机/释放未成立；size/structure/config/hash/offline info/check=NOT_TESTED。尚无可检查备份，所以不执行qemu-img check；活动源仅info/OS extent metadata。

23. **BACKUP_VALIDATION**：INCOMPLETE

24. **restore procedure**：精确原路径、UUID、config/EFI绑定已记录；停止并无FD→有容量时保留坏副本→备份hash→恢复完整bundle→UTM附加/boot→hostname/root/kernel/network/k3s/Jenkins/Harbor/PetClinic/digest验收。不能覆盖当前VM做恢复实验。详见计划。

25. **restore validation method**：17项文档/guard断言通过，仅验证计划结构。当前无备份，OFFLINE_IMAGE_VALIDATED也未执行；隔离boot须全断网、新UUID/MAC、无共享生产写路径/卷，另需资源。原22+clone22+Colima2GiB超过32GiB宿主，不能并发尝试。

26. **RESTORE_VALIDATION_LEVEL**：NOT_VALIDATED

27. **RESTORE_READINESS**：NOT_READY；无可用备份及恢复暂存/验证，精确文档本身不代表恢复成功。

28. **original VM restart result**：NOT_REQUIRED_NOT_EXECUTED；原VM未关闭，仍持原UUID运行，config SHA3b10a9eb797dd8bad070a9b77f0f0d381303c7b4b20d2b1658f623371dcc1baf与前轮相同；无“重启即修复”结论。

29. **Jenkins health**：petclinic-ci #270 SUCCESS，building=false；validation #30 SUCCESS，所有API列出的build均idle。V1 summary SHA ec9ee51a06d4b9f61c6c0eaf50b374d1e25e6d3ca687908b7596d3a2c794f5d8 未变；未触发新build。

30. **Harbor health**：7/7 Pod Ready；只读GC历史均完成，replication为空；没有启动GC。Docker system df报告security-test Build Cache=0；单独builder du在已安装客户端不支持，未安装/修改工具。

31. **protected digests**：4/4 GET200，完整digest见registry-retention-final.json；current489cb821…、previous83c2ae78…、known-good#214 a8c03e46…、candidate2fbaea65…及其他保留依赖均未删除。

32. **K3s health**：当前采样devops/aliyun-worker/ucloud-worker均Ready，MemoryPressure/DiskPressure/PIDPressure=false；未重启/改配置。此为本轮健康快照，不宣称永久稳定性。

33. **PetClinic health**：3/3 Ready，UID/generation175/revision164与基线一致；保留Deployment/RS及业务数据，未改发布逻辑。

34. **HTTP 200**：YES；通过原Service clusterIP在现有节点实测HTTP200。

35. **VM_MAINTENANCE_READINESS**：NOT_READY；OFFLINE_EXPANSION_REQUIRED方案保留，无排它窗口、合适目标、容量与可恢复备份，不停机。

36. **BACKING_DISK_RESIZE_READINESS**：NOT_READY；无备份/恢复依赖。即便将来READY，本轮仍明确禁止resize。

37. **GUEST_PARTITION_GROW_READINESS**：READY仅指上一轮绑定几何与工具的步骤就绪；不是执行授权，当前parent仍258GiB无尾部空间。

38. **FILESYSTEM_GROW_READINESS**：READY仅指ext4/resize2fs步骤匹配。当前全局门禁未过，执行0。

39. **STORAGE_EXPANSION_READINESS**：NOT_READY

40. **disk resize count**：0；guest partition grow=0；filesystem grow=0。

41. **proxy modification count**：0

42. **Trivy DB refresh count**：0；Trivy runtime scan=0。

43. **Harbor image deletion count**：0；containerd镜像删除=0；HarborGC执行=0。

44. **release count**：0

45. **rollout count**：0

46. **exact blocker if still NOT_READY**：BACKUP_DESTINATION_READINESS=NOT_READY：无稳定、独立且已验证容量/大文件恢复的目标；HOST_CAPACITY_READINESS=NOT_READY：当前free约25.21GiB，缺约11.79GiB，SAFE_RECLAIM_TOTAL=0。因此备份/恢复未验证，维护和扩盘不能通过。

47. **exact next permitted action if STORAGE_EXPANSION_READINESS = READY**：当前未READY：先提供可合法使用的独立目标/已有存储挂载入口，并为至少约11.79GiB宿主清理量补精确可丢弃证明；可验证冷源与目标稀疏恢复以实证重算207GiB级预算，不用假设压缩比。若将来全部READY，唯一下一动作仍是报告并STOP；扩盘是下一轮独立变更，本轮不得执行，也不进入proxy/DB/Cosign/Dojo。

## Final verdicts

```json
{
  "BACKUP_DESTINATION_READINESS": "NOT_READY",
  "HOST_CAPACITY_READINESS": "NOT_READY",
  "HOST_RECLAMATION_EXECUTION": "INCOMPLETE",
  "BACKUP_READINESS": "NOT_READY",
  "BACKUP_VALIDATION": "INCOMPLETE",
  "RESTORE_READINESS": "NOT_READY",
  "RESTORE_VALIDATION_LEVEL": "NOT_VALIDATED",
  "VM_MAINTENANCE_READINESS": "NOT_READY",
  "BACKING_DISK_RESIZE_READINESS": "NOT_READY",
  "GUEST_PARTITION_GROW_READINESS": "READY",
  "FILESYSTEM_GROW_READINESS": "READY",
  "STORAGE_EXPANSION_READINESS": "NOT_READY",
  "STORAGE_EXPANSION_EXECUTION": "INCOMPLETE",
  "PROXY_REACHABILITY": "INCOMPLETE",
  "TRIVY_DB_REFRESH": "INCOMPLETE",
  "TRIVY_RUNTIME_FACT_CAPTURE": "INCOMPLETE",
  "REAL_RUNTIME_FACT_CAPTURE": "INCOMPLETE",
  "REAL_POLICY_OWNER": "INCOMPLETE",
  "IMMUTABLE_ARTIFACT_RUNTIME": "INCOMPLETE",
  "SUMMARY_V2_MIGRATION": "INCOMPLETE"
}
```

验证：Runtime154/154、Regression147/147、Policy core5/5、contract10/10、原pre-expansion guards30/30、新cleanup/destination guards24/24、restore-plan结构断言17项。后面三类是synthetic/文档防护验证，不能冒充真实备份/恢复。455个冻结引用（229唯一源码）及120/72/43/97文件先前seal均不变。

STOP：无足量safe deletion set，按条件停止在任何删除和关机前；不承诺依赖目前不存在的备份目标。
