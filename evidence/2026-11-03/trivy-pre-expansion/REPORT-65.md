# PRE-EXPANSION 最终验收（未扩容）

证据采样：2026-11-03 12:18–12:30 Asia/Shanghai，收口仅写本目录计划/测试/报告；采样不是未来写操作可复用的fresh证明。Runtime capability 13/16，compatibility2202均未提升。

1. **VM identity**：devops / 4C8DEDBC-D2FB-43F6-99EC-C2C6F9C1FF46，UTM 4.7.5，aarch64，6 CPU，22 GiB RAM。

2. **UTM bundle**：/Users/zhangsir/Library/Containers/com.utmapp.UTM/Data/Documents/devops.utm

3. **disk path**：/Users/zhangsir/Library/Containers/com.utmapp.UTM/Data/Documents/devops.utm/Data/450FFAC4-2D45-4A41-B8C7-76EDE35C4877.qcow2

4. **disk format**：qcow2 compat1.1，64KiB cluster。

5. **virtual size**：277025390592 bytes = 258 GiB。宿主文件逻辑长度 365810089984 bytes，不等于虚拟容量。

6. **allocated host size**：磁盘 204.98 GiB；bundle 204.98 GiB；活动文件会随写入变化。

7. **backing chain**：info --backing-chain 仅一层，无 backing parent。只读元数据，不等于离线完整性 check。

8. **snapshot state**：qcow2 info 无 snapshots；Data 卷无 snapshot，tmutil 无本地快照；根系统 sealed snapshot 不是 VM 备份。未证明 UTM4.7.5 可用的恢复型快照。

9. **active QEMU/image-use state**：QEMULauncher PID18121，磁盘 FD18 read/write，VM Running；无占用 guard 不通过。未 hash/check 活动整盘。

10. **host filesystem**：APFS disk3，physical disk0s2，Data disk3s5，container 460.43 GiB；container used 435.30 GiB，Data used 409.82 GiB，quota/reserve=0。

11. **authoritative host free space**：26980331520 bytes = 25.13 GiB；APFS 与 df 取较小实测值，同 container 挂载不相加。

12. **purgeable/non-guaranteed space**：purgeable 未单独报告，不计 guaranteed free；未用缓存、Trash 或 thin provisioned 空间冒充可用容量。

13. **largest host consumers**：Library≈265.85GiB（包含活动UTM约205GiB），code≈26.50GiB，Colima≈7.02GiB，Caches≈5.28GiB；嵌套项不叠加。CloudDocs/Google application data 保留。du 有权限缺口。

14. **safe host-reclaim candidates**：已有文件无已证实 SAFE_EPHEMERAL 删除集；浏览器/CloudKit缓存、Downloads、Trash、旧日志为 REVIEW_REQUIRED；活动 VM、源码/evidence、Colima RETAIN。详见 host-reclamation-plan.json。

15. **safe reclaim total**：0 bytes；未删除现有用户文件。自建64MiB临时稀疏实验文件已清理，不算回收旧文件。

16. **external storage inventory**：diskutil external 为空，无挂载 network backup；11个挂载逐项见 external-storage-inventory.json。/Volumes/Recovery 是同一内部 APFS，不是外盘。

17. **external backup suitability**：EXTERNAL_BACKUP_STORAGE=NOT_AVAILABLE；没有已验证、空间足够且能容纳单个巨大镜像的目标。

18. **+16 GiB total host requirement**：当前本地完整备份方案 379.69 GiB，预算后差额 -354.56 GiB；若另有独立外盘，宿主仍需37GiB，外盘另需 342.69 GiB。

19. **+32 GiB total host requirement**：当前本地完整备份方案 395.69 GiB，预算后差额 -370.56 GiB；独立外盘条件下宿主53GiB，外盘另需 342.69 GiB。

20. **HOST_FREE_REQUIRED_MINIMUM**：407687153688 bytes = 379.69 GiB，适用于当前无外盘拓扑的+16方案。

21. **HOST_FREE_REQUIRED_RECOMMENDED**：424867022872 bytes = 395.69 GiB，是+32比较预算，不代表已选择+32。若保留损坏副本并再暂存恢复，另须一份备份预算。

22. **selected expansion size**：NO_SAFE_EXPANSION_SIZE_CURRENTLY

23. **expansion rationale**：guest available≈43.20GiB，低于 frozen guard≈49.78GiB和preferred52；Harbor/DB缓存及扫描临时文件仍需增长空间。宿主25.13GiB不足任一含备份方案；不能只因thin resize即时写得少而批准。

24. **HOST_CAPACITY_READINESS**：NOT_READY

25. **selected backup strategy**：NONE_CURRENTLY_EXECUTABLE；未来优先 A+D：干净关机＋完整bundle复制至已验证独立外盘。A–F 的一致性、停机、空间、独立性、恢复与风险见 backup-strategy.json。

26. **backup consistency level**：实际备份 NONE。计划要求 guest clean shutdown + QEMU完全释放后静态复制；不接受活动 qcow2 copy。不能宣称当前已有application-consistent backup。

27. **backup required size**：367958706200 bytes = 342.69 GiB，bundle逻辑长度+2GiB余量；乐观稀疏分配下限也不适配当前可用容量。

28. **backup destination**：NONE；原VM路径已固定，具体备份/恢复暂存目标未具备，不虚构外盘。

29. **backup created**：NO；VM未关机，未复制生产镜像。

30. **backup validation**：未存在备份，故size/hash/metadata/offline check均未执行。64MiB copy fixture只验证同APFS工具，结果通过且已清理，不能当VM backup。

31. **BACKUP_READINESS**：NOT_READY；无容量/目标/可执行策略。已见构建空闲、GC完成、复制为空；手动registry/destructive maintenance无全局排它证明，不当作idle。

32. **BACKUP_VALIDATION**：INCOMPLETE

33. **restore procedure**：精确原bundle恢复顺序、EFI/config/identity、保留坏副本、启动及root/network/k3s/Jenkins/Harbor/PetClinic验收已写入 MAINTENANCE-RESTORE-RESIZE-PLAN.md。禁止覆盖当前VM测试恢复；执行路径尚未验证。

34. **RESTORE_VALIDATION_LEVEL**：NOT_VALIDATED；当前无备份，连备份 METADATA_ONLY 都不能声称。

35. **RESTORE_READINESS**：NOT_READY；备份和恢复暂存容量未验证。隔离clone需全断网/新UUID/MAC/无共享生产写卷；32GiB宿主不能同时承载22+22+2GiB再加OS。

36. **maintenance model**：OFFLINE_EXPANSION_REQUIRED；窗口包括暂停新任务、健康快照、干净关机、释放、备份/hash/check、增长、启动和健康恢复；时长未测，不承诺零停机。

37. **image-in-use guard**：Stopped＋fresh检查＋目标QEMU/QEMULauncher全退出＋无任意打开FD/写入者＋所有writer检查成功。缺证据、权限失败、Running或旧快照均ABORT；本轮BLOCKED。

38. **VM_MAINTENANCE_READINESS**：NOT_READY；容量/备份/恢复与排它维护窗口未满足，未启动停机。

39. **selected backing resize mechanism**：拟用完全停机后的 /opt/homebrew/bin/qemu-img resize -f qcow2；不是运行时扩盘，也不编辑plist替代扩盘。

40. **exact proposed resize procedure**：全8门禁通过后再次停机/无占用/备份终检→对精确磁盘执行唯一选定 +16G 或 +32G（命令见计划）→info→启动原VM→确认274或290GiB。当前没有选定尺寸，执行0；失败走冷备恢复，禁止缩盘回滚。

41. **BACKING_DISK_RESIZE_READINESS**：NOT_READY

42. **partition topology**：GPT vda258GiB/512Bsector；vda1 EFI2048–2203647；vda2 root2203648–541065182，最后分区已到最后usable sector；非LVM/MD。

43. **partition grow procedure**：更大backing已启动并见guest容量后，保存分区身份→growpart -N /dev/vda 2→核对start/EFI/GUID/type→growpart /dev/vda 2→确认内核新大小。未执行。

44. **GUEST_PARTITION_GROW_READINESS**：READY（独立工具/几何匹配的计划就绪；不代表现在允许执行，parent扩盘和全局门禁仍必需）。

45. **filesystem type**：ext4 /dev/vda2；工具resize2fs已存在。当前无24h匹配I/O/ext4错误；mounted needs_recovery是journal标志，不据此诊断损坏。

46. **filesystem grow procedure**：只有分区实际变大且无异常，sudo resize2fs /dev/vda2；不mkfs，不重建，不对挂载root做修复式fsck。未执行。

47. **FILESYSTEM_GROW_READINESS**：READY（独立步骤就绪；执行仍由全局门禁阻断）。

48. **STORAGE_EXPANSION_READINESS**：NOT_READY

49. **resize executed YES/NO**：NO；guest分区/文件系统增长也均0。

50. **post-expansion virtual disk size**：NOT_APPLICABLE（未扩容）；最近读取仍258GiB。

51. **post-expansion root filesystem size**：NOT_APPLICABLE；读取到的现状capacity270430261248 bytes≈251.86GiB，与分区容量不同。

52. **post-expansion available**：NOT_APPLICABLE；当前最近filesystem-state样本46387695616 bytes≈43.20GiB；不得当作扩容结果。

53. **STORAGE_EXPANSION_EXECUTION**：INCOMPLETE

54. **production Jenkins state**：petclinic-ci #270 SUCCESS / building=false，validation #30 SUCCESS；全jobs active=[]，未触发新构建；V1 summary SHA ec9ee51a06d4b9f61c6c0eaf50b374d1e25e6d3ca687908b7596d3a2c794f5d8 不变。

55. **Harbor state**：7/7 Pod Ready，未运行新GC、删除或维护。API旧GC为完成态；不据此承诺将来维护窗口已锁定。

56. **K3s/nodes**：最近只读取证3/3 Ready，Memory/Disk/PIDPressure=false；未重启k3s或节点。未把短暂快照称永久稳定。

57. **PetClinic**：3/3 Ready，业务HTTP200；UID/generation175/revision164与原基线一致，无发布。

58. **protected digest checks**：current489cb821…、immediate previous83c2ae78…、documented rollback a8c03e46…、candidate2fbaea65…均GET200，完整digest见registry-retention-final.json；保留其余RS历史与验证依赖。

59. **image deletion count**：0（Harbor和containerd镜像均未删）。

60. **proxy modification count**：0

61. **Trivy DB refresh count**：0；Trivy scan=0。

62. **release count**：0

63. **rollout count**：0

64. **exact blocking gate if NOT_READY**：HOST_CAPACITY不足且EXTERNAL_BACKUP_STORAGE不可用；BACKUP_READINESS未通过→BACKUP_VALIDATION INCOMPLETE→RESTORE_READINESS未通过；维护/扩盘因此NOT_READY。不是growpart/resize2fs缺失。

65. **exact next permitted action**：仅验证新可用独立备份目标，保守备份预算≥342.69GiB；同时把宿主实际free补足独立备份条件下+16至少37GiB（尚差约11.87GiB），再重新测算和建立独占维护窗口。也可先为明确的宿主可丢弃文件补引用/所有权证据，不能清理受保护VM、镜像、Colima、源码/evidence。所有条件再通过才执行备份→验证→恢复验证→扩盘。到此STOP。

## Final verdicts

```json
{
  "HOST_CAPACITY_READINESS": "NOT_READY",
  "BACKUP_READINESS": "NOT_READY",
  "BACKUP_VALIDATION": "INCOMPLETE",
  "RESTORE_READINESS": "NOT_READY",
  "VM_MAINTENANCE_READINESS": "NOT_READY",
  "BACKING_DISK_RESIZE_READINESS": "NOT_READY",
  "GUEST_PARTITION_GROW_READINESS": "READY",
  "FILESYSTEM_GROW_READINESS": "READY",
  "EXTERNAL_BACKUP_STORAGE": "NOT_AVAILABLE",
  "RESTORE_VALIDATION_LEVEL": "NOT_VALIDATED",
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

验证：Runtime154/154、Regression147/147、Policy core5/5、contract10/10、pure guard30/30；恢复文档/guard断言21项。最后两类不是VM备份或恢复执行。冻结源码455个引用（229个唯一文件）及此前120,72,43文件seal全部不变。

参考机制：[QEMU qemu-img](https://www.qemu.org/docs/master/tools/qemu-img.html)、[UTM Resize](https://docs.getutm.app/settings-qemu/drive/resize-and-compress/)；本机实际证据优先，在线文档不证明安装版本的快照/在线扩盘能力。
