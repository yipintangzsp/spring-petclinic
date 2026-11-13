# 14/16 checkpoint 与 Trivy disk guard 只读复核

Checkpoint字节/来源完整性验证通过，但本轮权威checkpoint验收FAILED：只读采样间发现代理配置内容变化，原因未知。候选数据保留，恢复门关闭。

49.78GiB来源是filesystem capacity×15%+12GiB，包含平台原15%+8GiB与刷新额外4GiB。来源确定，当前实际刷新峰值未证明；guard未修改。

1. **checkpoint path** — checkpoint.json（保留为失败候选，未提升权威）；checkpoint-digest.json为字节锚；verify-checkpoint.mjs可复查。文件/回执完整性VERIFIED，但权威checkpoint验收FAILED，原因是代理保护检查未通过。

2. **checkpoint git revision** — 741ea2866ea142b24c7838e1ef25c8327c79d279，分支fix/security-manager-plugin-switches。工作区既有修改/未跟踪实现保留，77个实现文件hash补充Git SHA无法覆盖的内容。

3. **canonical source count** — 16。canonical inventory hash、collector/owner/projection/authoritative owner及Policy baseline全部记录，未删除Trivy/Dojo。

4. **verified/wired count** — 14/16 accepted for runtime wiring，原始bindings未重绑。Provenance / Build Provenance保留原SKIPPED函数返回分支证明，不宣称其enabled签名分支已实跑；Sonar负例债务DEFERRED_REAL_NEGATIVE_EVIDENCE不变。

5. **blocked sources** — Trivy为ENVIRONMENT_BLOCKED；DefectDojo经mandatory Trivy输入传递阻塞。额外checkpoint保护阻塞：UNEXPLAINED_PROXY_CONFIG_DRIFT。

6. **Trivy blocker receipt** — receipts/trivy/engineering-receipt.json复制原工程回执并记录原hash；宿主free25.21GiB/host guard37GiB为上一轮观察，不冒充本轮宿主新采样。guest刷新49.78GiB是另一约束。没有变成ResolvedPolicyResult。

7. **Dojo dependency receipt** — receipts/defectdojo/engineering-receipt.json，保留TRIVY_HARD_DEPENDENCY / BLOCKED_BY_TRIVY；真实owner评价0，没有Policy PASS/WARN/FAIL替代阻塞。

8. **Cosign verified receipt** — ../runtime-independent-boundaries/cosign-source-receipt.json，#32 SUCCESS、旧Gate=Policy=PASS、evaluation1、resultDigest=GateInputDigest=c7dbafbf7cf496456c872297eedcf800cebf110073793ad02ebfda70842de2b1。独立复制result/capture/gate到receipts/cosign，私钥/权限清理证据仍在原封存中。

9. **49.78 GiB guard source file** — infra/observability/scanner-db-refresh.mjs；本地与线上活动helper SHA256均6e49e8e3d79264e916f0c3c424181ab6e8d15342fcca24a811e3f78de89f306a。

10. **guard line/function** — scannerRefreshIO().assertOwner()，第68–72行，关键表达式第71行；node.fs、node.runtime.imageFs各自检查，不把两者相加。Lease与采样时效也必须通过。

11. **guard introduction/history** — 8028e55fd5e1120acd833770dc1bd0611dd4d641于2026-10-23首次引入refresh helper及12GiB表达式；base 15%+8GiB在11e1b1b8f95eb028b7ff070fa2bd1b462fecd0fa（2026-10-21）引入；5e301a36只修改official route fallback，没有改阈值。Git show/log/blame均保存。

12. **guard classification** — CALCULATED_FROM_FILESYSTEM_STATE。15%是比例项、12GiB为静态项；不是49.78固定常量，也不按download或DB大小计算。33处相关位置记录于guard-reference-locations.json。

13. **original formula** — required = stats.capacityBytes * 0.15 + 12 * 1024**3 = capacity*15% + base8GiB + refresh4GiB。没有增加或改写任何原项。

14. **formula inputs** — 当前capacity=270430261248B（251.85780716GiB）；比例0.15；8GiB=8589934592B；4GiB=4294967296B；合计12GiB=12884901888B。availableBytes只参与比较，manifest/SQL/extracted size不参与公式。

15. **current DB/cache sizes** — db/trivy.db=1666846720B；java-db/trivy-java.db=1564942336B；两者logical总=3231789056B（3.009838GiB）。两份metadata各153B；cache du=3243958272B（3.021172GiB），含Fanal。

16. **current artifact/manifest sizes** — 最近本地正式manifest观察（2026-11-03，未重新请求upstream）DB压缩layer137873295B、Java994006717B；各digest见current-artifact-sizes.json。新upstream是否仍相同UNKNOWN，当前新payload解压大小UNKNOWN。另现存Oct11 archive为126923263/981758967B，tar头解压文件总1467543694/1550987407B；明确为历史，不当作当前size。

17. **temporary-object sizes** — 观察时scanner /tmp分配4KiB，没有匹配的trivy/javadb/petclinic-db临时对象；这不是refresh峰值0。Jenkins manifest/token/header临时目录和CLI下载/解压峰值均UNKNOWN；本轮没有创建真实download对象。

18. **coexistence model** — helper依次await db、java-db，先完成一个再开始另一个。upstream manifest临时目录在返回前finally移除，之后才download；不盲加其完整占用到download峰值。已占用的旧DB已经体现在初始used中，free预算不能重复加。CLI内部新压缩包、解压DB、旧DB/rename/copy具体共存未获证明。

19. **PEAK_SPACE_COMPONENTS** — peak-space-model.json逐项区分：已有两库/Fanal、manifest临时文件、当前kind压缩payload、新提取库、旧活动库/安装临时对象、overlay/fs开销和背景增长。已测字节与UNKNOWN分开；两个刷新阶段取真实共存最大值，不直接相加两个独立峰值。

20. **PEAK_EXPECTED_BYTES** — null / UNKNOWN。缺冻结CLI内部提取与替换生命周期、当前未压缩payload尺寸、实际高频峰值；不编造一个数字，也不把cache逻辑大小当额外free需求。

21. **filesystem/mount path** — 实际cache=/home/scanner/.cache/trivy，父目录挂载PVC data-harbor-trivy-0，local-path PV位于devops /var/lib/rancher/k3s/storage/pvc-262fbaec-19cb-49dd-b8e2-fd2be46ab2d7_harbor_data-harbor-trivy-0。声明5Gi，未证明其有硬quota；底层/dev/vda2 ext4与nodefs同容量。

22. **filesystem semantics** — DB在PVC bind mount，容器/tmp在overlay；两者共享devops物理文件系统但不是相同挂载视图。当前Fanal逻辑16MiB/分配约11.57MiB呈稀疏差异；不能假定所有logical size等于块占用。同文件系统rename才具备相应atomic语义；CLI temp路径/copy fallback未知。此helper不会docker pull/build或上传本地registry，不加入这些不存在的写入。UTM qcow2/APFS的host容量/COW/backup仍是独立限制。

23. **safety margin bytes** — 平台base reserve=49154473779.2B，包含15% capacity+8GiB；刷新额外allowance=4294967296B（4GiB）。相对真实peak的margin bytes无法计算，不能以当前DB占用直接相减。

24. **safety margin origin** — CODE_DEFINED，且base停止线有DOCUMENTED_POLICY：RECOVERY-20261021.md:24解释旧固定8GiB不能保护约244GiB根盘；ANALYTICS-E2E-20261024.md:60明确DB另留4GiB。没有找到4GiB来自当前真实峰值测量的推导，不能伪称INCIDENT_DERIVED精确4GiB。

25. **historical refresh observations** — Oct18/19漏洞DB、Oct18/22 Java库有real成功warm日志、metadata和稀疏资源采样。经本地registry warm，与本轮冻结official→mirror helper不是完全同架构。Oct22三样本free59550.41→58803.39→57838.71MiB，差1711.70MiB；Oct18 Java差2671.95MiB。DERIVED差值含全盘背景，不是精确刷新峰值。Nov3有磁盘guard拒绝和proxy TCP refusal失败证据。

26. **measured historical peak if available** — UNKNOWN。保留成功时间、compressed artifact大小和采样序列；不从少量free-before/after虚构中间peak。

27. **current guard bytes** — 原Number表达式=53449441075.2B；整数available最低passing=53449441076B；49.77867107391GiB显示为49.78GiB，不能把显示round值写回阈值。

28. **guard vs reconstructed peak** — 公式明确包含平台保留余量，而不是纯DB payload预算。raw peak仍UNKNOWN，无法定量证明4GiB临时预留覆盖当前提取/替换，也无法宣称49.78GiB“过大可删”。当前guest free约42.8GiB仍不满足原guard。

29. **TRIVY_DISK_GUARD_VALIDITY** — GUARD_REQUIRES_REVALIDATION。来源已证明，因此不是GUARD_ORIGIN_UNPROVEN；但没有完整peak证据，不能标GUARD_VALIDATED、CONSERVATIVE_BUT_JUSTIFIED或INSUFFICIENT。

30. **TRIVY_DISK_GUARD_REVALIDATION_REQUIRED** — YES。当前guard保持原值，newApprovedGuard=null。

31. **future controlled revalidation plan** — FUTURE-GUARD-REVALIDATION-PLAN.md：独立备份容量充分的可销毁VM/副本，固定同代码/镜像/路径/文件系统/原guard，真实测free/used/download/extract/共存/peak/final/失败cleanup及atomic行为。先核对冻结版本CLI源码，分db/java/串行，隔离故障验证。仅计划，未创建或执行环境。

32. **alternate-storage changes performed** — 0。没有tmpfs、RAM disk、扩容、迁移PVC/cache、改变底层存储或新增常驻组件。

33. **threshold changes performed** — 0。formula、Policy、freshness与Gate未改，原阈值继续生效。

34. **DB-path changes performed** — 0。仍/home/scanner/.cache/trivy。

35. **Trivy refresh count** — 0。新manifest/HEAD/blob下载请求0；只读使用本地已存在manifest/tar metadata和现存缓存元数据。无真实Trivy执行/扫描，无网络资源写，无磁盘清理。

36. **Dojo dependency frozen evidence** — governance/defectdojo.mjs:8无条件Trivy报告校验，:14才进入import；policy/dojo-parent.mjs:15相同条件；active petclinic adapter指向该父阶段。通用manager/tool可选分支未实施。

37. **DOJO_DECOUPLING_REQUIRED** — YES，仍属未来Summary V2 / Plugin Contract之后的独立阶段。

38. **future coupling debt** — 当前Trivy私有native路径/顺序→defectdojo.mjs→Dojo import；未来Scanner plugins→Manager→normalized reports/results→Result Router→Dojo。只冻结债务，不重构当前代码。

39. **runtime tests** — 154/154＝runtime143/143＋受控完整性负例11/11。没有新真实runtime接线。

40. **candidate tests** — 40/40，在disposable checkout执行，旧证据保留。

41. **Policy core** — 5/5。

42. **contract checks** — 10/10。

43. **Regression 147/147** — 147/147本地通过，没有触发新Jenkins构建。

44. **guard tests** — 10/10，实际assertOwner代码在内存I/O中验证公式、ceil字节边界、双fs独立检查、采样过期/未来、失败前无下载。首轮仅派生差值的严格float相等断言遇亚字节误差，已保留attempt-1日志，改用该派生差值<1B误差断言；生产guard及精确byte边界测试未变。

45. **checkpoint integrity** — 文件与原始回执完整性VERIFIED，当前校验380处hash；checkpoint测试12/12含代理漂移不能提升权威状态。verify-checkpoint CLI按设计exit2，status=FAILED、integrityStatus=VERIFIED；恢复门false。

46. **source/hash preservation** — 77份实现hash、455冻结引用/229unique文件全部一致；9个旧封存目录671文件校验无失败；compatibility样本2202不变。线上helper/preflight与本地一致，活动V1 manager与本地版本差异已明确记录，未混同。

47. **production Jenkins state** — petclinic-ci最新仍#270 SUCCESS，专用job最新#33 SUCCESS；#32/#33在线归档hash和job definition与原封存一致，新构建0。

48. **V1 state** — V1 active，Summary SHA ec9ee51a06d4b9f61c6c0eaf50b374d1e25e6d3ca687908b7596d3a2c794f5d8不变，producer038320f0…、baseline02c3f549…未变。未启用V2。

49. **nodes state** — devops / aliyun-worker / ucloud-worker均Ready。Trivy Pod/PVC、StatefulSet spec、container env hash、磁盘capacity前后不变；DB文件size/blocks/inode/mtime与metadata hash前后相同，不虚构新的全库内容checksum。

50. **PetClinic state** — 3/3、3Ready Endpoint、HTTP200，Deployment generation175/revision164/spec不变，Argo Synced/Healthy及同GitOps revision；Dojo2产品/2 engagement/35test/6627finding元数据前后相同。代理保护检查失败：v2rayN config bytes/hash在观察期间变更，原因未知；本轮agent写入0，未恢复或调整。

51. **release count** — 0。

52. **rollout count** — 0。

53. **RUNTIME_14_OF_16_CHECKPOINT** — FAILED

54. **TRIVY_DISK_GUARD_ORIGIN** — CALCULATED_FROM_FILESYSTEM_STATE

55. **TRIVY_DISK_GUARD_VALIDITY** — GUARD_REQUIRES_REVALIDATION

56. **TRIVY_DISK_GUARD_REVALIDATION_REQUIRED** — YES

57. **TRIVY_STORAGE_ENVIRONMENT** — ENVIRONMENT_BLOCKED

58. **TRIVY_RUNTIME_FACT_CAPTURE** — INCOMPLETE

59. **DEFECTDOJO_RUNTIME_DEPENDENCY** — BLOCKED_BY_TRIVY

60. **DEFECTDOJO_RUNTIME_FACT_CAPTURE** — INCOMPLETE

61. **COSIGN_RUNTIME_FACT_CAPTURE** — VERIFIED

62. **FINAL_WIRED_CAPABILITY** — 14/16

63. **REAL_RUNTIME_FACT_CAPTURE** — INCOMPLETE

64. **REAL_POLICY_OWNER** — INCOMPLETE

65. **IMMUTABLE_ARTIFACT_RUNTIME** — INCOMPLETE

66. **SUMMARY_V2_MIGRATION** — INCOMPLETE

67. **exact blocker** — Checkpoint权威验收：UNEXPLAINED_PROXY_CONFIG_DRIFT，前hash e3c322ce…/6648B，后b702ff16…/6306B，发生于只读观察窗口；原因未确定，agent未写。Guard峰值：当前未压缩payload/CLI安装共存/实际高频峰值未证明；Trivy仍缺独立容量/backup，Dojo仍被Trivy传递阻塞。

68. **exact next permitted action** — STOP。下一轮先以独立授权的只读取证确认代理变化来源与可信基线，再重新验收/生成权威checkpoint；guard受控峰值复验按计划另行批准，未批准前保留原guard，不刷新DB或继续runtime/Summary/Router。

```text
RUNTIME_14_OF_16_CHECKPOINT = FAILED
TRIVY_DISK_GUARD_ORIGIN = CALCULATED_FROM_FILESYSTEM_STATE
TRIVY_DISK_GUARD_VALIDITY = GUARD_REQUIRES_REVALIDATION
TRIVY_DISK_GUARD_REVALIDATION_REQUIRED = YES
TRIVY_STORAGE_ENVIRONMENT = ENVIRONMENT_BLOCKED
TRIVY_RUNTIME_FACT_CAPTURE = INCOMPLETE
DEFECTDOJO_RUNTIME_DEPENDENCY = BLOCKED_BY_TRIVY
DEFECTDOJO_RUNTIME_FACT_CAPTURE = INCOMPLETE
COSIGN_RUNTIME_FACT_CAPTURE = VERIFIED
FINAL_WIRED_CAPABILITY = 14/16
REAL_RUNTIME_FACT_CAPTURE = INCOMPLETE
REAL_POLICY_OWNER = INCOMPLETE
IMMUTABLE_ARTIFACT_RUNTIME = INCOMPLETE
SUMMARY_V2_MIGRATION = INCOMPLETE
```

STOP。
