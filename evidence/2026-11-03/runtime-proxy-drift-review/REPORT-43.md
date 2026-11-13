# v2rayN 漂移只读取证与 checkpoint 收口报告

结论：UNEXPLAINED / 语义 UNKNOWN / checkpoint FAILED，保持14/16，不允许恢复闸门打开。

1. **changed v2rayN file** — `/Users/zhangsir/Library/Application Support/v2rayN/binConfigs/config.json`。旧 checkpoint 的 v2rayN hash 集合只有这一文件。当前 inode=51467903，owner/group=zhangsir:staff，权限=-rw-r--r--；旧 inode/owner/mode 未记录，不能补猜。

2. **old hash** — e3c322ce52c284ac77450781fce9ed71fe0711e52d62550d076059956e054452

3. **new hash** — b702ff16eae6f27f0cc84e11e59565b1dded8e2c197778f0b888297266593d62

4. **old/new size** — 6648 → 6306 bytes，减少 342 bytes。

5. **old/new mtime** — 旧 2026-11-03T09:17:03.478948293Z（本地17:17:03）；新 09:20:28.424101798Z（本地17:20:28）。精确 mtimeNs 分别为1793697423478948293、1793697628424101798。

6. **byte-level diff** — 不可取得：旧轮仅封存 hash/size/mtime，没有旧内容；12个有界候选文件检索没有匹配旧 hash 的副本。不能输出虚构文本 diff。

7. **semantic diff** — UNKNOWN。无法列出旧→新字段变化，不能判为排序、时间戳、运行状态或订阅元数据变化。

8. **likely writer** — v2rayN GUI 的运行配置生成器是最有依据的候选，但历史实际写入者=UNKNOWN，触发原因=UNKNOWN。

9. **writer evidence** — GUI PID84672（10:53:57启动）；主 xray PID6529、PPID84672（17:20:28启动），相对 config.json 与 binConfigs cwd 对齐新 mtime。596条已脱敏 unified log、应用日志窗口只显示17:17:08 WindowClosing和相关GUI活动，没有文件写入审计。窗口关闭不等于GUI进程退出。7.20.4官方源码证明GUI具备生成/写入能力，不证明本次历史动作。其余约29个旧孤立 xray 只记录、不清理。

10. **automatic refresh settings** — 全局 AutoUpdateInterval=0；8个订阅 Enabled=1、AutoUpdateInterval=0、UpdateTime=0。EnableStatistics/DisplayRealTimeSpeed/MsgUI.AutoRefresh=true；Clash Proxies/ConnectionsAutoRefresh=false。SpeedTestTimeout=30、并发10，未确认自动测速计划。发现现有1800秒 launch agent 与 managed YAML helper，但本轮未执行；helper日志不存在，launchctl查询不可用，不能证明发生过刷新。GUI源文件同字节替换已观察到，具体保存周期/写入者未证明。

11. **source vs generated** — 变化文件=GENERATED_RUNTIME_CONFIG。guiNConfig.json + guiNDB.db 的选择/节点/路由配置 → GUI生成 → binConfigs/config.json → 主xray读取。不是单纯GUI窗口状态文件，也不是可随意忽略的缓存。

12. **active listener before/current** — 历史仅能证明10808回环代理可访问、LAN路径失败；当前主xray监听127.0.0.1:10808及127.0.0.1:10812，生成配置的mixed inbound=10808、noauth、无accounts、AllowLAN=false。10812历史基线缺失，不能称其新增或未变；本轮未重放外部代理请求，不宣称完整行为等价。

13. **active routing semantics** — 当前生成配置 domainStrategy=AsIs；rules digest=76459c502bb82beace2b0c149df853c67a146ea70b3ca89003a6e5d1b9bbc912。proxy outbound protocol=vmess，另有freedom/blackhole；节点/订阅身份只记录摘要，不导出地址或凭据。AsIs不等于已证明所有GUI路由模式。旧上游/路由完整语义缺失。

14. **PROXY_RUNTIME_SEMANTICS_CHANGED** — UNKNOWN。当前回环10808仍存在，但无法证明旧、新整个代理语义相同。

15. **V2RAYN_DRIFT_CLASS** — UNEXPLAINED。不能将时间相关性提升为EXPECTED_RUNTIME_REWRITE。

16. **checkpoint hash contract problem** — 把自然可再生成且带安全语义的配置字节当作稳定用户源配置，会把正常生成与危险语义变更混在一起；但当前漂移不能据此豁免。REQUIRES_SEMANTIC_NORMALIZATION仅为设计结论，不是已启用规则。

17. **files classified immutable** — 批准的checkpoint manifest/validator/helper及固定二进制可作为候选；没有现有v2rayN用户配置被证明不可变。本轮未新增不可变合同文件或二进制验收。

18. **files classified semantic-mutable** — guiNConfig.json、guiNDB.db中被选中的Profile/路由/订阅记录，现有helper目标grok-managed.yaml。完整分类见proxy-source-runtime-map.json。

19. **files classified runtime-generated** — binConfigs/config.json（安全相关，必须保持语义保护）；源码中的configTest*.json是测速生成物，不能和主配置混淆。

20. **files classified volatile** — guiLogs、GUI/统计状态、测速临时输出等候选；不是本轮已批准的hash排除集合。GUI源文件部分字段可能有安全语义，禁止整个GUI文件泛化为无关状态。

21. **proposed semantic fields** — 全inbound、地址、端口、LAN、协议/auth/accounts、sniffing；路由模式与规则顺序；outbound目标/凭据受保护摘要、transport/TLS/security、链式代理、选择；DNS、mux、相关开关、订阅源与实际运行进程绑定。未知字段默认保留。

22. **excluded volatile fields** — 无。分析代码保留全部字段，包括未知timestamp/counter；只排序JSON对象键，保留数组顺序，拒绝重复键和非有限数。

23. **exclusion rationale** — 没有证据支持字段级豁免，因此不排除。格式/对象顺序只在受控副本验证分析等价，不作为旧历史漂移的解释；没有将文件从正式保护集合移除。

24. **bounded stability observations** — T0 2026-11-03T09:42:56.492109+00:00；T1 2026-11-03T09:44:06.322661+00:00；T2 2026-11-03T11:33:02.069604+00:00；T3 2026-11-03T11:34:43.935101+00:00。跨度6707.443秒，工作/继续执行期间的4次稀疏诊断采样，不是连续观测或新的验收窗口，没有为等待稳定设置sleep。

25. **semantic digest stability** — 运行配置 raw SHA、size、mtime、inode及全字段分析digest在4样本均稳定；GUI配置raw SHA/全字段digest稳定，但mtime/inode改变。运行分析digest=15105ccffd415778f548c0db2ddec6cc0fabc2edfd28318ad36317e7a73d7853；GUI=a76c836622e0dc4750283f2e3ae75cf8b9d56591f99e29f6c4291a56e6b34c63。未证明覆盖自动刷新执行，不填补旧语义基线。

26. **checkpoint implementation changes** — 0。只新增本轮证据、设计和受控副本测试。旧checkpoint/verifier字节保留，没有重建或重新验收14/16 checkpoint，没有接线新contract。

27. **negative checkpoint tests** — 6类受控变更：listener、port、LAN、route、outbound identity、security flag均被严格字节合同与分析digest检测。只改内存synthetic fixture，未改活配置；不是新语义validator的生产验收。

28. **proxy checkpoint tests** — 8/8 PASS：6类strict byte负例、空白变化仍拒绝、旧FAILED checkpoint继续禁止恢复。语义分析12/12 PASS（ANALYSIS_ONLY）；无“容忍已证明良性历史漂移”的新规则。

29. **runtime tests** — 143/143 PASS；另有隔离副本completeness-negative 11/11，合计154/154。不是16源真实runtime完成证明。

30. **candidate tests** — 40/40 PASS；使用一次性checkout，执行完成已清理。

31. **Policy core** — 5/5 PASS。default standard / explicit low / strict / overrides / POLICY_ERROR语义未改。

32. **contract checks** — 10/10 PASS。

33. **Regression 147/147** — 147/147 PASS；既有本地fixture需要loopback，仅本地测试执行获授权，不触发Jenkins或发布。

34. **source/hash preservation** — 455引用/229唯一冻结文件、77实现文件及10组811个旧封存证据文件全部hash一致。Policy兼容计数2202未增加；旧checkpoint完整性12/12 PASS，仍FAILED。初次报告聚合误要求GUI元数据恒定，现改为如实分字段报告，原样本保留，见validation-adjustment.json；未改生产Gate。

35. **RUNTIME_14_OF_16_CHECKPOINT** — FAILED，recovery/resume gate CLOSED。没有因本地388项检查通过而提升runtime状态。

36. **exact blocker** — 缺失与旧hash e3c322…一致的旧内容或足够完整的可信旧语义快照；缺失历史写入者/触发事件证据。故不能证明语义未变，不能重新验收。

37. **production Jenkins state** — petclinic-ci最新#270 SUCCESS，未触发新build；验证任务仍#33，Cosign #32/#33已归档hash及任务定义未变。

38. **V1 state** — V1仍active，Summary SHA=ec9ee51a06d4b9f61c6c0eaf50b374d1e25e6d3ca687908b7596d3a2c794f5d8。生产manager SHA=6854436a43b347fc94e895eada0b2048be238668817a4af33a228396f1c57c32，本地现有manager含未部署可选开关，与线上差异是已知基线，本轮均未改。

39. **nodes state** — aliyun-worker/devops/ucloud-worker均Ready；这里只读瞬时核验，不冒称持续节点HA演练。

40. **PetClinic state** — 3/3 Ready、3个Ready Endpoint、HTTP200；Deployment generation175/revision164、spec及Argo应用spec/revision保持，Argo Synced/Healthy；Harbor7个Pod Ready。

41. **release count** — 0。

42. **rollout count** — 0。

43. **exact next permitted action** — STOP。下一步仅可继续只读查找可信旧配置内容/完整旧语义及历史写入证据。若无法取得，建立未来新基线需另行明确授权，且不得追认本次FAILED为VERIFIED。禁止代理restore/restart、Trivy refresh/guard变更、Dojo修改、Summary V2/Registry/Router/COMPLETE或发布。

## 最终裁决

```yaml
V2RAYN_CHANGED_FILE: /Users/zhangsir/Library/Application Support/v2rayN/binConfigs/config.json
V2RAYN_DRIFT_CLASS: UNEXPLAINED
PROXY_RUNTIME_SEMANTICS_CHANGED: UNKNOWN
CHECKPOINT_HASH_CONTRACT: REQUIRES_SEMANTIC_NORMALIZATION
RUNTIME_14_OF_16_CHECKPOINT: FAILED
TRIVY_DISK_GUARD_ORIGIN: CALCULATED_FROM_FILESYSTEM_STATE
TRIVY_DISK_GUARD_VALIDITY: GUARD_REQUIRES_REVALIDATION
TRIVY_DISK_GUARD_REVALIDATION_REQUIRED: YES
TRIVY_STORAGE_ENVIRONMENT: ENVIRONMENT_BLOCKED
TRIVY_RUNTIME_FACT_CAPTURE: INCOMPLETE
DEFECTDOJO_RUNTIME_DEPENDENCY: BLOCKED_BY_TRIVY
DEFECTDOJO_RUNTIME_FACT_CAPTURE: INCOMPLETE
COSIGN_RUNTIME_FACT_CAPTURE: VERIFIED
FINAL_WIRED_CAPABILITY: 14/16
REAL_RUNTIME_FACT_CAPTURE: INCOMPLETE
REAL_POLICY_OWNER: INCOMPLETE
IMMUTABLE_ARTIFACT_RUNTIME: INCOMPLETE
SUMMARY_V2_MIGRATION: INCOMPLETE
```

Trivy guard保持 capacity × 15% + 12GiB（8GiB平台预留+4GiB刷新预留），未修改、未重验为有效；当前guest可用约42.74GiB，低于49.7787GiB。Dojo仍TRIVY_HARD_DEPENDENCY / DOJO_DECOUPLING_REQUIRED=YES。DB保证范围为文件元数据与metadata.json hash，未重新计算完整DB内容SHA。

[契约设计及官方7.20.4源码链接](PROXY-CHECKPOINT-CONTRACT-DESIGN.md)；[源→运行映射](proxy-source-runtime-map.json)；[保护核验](protected-state.json)；[测试计数](test-counts.json)；[旧证据/源码保全](source-hash-preservation.json)；[停止收据](stop-receipt.json)。

本轮不提交源码、不重配、不触发build、不签名、不发布、不rollout。
