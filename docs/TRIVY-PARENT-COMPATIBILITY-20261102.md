# Trivy 完整生产父阶段兼容性（2026-11-02）

**Trivy = VERIFIED**，限定当前冻结生产父阶段与 Policy Engine **baseline-v1 / standard** 的兼容性，不表示新在线漏洞扫描、DB健康认证或generic Trivy跨项目最终验收。

**完整审计父阶段123/123 MATCH，MISMATCH0；old / standard均为PASS43 / FAIL80。** 其中103个完整 `ensure-audit-candidate && audit-trivy` 重放、20个原Security Manager单选Trivy聚合重放。发布扫描健康20/20、DB prerequisite41/41另行证明，**不混入123个完整审计parent样本**。全部范围合计184/184一致，old / standard均PASS54 / FAIL130。

新增测试190/190 PASS；原Trivy Medium分类器测试另1/1 PASS。本轮共执行191项，FAIL0。原8个冻结classifier样本保留，并在新增测试中逐一核对；不计作新完整parent样本，没有重跑其他已验收来源。

延续本次冻结证据目录 `evidence/2026-11-01/trivy-parent/`；本报告记录11月2日的最终收口。受控时钟固定于11月1日，用于确定性验证现有时间阈值，不把合成时间当作当前生产状态。

## 1–3：生产位置、prerequisite与执行模型

生产父入口位于 `resources/security-manager/petclinic-adapter.json` 的Trivy模块：

```text
( node infra/security/ensure-audit-candidate.mjs && node infra/security/audit-trivy.mjs )
```

`Jenkinsfile.security-audit` 通过原 `securityManager(mode:'enforce',adapter:'petclinic')` 执行。`Jenkinsfile` 普通发布的 `Harbor Push & Scan` 另调用 `publish-artifacts.mjs harbor-scan`。后者检查扫描完成及镜像身份，不能冒充前者的漏洞分类Gate。

主要实现：

- `infra/security/ensure-audit-candidate.mjs`
- `infra/security/audit-trivy.mjs`
- `infra/security/audit-target.mjs`
- `infra/security/trivy-medium-policy.mjs`、`trivy-medium-review.json`
- `infra/security/governance/scan-counts.mjs`
- `infra/observability/publish-artifacts.mjs` 的harbor-copy/harbor-scan
- `infra/observability/release-preflight.mjs`、`scanner-db-refresh.mjs` 的上游DB依赖
- 原 `vars/securityManager.groovy`、两份Jenkinsfile及production adapter

五层保持分离：**prerequisite/capability → execution → raw漏洞事实 → 原reachability/fixability审查事实 → parent decision**。

该审计父命令**不调用共享scanner-runtime.mjs，不创建scanner Pod，不直接执行Trivy CLI或verifyTools**。Manager外层已有Lease生命周期；审计脚本内部没有额外Lease或独立binary检查。不能给adapter增加生产命令不存在的前置Gate。工具/backend不可用表现为Harbor HTTP、scan Error/Stopped或超时；DB updater CLI失败是上游维护路径的独立事实。

候选准备先查询Harbor固定digest：已存在即成功；404才读取本地registry的OCI index bytes并核对SHA、构造当前build tag、调用原harbor-copy child并验证digest可见；其他状态或child非零FAIL，后续audit按原`&&`短路。child是外部执行观察，其完整copy内部已有此前Build Provenance冻结证明，本轮引用而不重跑、不重计该来源。

审计通过Harbor API按目标artifact发起scan、轮询overview、取native vulnerability JSON。适用arm64/amd64 child串行扫描；无匹配child则扫描index。没有本地Trivy CLI vulnerability scan命令或本地DB缓存解析。

## 4：DB、更新和fallback

这是**普通发布release-preflight的上游依赖**；security-audit里的Trivy父命令没有直接调用它。本轮没有把DB freshness加成新的audit阻断条件，也没有重放整个集群资源preflight。

原 `ensureScannerDatabases` 验证db版本2、java-db版本1及UpdatedAt/DownloadedAt/NextUpdate。fresh时不更新；过期时串行执行：确认外层Lease owner、devops磁盘新鲜余量、没有其他Trivy进程 → 获取官方manifest → 验证SHA及单layer格式 → updater下载 → 重新读取metadata，必须fresh。更新失败、版本无效、时间无效或更新后仍旧，均FAIL，没有“旧DB暂时PASS”的静默降级。

`fetchOfficialCurl` 对官方token/manifest请求有明确路由回退：配置代理时先proxy，失败再direct；无proxy只direct。全部失败抛错。验证官方manifest后，下载指向 `ghcr.nju.edu.cn/aquasecurity/trivy-{db|java-db}@digest`，清空代理，保留原3分钟CLI timeout；没有新增repository、镜像或重试策略。

DB cleanup保留随机owner token、pidfile、仅终止本次updater、检查退出后删除pidfile；manifest临时目录在finally清理。全部由in-memory替身观察，不执行curl/kubectl/kill或真实下载。

## 5：image/artifact身份模型

- 显式candidate仅接受 `core.harbor.domain/petclinic/petclinic@sha256:<64hex>`；tag、其他repo拒绝。
- candidate为空时使用live Deployment image，audit仍要求其digest固定；原代码没有相同repo约束，未新增。
- candidate可以与runtime不同，runtime maps只作为真实原观察事实保留，不推断candidate reachability。
- candidate源index bytes须与请求digest相同，copy后按digest可查询；已有candidate不重新hash其bytes。
- audit选择的child digest构成请求路径并写入report；不额外校验native report内部artifact identity/header，也不新增架构唯一性或必须两架构的规则。
- release `harbor-scan` 单独要求root digest等于 `target/platform/image-digest.txt`、两条匹配runtime架构entry，串行等待扫描完成。原代码是entry count检查，本轮不升级为更严格的集合证明。

## 6–8：exit、报告与分类器复用

审计消费HTTP和原Node进程结果，不直接消费`trivy image`漏洞扫描退出码。`transportFetch`最多三次，对408/429/502/503/504及TypeError/TimeoutError/AbortError按现有规则重试；403等认证错误不重试。audit request原本允许409进入后续处理，保持不变。

每次扫描最多180轮、每轮5秒；Success继续，Error/Stopped立即失败，长期Pending/无overview超时FAIL。每HTTP请求20秒；runtime maps15秒读取失败仅记录observed=false；candidate copy child预算600秒；release每child deadline15分钟。scanner运行/基础设施失败与漏洞Finding失败在原始事实中分别保留，父Node进程可以同为非零。

audit报告为 `.devsecops/trivy-audit.json`，在finally写入，保留每child的scan、native raw、runtimeContext、SBOM Brotli观察、classifications和mediumGovernance。report写失败即使扫描成功也FAIL。release报告另为 `target/platform/harbor.json`。

原解析使用 `Object.values(native).flatMap(vulnerabilities??[])`，没有新增schema算法：空object或vulnerabilities=null可能按原逻辑变空结果PASS；HTTP404、空/损坏JSON、null条目、错误结构、SBOM/review读写错误按原异常语义处理。Policy缺完整成功report或原classifier事实时返回NOT_TESTED/null，不能缺证PASS。另核对classifier输入必须对应原report漏洞集合和image，防止用替换后的事实生成新判定。

父adapter只调用原 `classifyVulnerability`，不建立第二个severity引擎：

| 原事实 | 原分类 / 父Gate |
| --- | --- |
| Critical / High | mandatory FAIL；GATE_TRIVY=warn不改变这段代码 |
| Medium | review.image及id/package/version匹配，且mustFix=true、reachability=confirmed、fixVersion非空、positive/negative/businessPath完整，才FAIL |
| 其他Medium | WARN，保留原漏洞及review事实 |
| Low / 未识别severity | 原分类WARN，不补造severity |
| 只有非阻断WARN | audit父阶段可以PASS，不新增父WARN或FAIL |
| review过期 | 原代码仅记录reviewExpired，不新增阻断 |

原 `review.fixVersion` 是证据输入；生产分类器没有将它和native `fix_version`作额外相等比较，已记录并保留。既有 `trivyCounts` 原函数用于校验C/H/M/L计数，不修改计数规则。

## 9–10：parent aggregation与adapter完整性

完整原JS脚本、原transport helper及原分类器在VM中执行；只替换外部fs、HTTP、subprocess、计时和环境观察。原Manager在固定SHA的本地Groovy runner中执行，plan只选Trivy，Jenkins DSL inert；凭据绑定、stage、shell结果、结果写入和archive异常均保留。未调用真实凭据、实际Summary脚本、Git、registry或cluster。

Policy不导入collector/oracle，不读取oldDecision字段。成功父阶段要求原report、classifier/raw facts；失败父阶段保留原execution失败事实。默认standard生效，既有强制失败在low/standard/strict下不被降级。disabled/skipped/not_configured仍为非决策，不能PASS。

## 11–21：样本与证据类型

| 项目 | 数量 / 状态 |
| --- | --- |
| 既有classifier-only样本 | 8，原件未变，独立逐项核对，不计parent |
| 完整audit `&&`脚本 | 103 CONTROLLED_REPLAY |
| 原Manager父聚合 | 20 CONTROLLED_REPLAY |
| 完整审计parent合计 | **123** |
| release scan-health依赖 | 20，单列 |
| DB prerequisite依赖 | 41，单列 |
| 全范围controlled replay | **184**，输入全部synthetic/disposable |
| 真实历史完整parent | **0** |
| 历史DB子观察 | 3份HISTORICAL_ARCHIVE，不计parent |
| 新增独立契约检查 | 6，属于unit-only，不计完整parent |
| 漏洞决策主标签 | 18 |
| audit registry / transport | 8 / 12 |
| audit prerequisite | 2；另含identity6、architecture3及candidate-copy2 |
| audit execution error / timeout | 5 / 4；另有transport error2、abort1 |
| audit missing / malformed report | 3 / 15 |
| audit IO/write | 4 |
| audit cleanup | **NOT_APPLICABLE**：不拥有scanner Pod或本地scan临时目录，finally仅写report |
| DB cleanup / IO | 3 / 3；属于上游DB依赖，非audit cleanup |

分类按fixture主标签统计，非重复累加全部故障特征；完整分支表在acceptance.json。

用户给出的历史C0/H0/M108/L8没有绑定完整原始报告，本轮不将其伪造成历史样本。单独构造等计数fixture并用原 `trivyCounts` 验证，明确标为合成重放。历史保留3份原DB metadata/download log，仅作历史子观察，未替换日期或冒充当前DB健康。

## 22–25：差分、不变性和保存

| 范围 | samples | old PASS / FAIL | standard PASS / FAIL | MATCH / MISMATCH |
| --- | ---: | ---: | ---: | ---: |
| 完整审计parent | 123 | 43 / 80 | 43 / 80 | 123 / 0 |
| release scan-health | 20 | 4 / 16 | 4 / 16 | 20 / 0 |
| DB prerequisite | 41 | 7 / 34 | 7 / 34 | 41 / 0 |
| 所有范围合计 | 184 | 54 / 130 | 54 / 130 | 184 / 0 |

**Raw facts preserved = YES**。原vulnerability id/severity/package/version/fixed version、review reachability/fixability、image/digest、scan状态、DB/fallback、HTTP/exec结果和report均保持不变。

全部184份落盘fixture重新读取后raw SHA184/184、decisions184/184，164份script/DB/release输入SHA164/164；20份wrapper另存原input和执行facts。原始输入及facts前后深比较不变。84个显式故障/响应注入键均确认到达原代码路径。

2765份既有受保护文件中2764份未变；唯一既有变化是Policy engine两行追加import/Trivy stage分派，去掉两行即可恢复此前SHA。原Gate/分类器、Gitleaks等已验收代码与证据、Jenkins、Manager、release、actual Summary和最终readiness审计均未修改。

## 26–29：剩余缺口、状态、测试和停止

- 当前冻结production parent没有剩余standard compatibility blocker。
- 历史完整CLI/HTTP/prerequisite transcript未找到，真实完整parent样本0；没有声称真实历史负例VERIFIED。
- 全部外部行为是受控观察，未认证在线Harbor/Trivy binary/DB/registry健康，没有真实扫描或DB刷新。
- Manager是原本地Groovy/inert DSL重放，不是Jenkins CPS验收；全局release-preflight资源判断与generic manager/tool.mjs Trivy路径不在本轮兼容认证范围。

最终 **Trivy = VERIFIED，可以退出本次compatibility阶段**。新增190/190 PASS，加原分类器1/1复核，共191 PASS / 0 FAIL。旧8个冻结分类样本保留且不重复计数。

只写本来源coverage-delta，不重建authoritative readiness，不接actual security-summary.json，不改发布、不rollout、不开始下一来源。全局开关、plugin lifecycle、Result Router等目标仍保留在后续设计中，本轮未实施。

证据目录：`evidence/2026-11-01/trivy-parent/`。核心文件为 `production-inventory.json`、`acceptance.json`、`differential.json`、`workflow-differential.json`、`db-differential.json`、`persisted-fixture-verification.json`、`fault-reachability.json`、`classifier-preservation.json`、`source-preservation.json`、`historical-index.json`、`safety-check.json`、测试日志和fixture。
