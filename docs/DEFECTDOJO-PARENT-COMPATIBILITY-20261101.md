# DefectDojo production acceptance compatibility

DefectDojo = **VERIFIED**，限定当前冻结源码的完整生产集成验收逻辑在baseline-v1/standard下兼容。不是新的生产导入验收，不是漏洞扫描结论，也不代表去重算法本身完美。全阶段通过受控内存传输重放，没有生产HTTP写入；本轮立即停止，不开始Falco、Router或Summary。

## 1–6 生产入口及真实验收语义

入口为生产Security Manager adapter的DefectDojo Governance阶段，执行 `infra/security/governance/defectdojo.mjs`；导入/查询/重试/去重由 `dojo-client.mjs`，产品/Engagement由dojo-target.json。两个原源码和target摘要均未改。

前置为已有DEFECTDOJO_TOKEN和SONAR_TOKEN绑定、可读.git-sha、output目录和target。原脚本读取Gitleaks/Semgrep/ZAP原生报告，selected image的完整Trivy报告及source一致的四份Kubescape报告，另由Sonar API导出完整且有界的漏洞issue列表。未改变这些私有文件依赖，未来解耦仍是另一阶段。

Trivy扫描必须完整/Success；若其Gate失败但有完整failure findings，原流程仍允许导入用于治理。源Gate失败但有blockingFindings时也允许治理；Dojo不能解除原scanner阻断。输入不完整、缺文件、JSON损坏及导出总数不完整等仍FAIL。

每项任务固定title前缀与scope，提交原scan type、report文件、engagement/build/source/auditContext。客户端按engagement查询Test，以完全相同title匹配：多于一个Test拒绝；有Test用reimport，否则import；支持response.test为数字/对象及列表回查fallback。若仍无ID则FAIL。原生报告字节限制100MiB。

第一次导入后查询finding列表，再次同步reimport并查询；两次Finding ID排序后必须相等，变化即FAIL。close_old_findings=false、sync dedupe、reimport do_not_reactivate=true保持；不重新实现parser或服务端dedupe。

GET/PATCH只对规定transport和502/503/504有两次额外重试；import/reimport POST不自动重试。认证错误、不可用、JSON/collection错误、外部域分页及100页仍未结束均FAIL。最终query product finding集合后沿用原governanceCounts展示状态，finding数量/严重级别本身不改变治理Gate决策。

误报同步只使用原source Gate的已证明条目：path或title后缀、line、description中的Rule Id、64位line hash形状匹配；需要时PATCH既有Finding为false-positive。这个原匹配契约未放宽，也未新增精确hash核验或更严格rule解析。没有本轮生产PATCH。

原Gate没有独立cleanup资源步骤；finally写报告失败仍FAIL，不编造cleanup通过。原stage没有普通Finding WARN出口，治理成功PASS、操作或证据验收失败FAIL。风险统计保持原事实，并不把High/Critical集合重分级为Dojo自身发现。

## 7 Adapter 与对照方式

新增dojo-parent.mjs及dojo-frozen-io.mjs；引擎提供evaluateAsync用于该异步治理事实，保留其他同步接口。未接生产Manager或实际Summary。原DojoClient源码在隔离VM中加载，只把HTTP、native文件输入、输出和sleep替换为明确冻结的内存观察。没有真实凭据、网络、文件写入或调用生产服务。

旧Oracle执行**完整未修改defectdojo.mjs + 原DojoClient**，新adapter消费相同事实，复用原客户端验证，不重写parser/dedupe/服务端判断。两边分别创建独立的内存状态，不共享导入或查询变更。全部成功例还比较完整imports结果、原始查询统计、误报证明及产生的请求/表单序列；失败例比较完整阶段决策和请求序列。

版本文件锁定两个旧源码SHA，变化须POLICY_ERROR及重新验证。raw输入逐例JSON比较且返回独立副本，不修改原导入响应、finding、Test/Engagement/source、report内容或任何severity。

## 8–16 样本与计数

历史真实依据为已有Jenkins #270脱敏归档：10项原生报告import receipt均reimportSameIds=true，包含Test ID、scanType、source/report SHA及治理统计。它不是原始完整HTTP逐响应抓包。

**68个完整阶段fixture全部标记SYNTHETIC_COMPLETE_STAGE_WITH_HISTORICAL_RECEIPT_IDENTITIES**：复用历史Test/engagement/report路径身份；原生payload、HTTP响应和finding集合为受控合成输入。不是68次生产导入，不将报告成功receipt伪装成完整历史执行重放，也不称为自然生产事故。

- import/query/dedupe：现存Test、新建Test、对象ID、列表fallback、ID变化、重复title、无ID、oversize等。
- 响应/查询：auth、503/transport、JSON损坏/null、坏collection、query-back不可用、最终query失败、外域/无界分页。
- 前置报告：Trivy完整/失败仍可治理、四份source绑定、source证明、Sonarissue总数、原生文件缺失/不可读、target缺失/损坏。
- 误报匹配：正常PATCH、已设置不再PATCH、rule/path/line/hash不匹配不使用、title fallback、PATCH失败/暂态恢复。
- 失败/写入：中间生成报告、逐项receipt、finally报告、输出目录和源码读取故障。

完整differential **68**；matched **68** / mismatched **0**；旧PASS19/FAIL49，新standard完全相同。另1项缺证据测试返回NOT_CONFIGURED、decision=null。总Policy tests **301/301 PASS**。所有raw facts保持不变。

## 必须保留的旧验收边界

- 稳定的零Finding查询可以PASS，因为原代码没有要求native report count与query count相等。不能自行加“结果必须>0”。
- 原客户端不会独立把每条返回finding与source report fingerprint/parser逐项核验；新adapter不新增或声称已有此证明。
- 产品查询response内容并未在原代码中独立核验id等于预期值；实际identity约束来自已有target与请求路径/Test匹配，不虚构更强绑定。
- reimportSameIds验证ID集合稳定，不认证服务端内部dedupe机制，也不证明所有未来重复行为。
- 假阳性匹配保留原规则，报告中的governance结果不替代scanner门禁。

这些限制已有明确差分正例或源码依据，属于冻结兼容必须保留的行为，不应通过改规则来得到更好看的安全声明。

## 17–20 剩余缺口、最终状态与停止

当前没有已知未覆盖的结构性**完整集成验收兼容**分支；自然历史失败的完整HTTP/文件观察仍为DEFERRED_REAL_NEGATIVE_EVIDENCE。受控完整stage重放足以证明本轮限定的源码兼容，而不能证明服务端实际parser在所有报告上的行为或实时服务健康。

DefectDojo可离开本次compatibility阶段。并不表示已解除文件耦合、实现Result Router、通知或query closure，也没有把结果写入实际security-summary.json。

SOPS/age保持NOT_TESTED/ENVIRONMENT_BLOCKED，Sonar负例保持DEFERRED_REAL_NEGATIVE_EVIDENCE，最终Security Manager portability仍受这些证据边界约束。本轮不自动进入Falco或其他来源。

证据目录：evidence/2026-11-01/dojo-parent，包含differential.json、historical-import-receipt.json、acceptance.json、source-integrity.json、production-coverage-update.json、tests-complete.log、all-policy-tests.log。此前其他来源证据保留，未覆盖旧状态记录。
