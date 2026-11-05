# DefectDojo HTTP Consumer Candidate — 本轮交付

基线：`da259baf`。只实现 Candidate、本地真实 HTTP 协议测试及真实实例只读能力核查。
没有真实 Dojo 写入、扫描、Jenkins CI、Kubernetes 变更、生产发布、rollout 或 push。

## 实际代码与接线

新增：

- `infra/security/manager-v2/consumers/dojo-http.mjs`：目标白名单、受保护凭据读取、原生 HTTP multipart、只读上下文确认、超时、只读重试、追加回执和不确定状态恢复。
- `dojo-http-targets-v1.json`：默认关闭；只有两个 `MOCK_PROTOCOL_ONLY` 固定回环目标，真实目标列表为空。
- `dojo-http-cli.mjs`：显式 Mock HTTP CLI，不接受 URL、Product ID 或 Token 值。
- `dojo-http-fixtures.mjs`：测试专用 REPLAY/显式变体，未接入生产执行。
- `dojo-http.test.mjs`：59 项真实 socket HTTP/输入/凭据/状态测试。

仅修改既有 `router.mjs` 和 README。`routeResultsHttp` 是原 Router 的显式异步扩展，
先调用原 `routeResults`，复用既有 `prepareDefectDojo` 的 Artifact、原始报告、Fact、
Policy Result 和 Payload 校验，再执行 HTTP。原 `routeResults` 主体及默认 Consumer 列表不变。
未修改原 Mapping、三插件 Runner、Policy Engine、Gate、V1 Summary、Trivy Guard、Helm 或生产 Dojo importer。

## 安装版 API/Parser 依据

通过已有严格校验 host key 的 SSH，只读取运行中实例的公开分发代码，未读取 Dojo Token、
`.env`、进程环境或数据库。实际分发版本 `3.4.301`，源码副本、SHA 与提取记录位于
`installed-api/`、`installed-api-inspection.json`、`installed-api-supplement.json`、`installed-model-contract.json`。

已确认的源码契约：

- `dojo/urls.py`：注册 `import-scan`、`reimport-scan`，及独立 Product/Engagement/Test/Finding 路由。
- `ImportScanView`：`MultiPartParser`，认证及 `UserHasImportPermission`；不把它当作匿名写入接口。
- `CommonImportScanSerializer` / `ImportScanSerializer`：支持 file、scan_type、engagement、build_id、version、test_title、两个 close-old 选项、auto-create、deduplication_execution_mode 等。
- **description 并非 Import Serializer 声明的输入字段**。第三轮 Mock 样本曾依赖该字段；源码核查发现后已改为 build_id/version，第四/五轮是最终权威样本，早期样本保留并明确为被替代尝试。
- **do_not_reactivate 只属于 Reimport Serializer**，Import 不发送；Reimport 默认 `close_old_findings=True`，本轮完全不开放 Reimport 写路径。
- `DefaultImporter` 将 build_id、version、test_title 写入 Test；模型允许 build_id 150 字符、version 100 字符。当前固定值分别69和64字符。
- Test Serializer 返回模型字段和 test_type_name；查询核对 Test→Engagement→Product，再核对 Finding 的 Test、稳定身份、严重度、文件位置和证据引用。
- 继续使用已冻结 `Generic Findings Import` 的 Gitleaks/Semgrep Mapping；不共享错误的原生 Scanner Parser，也不生成 Cosign CVE。

`verify-api-schema.py` 在独立临时沙箱内解析安装源码，核对最终样本 **27 份实际 multipart 请求**
的字段及摘要。它是静态兼容检查，不是 Django serializer 实例化、服务器验权或真实 import 成功证明。
最终结果：`api-schema-attempt5.json`。

## HTTP 安全与生命周期

HTTP 默认关闭，目标只能来自冻结目标表。启用后只能连接 `127.0.0.1:32185`，不解析用户提供域名。
不存在真实服务器 target，也不能通过新增 CLI 参数绕过。真实 HTTPS/受信任 origin 的接入需下一阶段审查。
所有重定向和分页 URL 均不跟随；超过一页、结果不完整或上下文无法绑定时拒绝派发。

Token 只由当前 UID 所有、仅 owner 可读（0400/0600）、单链接的普通运行时文件读取，父目录仅允许 owner 访问，拒绝软链接、
硬链接、宽权限和非 Mock Token。只接受 disposable `SMV2_MOCK_TOKEN_` 前缀。
Transport 使用不可序列化能力绑定，公开句柄里没有 Token；伪造或复制句柄不能发送请求。
没有 URL/请求头/fetch 注入接口。错误只输出固定分类码，不输出服务端错误正文、Header、Token 或堆栈。

预算：默认请求超时2秒，配置范围20ms–10秒；只读 GET 最多3次、指数退避上限1秒。
每报告最多32条/64KiB、multipart 80KiB、响应128KiB、查询100条且无下一页。
POST 不自动重试。只读 GET 的429/500/503/网络错误可以有界重试，不能将该行为套到写操作。

状态与恢复：

| 情况 | 状态 / 行为 |
|---|---|
| 未启用、无完整来源 | NOT_SENT；不会生成合成 Finding |
| 校验后 | PREPARED，保留各来源原状态和 resultDigest |
| 派发前 | fsync 追加 SENT 意图，再写 socket |
| 200/201 + 实际 Test/Finding 精确核对一致 | ACKNOWLEDGED，仅引用实际 Mock 成功对象 |
| 400/401/403/404 | REJECTED，不盲目重发 |
| POST429 | RETRYABLE_FAILURE，但任何重发前仍需只读恢复，当前不会自动重发 |
| 409、500/503、超时、响应丢失/损坏、202未完成、错误对象绑定 | UNKNOWN_REMOTE_STATE，不假定成功 |
| 已 ACK 的同一 journal 请求 | 校验并复用先前本地回执，标明旧 ACK 时间/来源；0次新HTTP |
| SENT 后不能证明 ACK | 只查询固定上下文和稳定身份，仍保留 UNKNOWN_REMOTE_STATE |
| journal 损坏、权限失败、锁残留 | fail-closed，不覆盖旧回执、不擅自删锁、错误在结果可见 |

独立 JSON 回执包含 runId、projectId、consumerId、targetIdentity、requestDigest、resultDigest、
factDigest、payloadDigest、deliveryAttempt、HTTP Status、remoteObjectReference、deliveryState、
retryState、timestamp、redactedError、摘要链和来源分类。
请求逻辑摘要与实际报文字节 SHA 分开记录；测试对比了真正收到的 body SHA 与持久化 SENT SHA。
无响应成功证据时 remoteObjectReference=null；只读观察到的 Test ID 用不同字段表达，不冒充 ACK。
回执永远不写入 Immutable Candidate Result，Policy Decision/evaluationCount/resultDigest 复用。

## 幂等证明的范围与明确竞态

相同 journal 的互斥锁、追加链、重复 ACK 复用、响应丢失后的只读核对均由真实 Mock HTTP 验证。
不会把409、重复Test、空查询、坏响应或“好像成功”当成成功。

**两个独立 journal 并发先查后写，仍可能创建重复 Test。** 本轮用真实 Mock 请求明确复现了2个重复 Test，
作为限制证据保存在 `documented-cross-journal-race.json`，没有把该样本列为远程幂等证明。
安装源里的 Test 标题无唯一约束；现有源码未建立请求级原子 Idempotency-Key 契约。
Generic Parser 保存 unique_id_from_tool 也不等于服务器按该字段去重。
因此下一阶段需单写者/共享 journal 的执行约束、实际去重配置和对象级恢复证据；不能宣称分布式 exactly-once。
远程幂等始终 `NOT_TESTED`。

## 测试与样本

- 首轮201项：198 PASS / 3 FAIL，原记录保留。修正的是 Mock 的有限失败响应状态、空 Finding 无法触发错误 Test 绑定负例、以及负例目录权限设置。
- 第二轮201/201 PASS。
- 第三轮208/208 PASS，含早期样本；尚未采用最终 build_id/version 绑定，不能当最终 API 兼容样本。
- 第四轮 **210/210 PASS**，包含原有153项及当时57项 HTTP 测试，安装源码 Schema 检查通过。
- 最后仅补跑 HTTP 文件：**59/59 PASS**，包括真实目录写权限失败和全部插件关闭；不重复未改动的153项。
- 当前不同测试合计 **212**；没有声称212项在最后一次单轮全部执行。
- 原 Router 默认路径、重复投递失败、旧future占位、既有离线Dojo Consumer：**5组 × 4 = 20 项直接对照一致**。
- 最终 **15份脱敏样本**，含实际请求方法/路径/报文长度与摘要、接收的 Generic Payload、追加回执、结果摘要及已知竞态。
- 覆盖 Gitleaks/Semgrep 真实历史 Finding 的 REPLAY、混合显式 FIXTURE、关闭/执行失败/Policy FAIL/Policy ERROR、Trivy blocked、Cosign unsupported、跨项目、Consumer失败和重试。
- HTTP 覆盖200/201、400/401/403/404/409/429/500/503、连接拒绝、读写超时、响应丢失、坏/超大响应、重定向、重复请求与不确定恢复。

`sample-index.json` 指向 `samples-attempt5/` 最终权威样本。测试来源分类：

| 分类 | 内容 |
|---|---|
| REAL_READ_ONLY | 已安装代码、无凭据GET、生产健康与DB摘要 |
| REAL_MOCK_HTTP | 本地原生TCP/HTTP请求、multipart、响应及错误 |
| REPLAY | 前轮真实受控扫描生成的封存 Candidate；本轮没有新扫描 |
| FIXTURE | 明确重封装的混合/错误状态/跨项目负例与 disposable Token |
| STATIC | 安装源码字段校验、调用/默认行为契约 |

## 真实实例可用性与下一轮授权清单

真实实例 `defectdojo.devops.local` 的 Products/Engagements/Tests/Findings/TestTypes 5个未认证 GET 均403。
这只能证明该入口拒绝这些未认证读取；没有认证 challenge，不能据此确认生效认证链或对象权限。
候选使用与既有客户端一致的 Token Header，但真实实例中的 Token 认证配置/有效身份仍未通过认证请求验证。
没有读取生产管理员 Token、没有管理命令/数据库旁路查询，也未创建测试 Product、Engagement 或身份。

- 安装代码 API/字段：有证据。
- 认证 API 端到端、实例 Parser 接受导入：未验证，`DEFECTDOJO_API_COMPATIBILITY=INCOMPLETE`。
- 独立非生产 Product/Engagement：UNKNOWN，真实 ID=null，不把生产1/1冒充测试对象。
- 独立最小权限身份：NOT_READY，Credential Scope 尚未证明。
- 真实投递批准：NOT_GRANTED；真实远程投递/远程幂等：NOT_TESTED。

具体字段、Payload来源、上限、清理、回滚和审计要求已列入 `real-delivery-authorization.json`。
Gitleaks1条与Semgrep2条真实 Finding 来自不同旧运行，不拼成同轮16/16；混合样本明确是 FIXTURE。
实际环境名也需确认，因为安装的 CommonImportScanSerializer 在 auto-create=false 下要求已有 Environment。
不得让本轮 Mock 的11001/12001等虚构ID进入真实实例。

**唯一下一步**：通过合法只读身份确认专用非生产 Product、Engagement、已有Environment及最小权限身份，
取得具体ID和作用域证据，再申请明确、有上限的真实投递授权。缺项时保持 NOT_READY，不创建对象补齐。
下一轮获批后才审查真实目标/HTTPS传输配置和少量导入；本轮不自动进入该阶段。

## 证据保护

复用现有 macOS sandbox-exec 文件写边界，只额外放行 localhost:32185。
实际预检证明覆盖/删除/chmod当前轮 canary 被拒绝，其他回环端口和外部地址被OS拒绝，允许端口收到HTTP200。
所有测试在唯一临时 Git 副本运行，结束目录已回收。没有对历史文件做破坏性写探测。

13,585个受保护文件的数量、SHA、大小、mtime/ctime、mode、uid/gid、inode、链接属性均保持一致；
历史 evidence 文件清单未变化。不声称atime不变。不存在本轮新覆盖事故。
原历史事故 `ORIGINAL_EVIDENCE_INTEGRITY=FAILED` 保持不变。
第一次嵌套沙箱权限失败与第一次 HTTP profile 的localhost语法修正都有独立记录，均未启动测试或写历史。
自动审批曾因额度不足阻止一次执行；该动作当时未执行，恢复审批后才继续，未绕过。

## 生产保护与回滚

`production-comparison.json` 的19项检查通过：
Jenkins petclinic-ci #270 SUCCESS、lastBuild270、Job定义及V1 Summary SHA不变；
Argo Synced/Healthy及revision不变；三节点Ready；PetClinic3/3、HTTP200、spec/pod/image不变；
Docker socket0660、daemon无重启、Dojo/Trivy Pod元数据不变。

Dojo compose SHA从实例接口源码核查到最终相同。
Trivy2个DB在最终集成测试前后做流式全字节SHA和stat对比一致；阶段起止另有DB metadata SHA/stat一致。
这里明确全字节窗口的起点，未将较早仅metadata检查改写为全阶段全字节测量。
没有刷新DB或执行Trivy。未更改Dojo实例配置、数据或原生产导入脚本。

本地 Candidate 回滚：继续使用原 `routeResults`/离线CLI，或撤销本次独立代码提交。
HTTP默认关闭，无需回滚任何集群部署。若以后在已批准测试上下文产生对象，必须按授权清单定向处理，
不得通过删journal、自动重发或关闭历史 Finding 代替回滚。

最终范围：`PRODUCTION_SECURITY_MANAGER=NOT_ACTIVE`，Runtime14/16，Trivy/Dojo canonical Runtime仍INCOMPLETE，
生产Summary V2未迁移；release=0、rollout=0、push=0。完整逐项状态见 `VERDICT.txt`。
