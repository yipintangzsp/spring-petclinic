# DefectDojo Consumer Candidate：统一结果出口

2026-11-05；基线98f906d8，未push。验收范围为**Candidate转换、格式校验、项目隔离、离线幂等/Receipt**。
生产Security Manager NOT_ACTIVE；Dojo远程投递和远程幂等NOT_TESTED；Trivy/Dojo Runtime仍INCOMPLETE；canonical Runtime14/16。

## 现有接口与本轮解耦

原生产`governance/defectdojo.mjs`固定Product1/Engagement1，读取Gitleaks/Semgrep/ZAP私有文件，且先强制读取完整
`.devsecops/trivy-audit.json`及Kubescape等报告，再调用DojoClient import/reimport；该生产路径和门禁本轮不变。
DojoClient既有`close_old_findings=false`，但仍有依赖前序私有文件及生产状态更新逻辑；**新Consumer不调用它**。

本轮只修改既有Router和README，新增`manager-v2/consumers/`中的Adapter、版本化映射、项目白名单、CLI与测试。
三个Plugin Runner、Manager Core、Policy Engine、Result/Artifact、Jenkinsfile、原生产Gate、旧Dojo实现、Trivy/Helm/Argo全不改。
不是第二套Router。原CONSUMERS默认列表、原dry-run/local-evidence与future占位符行为保持；新consumer需显式opt-in。

新链：已有封存Candidate → 验seal/summary/result/raw/fact绑定 → 每源转换 → 校验Generic JSON → 离线计划 → 原Router Receipt。
只读标准`<plugin>.raw.json`、`<plugin>.facts.json`及统一Result，不读取`.devsecops`或Trivy私有路径。
一个来源缺失/不支持/错误不会覆盖其他来源原Result；映射错误可返回PARTIAL_ERROR并保存其他已验证来源，不能生成该来源的PASS。
原始Artifact已损坏时则按原Router契约整体验seal拒绝，不为损坏输入准备导入。

## 事实、Policy和运行状态的边界

- 原始Finding：Gitleaks rule/file/line，Semgrep check_id/extra.severity/位置与规则身份；只从校验过的原生与normalized事实取值。
- Policy：原policyDecision、evaluationCount、factDigest/resultDigest为权威元数据，Consumer不决定或覆盖PASS/WARN/FAIL/POLICY_ERROR。
- 运行状态：DISABLED/SKIPPED/NOT_CONFIGURED/UNSUPPORTED/ERROR/POLICY_ERROR全部NO_IMPORT，Policy=null时不补PASS。
- Cosign：验签是供应链验证；PASS不是漏洞，失败暂无批准的治理类型/严重程度映射，因此Finding映射UNSUPPORTED，保留状态及摘要引用。
- Trivy：未来映射NOT_CONFIGURED，无真实本轮输入，既不执行也不以旧报告伪造结果。

## 格式和版本依据

只读核实安装实例**DefectDojo3.4.301**与实际镜像digest，读取Generic、Gitleaks、Semgrep parser源码，未读取env或API Token。
Django镜像为registry.defectdojo.com/defectdojo/defectdojo-django@sha256:ccee9de64bae2156abafac946a83a3bfda43e13a314ac703e849cf9831bedba9。
GenericParser.get_scan_types()明确注册`Generic Findings Import`；Generic JSON code要求title/severity/description，支持本轮所用字段。
已安装Generic JSON parser SHA：8de539f496babaa6b5ebc5ec98f337839af467dd57ebd2406939b5888359a58b。
原生Parser是不同格式，本轮没有把三种原始报告直接塞进同一个scanner parser。

`dojo-mapping-v1.json`固定parser/source hash、Consumer版本1.0.0-candidate.1、映射版本dojo-findings-v1及严格字段白名单：
顶层name/type/version/findings；Finding限title/severity/description/severity_justification/file_path/line/unique_id_from_tool/
vuln_id_from_tool/references/static_finding/dynamic_finding/active/verified/nb_occurences。
禁止注入payload/Secret/endpoints/mitigated/false_p等额外字段。每份payload及计划均校验digest，损坏不投递。

上游公开接口参考：[GenericParser](https://github.com/DefectDojo/django-DefectDojo/blob/master/dojo/tools/generic/parser.py)。
本轮具体格式以**本机安装的固定源码摘要**为准，未以master推断当前实例。

16份实际Adapter JSON经过已安装GenericJSONParser的字段/数值转换代码核对；缺required与unknown字段由该代码真实拒绝。
执行在唯一临时目录、OS写保护内；Django模型用显式test doubles替代，无app setup、DB或API。
因此是**OFFLINE_INSTALLED_PARSER_LOGIC**兼容证明，不是服务器接受或数据库列约束验收。
第一次纯格式核对仅读取本轮样本并写本轮receipt；最终又在OS隔离临时副本完成同一核对。没有历史文件写入。

## Finding映射与脱敏

| 来源 | 映射 | 严重程度依据 | 保留/丢弃 |
|---|---|---|---|
| Gitleaks | Secret治理Finding | native无severity；采用安装版get_finding_current的High默认值，明确标为治理展示映射 | rule、相对文件、行/列、稳定ID；Secret/Match/源码/作者/Email全部不输出 |
| Semgrep | SAST Finding | 安装版convert_severity：CRITICAL→Critical，ERROR/HIGH→High，WARNING/MEDIUM→Medium，LOW/INFO→Low | 原severity另存摘要references，rule/规则集SHA/相对位置保留，任意message/metavars/snippet不复制 |
| Cosign | UNSUPPORTED Finding映射 | 没有批准的严重度映射，不发明CVE/漏洞 | 仅统一结果状态和fact/result/raw摘要，PASS不发Finding |
| Trivy | 未来契约 | 无真实本轮事实，不生成payload | 阻塞/关闭不影响其他来源 |

Gitleaks的High不是声称scanner提供了High，更不改变Policy FAIL规则；Semgrep映射完全沿用安装版原生parser，未擅自升降。
安装版Gitleaks parser SHA f7973c52dd5be62b099fa65128facc6437fc9e7f5bd693dd9e140e9526c726e2；
Semgrep parser SHA8d85fd5b7af234d52f85bd589894a062f4c9b492429fc90a0cfdacf1f7e12b2c。

描述由固定模板生成，不复制任何自由格式原始描述、命中行、secret/fingerprint值或命令stderr。
references仅含rule身份、原severity/列及rawReportDigest/factDigest/resultDigest/规则摘要。
不把原始报告正文复制到Consumer输出；值型注入、敏感元数据、Token/URL参数和计划内Token私货均拒绝。
测试把无效sentinel放进Secret/Match/Description/Author/Email，最终plan/payload无该值；凭据参数不会进入失败Receipt。

## 项目映射及未配置项

`dojo-projects-v1.json`是可信Git白名单，项目参数不能选择任意生产Product：

| Manager project/profile | Product alias | Engagement alias | Test |
|---|---|---|---|
| java-fixture/java-web | candidate-java-fixture | candidate-java-fixture-local-validation | 固定项目+plugin+directory scope |
| service-fixture/container-service | candidate-service-fixture | candidate-service-fixture-local-validation | 同结构，项目隔离 |

真实ProductId/EngagementId为null、remoteApproved=false、apiRequestReady=false；原生产1/1明确排除。
这是本地Candidate上下文映射，**不是已建立真实非生产Product/Test**。远程上下文仍NOT_CONFIGURED，不能调用import API。
未知项目返回NOT_CONFIGURED，错误Profile/碰撞alias/注入Product1均拒绝，不自动建Product。
后续只能经单独授权把白名单别名解析到真实专用非生产上下文；不能默认映射到当前生产PetClinic产品。

## 幂等、重试与历史Finding保护

Finding ID=SHA(project+plugin+scan scope+rule+relative file+line+column)，不含runId、私密值或扫描临时绝对路径。
同一真实Finding在两轮既有受控扫描中得到相同ID，Result/idempotency key仍分别绑定各次运行。
跨项目/跨scanner相同位置不会共享ID。标题与描述也带项目/工具/scope，避免默认hash去重中无来源的同标题混淆。

Delivery key绑定project/plugin/run/resultDigest/payloadDigest；相同Result重复准备输出相同payload并重用已验seal目录。
文件准备先在本轮目标下新建私有临时子目录，完成seal后原子rename；finally只清理有inode/device归属证明的该临时目录。
不能把输出写入输入Artifact。冲突/失败不改Policy，安全重试可成功；既有本地payload如损坏则fail closed，不擅自删除修复。

安装版Generic parser会记录unique_id_from_tool，但源码说明默认匹配是hash-only，ID本身不能证明远程去重。
OFFLINE_IDEMPOTENCY=VERIFIED；REMOTE_IDEMPOTENCY=NOT_TESTED。没有发HTTP，更没有声称远程Finding ID不变。

所有import计划close_old_findings=false、close_old_findings_product_scope=false、auto_create_context=false、do_not_reactivate=true。
historyActions始终空。关闭/失败/缺能力/Trivy阻塞不会产生“已修复”操作；空findings的完整扫描也不自动关闭旧漏洞。
本轮没有任何生产Finding状态更新。HISTORICAL_FINDING_PRESERVATION的VERIFIED限于这些离线行为与零远程写，不是远程生命周期测试。

## 真实Adapter样本与测试来源

使用上一轮真实controlled执行的原Artifact作为**REPLAY**，不是本轮重新扫描，也不拼装成新的same-run：

- H-gitleaks-fail：Gitleaks1条脱敏Finding，原Policy FAIL保留。
- G-semgrep-fail：Semgrep2条Finding，两个原rule/severity位置保留，原Policy FAIL保留。
- F-cosign-tampered：供应链FAIL、Finding映射UNSUPPORTED，没有CVE记录。
- A-three-valid：同一既有三插件Candidate，Gitleaks/Semgrep完整零Finding可准备，Cosign PASS没有漏洞。
- D/C单插件关闭、I-Cosign ERROR、Q-Policy ERROR：对应源无import，其余独立保留。
- P-service-project：独立Product/Engagement别名和报告路径。

9组样本位于samples/，共16份Generic JSON；每组都有实际plan、首次delivery与retry Receipt、原始Summary/seal摘要。
样本不是手写模拟payload；由当前Consumer/原Router在OS隔离目录生成。
新扫描0，Consumer新增Policy求值0，HTTP0，所有原Result/factDigest复用。
原completed插件evaluationCount=1；disabled/ERROR/POLICY_ERROR保持原0，不伪造求值。

测试结果：

- **153/153**相关测试最终通过（STATIC/FIXTURE/REPLAY），覆盖附件25项及重发现/凭据私货/输入输出重叠等补充边界；coverage.json逐项定位。
- **15项**旧/新Router直接对照完全一致：5个相同历史输入各比较首次投递、重复投递失败、旧future占位符启用。
- **16份payload+2个格式负例**通过已安装Parser逻辑离线核对（模型double，DB/API NOT_TESTED）。
- REAL仅限环境/已安装公开源码/生产快照/文件系统写保护与元数据取证；本轮没有任何新scanner/Dojo导入Runtime。

首轮误把旧future描述符也加了新必需输入，导致2个既有回归失败；已恢复旧描述符并保留首轮日志。
首轮清理receipt在with尚未退出时读取而误记false，随后确认临时树实际删除；后续receipt在退出后采样，均true。
没有删除失败记录或改生产规则凑通过。原Dojo冻结实现、三Runner及旧Policy字节全未变。

## 写保护、生产与回滚

本轮先执行既有原生sandbox写保护预检，覆盖/删除/chmod对本轮canary均被拒绝；没有对历史做写探测。
测试只在唯一临时副本中运行。旧已知固定输出command/cosign历史回归没有直接运行于仓库根。
最终**13,429个受保护文件**数量、SHA、mtime/ctime、mode、UID/GID、inode和历史文件清单不变；atime不做保持声明。
出现历史写入应立即STOP的条件未触发，本轮新覆盖事件=false；旧事件CONFIRMED/旧完整性FAILED保持。
所有本轮测试临时目录删除，无常驻组件或高权限资源。

前后生产只读一致：petclinic-ci #270 SUCCESS、lastBuild270；V1 SHA ec9ee51a06d4b9f61c6c0eaf50b374d1e25e6d3ca687908b7596d3a2c794f5d8；
Argo Synced/Healthy、三节点Ready、PetClinic3/3、快照HTTP200；生产digest489cb821573ff1f98edd846d5949d74bf3391b24e2f1fe5bcfb71c6be0793137；
socket0660、Docker MainPID/启动单调时间/NRestarts不变；Trivy metadata.json hash/stat及Dojo Pod元数据不变。
未读取生产Token、私钥或Dojo数据库；无API写入。健康是快照，不是发布连续性/压测结论。

回滚：停止使用Candidate Consumer/CLI，或定向撤回本轮本地提交，保留新证据；生产无需回滚。
下一步最小可执行阶段：先提供并批准一个现有专用非生产Dojo上下文与最小权限身份，核实真实Generic parser/API/模型限制，
再另批一次有限导入/重导入/历史不关闭验证；若没有安全测试实例，继续保持远程NOT_TESTED，不新建实例或借生产产品代替。
本轮到此STOP，不推进Loki、Trivy、Agent、生产Result Router或Summary V2。
