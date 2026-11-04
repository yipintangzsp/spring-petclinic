# Semgrep — second real Candidate plugin

范围：2026-11-04开始，2026-11-05完成；基线ac7d7d69，Candidate升级为2.0.0-candidate.3。
本轮完成两个独立真实工具的本地受控闭环。生产Security Manager未激活，Jenkins CI未运行，canonical Runtime仍14/16。
所有VERIFIED均受以下本地Java规则/固定ARM64工具/合成数据范围限制，不能外推为完整生产Gate或16/16。

## 代码与复用

修改：`infra/security/manager-v2/{registry,core,cli}.mjs`和README。
新增：`infra/security/manager-v2/semgrep-real.mjs`、`semgrep-real.test.mjs`、
`infra/security/testing/semgrep-real-suite.mjs`；本目录保存操作脚本、真实结果、失败尝试、测试与恢复证据。

复用现有runCandidate、capabilityCheck、policyOwner.evaluateOnce、sealResult、artifactStore、verifyArtifact和routeResults。
没有第二套Manager。`gitleaks-real.mjs`、Result/Artifact实现、Router/Consumer业务逻辑、原Policy Engine、原Gate、规则、Agent候选均未修改。
默认replay registry和原realGitleaksRegistry保持原定义；新增显式realPluginsRegistry，两个真实插件默认disabled。
Semgrep为静态可信runner、固定pluginId和candidate.3版本；独立30秒总deadline，Gitleaks原10秒不变。
五项具体现实输入能力SOURCE_DIR/SEMGREP_BINARY/SEMGREP_RULESET/OUTPUT_DIR/POLICY_VERSION另加可信workspace能力。
能力hint不等于授权，runner仍验证root-owned approval/source/tool、inode/device/内容、固定规则和依赖SHA、执行身份与私有输出。
JSON配置不能提供runner函数、任意命令、工具路径、规则URL或shell。缺工具/规则/目录/Policy均不能产生PASS。

真实路径：Manager → 固定插件 → Capability → 原生binary → 独立Raw Collection → 原Finding不改动 → 原Policy一次求值 →
独立Result → 同一Candidate Summary → 原离线Router。实际按插件顺序串行执行，未为“双插件”增加并发负载。

## 工具与执行边界

- Semgrep CE **1.182.1**，实际输出`semgrep-core version: 1.182.1 (6f7d77ede0)`。
- 原生binary SHA：`886b69c889897ea13e23aba5f541c59ee1356c55218ebc21e07b7ab45f1256d2`。
- 复用现有生产离线工具包，27个native/dependency文件逐个校验；未下载、安装或改写原工具。
- 规则SHA：`f37975c96e42be2636c25867dd5dbe4748ad3c0944786ad5f2ea028038defcfe`，原8条Java规则未变。
- 原command-parent冻结manifest SHA：`f83a876ca96c5943b83bc289aeb27282fff7d9eb42cd2be0e1fdb6b41d098482`；17个生产源码依赖全匹配，未重签manifest。
- Gitleaks仍8.30.1，从既有固定digest的k3s镜像缓存只读提取，验证OCI链；没有Docker API、image pull或容器创建。

继续使用上一轮已验证的**固定工具专用**Linux本地执行方式：UID/GID65534、清空附加组/环境、NoNewPrivs、capabilities清零；
不能访问Docker socket/admin kubeconfig，无生产发布凭据。源码仅被解析，从未执行Java/Python源码、hooks、构建或项目命令。
这不是专用Jenkins Agent身份，不宣称共享UID具有通用不可信程序隔离能力，不推广到Trivy或对抗性后代逃逸。
只允许本轮root拥有、不可写、最多16文件/每文件64KiB的明确非生产快照和批准记录。

原生参数复用生产`-lang java -json -json_nodots -j 1 -timeout 5 -max_memory 512`及本地固定rules。
max_memory是原工具参数，不宣称新增内核/cgroup硬quota。Native core直接读离线文件，不用自动联网的规则/CLI安装流程。
临时工具/打包峰值预算700MiB；准备前要求空闲磁盘和内存各大于2GiB。实际空闲磁盘约42GiB、内存约5GiB。
未改生产预算或Trivy45.78GiB hard floor；该磁盘状态没有获得任何Trivy许可。

## Fixture、真实结果与次数

本轮用户指令授权专用synthetic/disposable/non-production fixtures。
管理端批准记录绑定project/profile、真实临时Git revision、文件manifest、源目录inode/device和执行UID；导出只保留元数据与摘要。
Fake PAT由临时控制器生成，从未签发或认证，未使用生产Secret。授权不延伸到Jenkins CI或私有项目。
java-fixture/java-web的Clean和Vulnerable复用生产Gate已有Java正反例；第二项目service-fixture/container-service使用不同Java源码。
规则只支持Java，因此**没有宣称Python SAST**；Python-only用例实际UNSUPPORTED，Policy=null。

| 最终验收轮用例 | Gitleaks | Semgrep | 观察 |
|---|---|---|---|
| 1 两者启用、Clean | PASS | PASS | 两个原生工具真实执行，各Policy一次 |
| 2 Gitleaks关闭 | DISABLED/null | PASS | Gitleaks启动0 |
| 3 Semgrep关闭 | PASS | DISABLED/null | Semgrep启动0 |
| 4 全部关闭 | DISABLED/null | DISABLED/null | 工具0、Policy0，Summary DISABLED |
| 5 Semgrep执行失败 | PASS | ERROR/null | 受控1ms timeout，真实版本进程启动，尚未进入native scan；Candidate Build=false |
| 6 Gitleaks假凭证 | FAIL | PASS | 两个真实结果独立保留 |
| 7 Semgrep高危 | PASS | FAIL | 2条真实Finding；原classifier与standard均FAIL |
| 8 master OFF | DISABLED/null | DISABLED/null | Candidate Build/Test可继续，Promotion BLOCKED |
| 跨项目 | PASS | PASS | container-service，不同源码/revision/artifact，同Manager/Schema |
| 普通命令观察 | PASS | WARN | 原Finding classifier WARN，与Policy相同；非生产wrapper失败 |
| 缺Semgrep能力 | PASS | NOT_CONFIGURED/null | Semgrep进程0，独立保留Gitleaks结果 |
| Python-only | DISABLED/null | UNSUPPORTED/null | 没有适用Java文件，不生成PASS |
| parser prefilter观察 | PASS | PASS | 原生报告errors=[]、没有选中规则；不伪造解析失败 |
| 未批准目录 | PASS | POLICY_ERROR/null | /etc被拒绝，Semgrep启动0 |

最终成功轮：**14个Manager用例**；Gitleaks实际10次目录扫描/20次binary调用；Semgrep实际7次native scan/15次binary调用，
其中1次是超时的版本进程，其余7组为version+scan。另有5个真实权限/不可写负例与2次Router投递测试。
不能把disabled/capability拒绝/timeout前未扫描计成成功扫描。
前两轮失败尝试单独保留，不混入成功轮计数：首轮包缺Gitleaks冻结依赖，Gitleaks ERROR、Semgrep真实PASS；第二轮停在错误的解析负例预期。
连同失败尝试，已封存24次真实目录扫描（Gitleaks13、Semgrep11）；工具版本探测与执行进程详见controller日志和runtime facts。
这不是24次生产运行，也不改变14/16。

## 原Gate/Policy等价范围

复用原`classifySemgrep`，没有重写检测规则或Policy算法。已真实证明：Clean零Finding PASS/PASS；
高危fixture包含java-weak-cipher和普通java-runtime-exec，原classifier FAIL、standard FAIL，Finding和ERROR severity保持原值。

必须区分：**Finding classifier**会把普通命令观察记WARN；原combined command-audit + Semgrep shell阶段可在仅warning时exit0。
本轮warning用例完整保留classifier=WARN、productionAcceptance=PASS、Policy=WARN三者，未把它声称为完整父Gate的PASS→WARN迁移证明。
SEMGREP_OLD_GATE_POLICY_EQUIVALENCE=VERIFIED仅表示已测Finding分类及Clean/高危验收分支；
生产command-audit、Lease、Pod、网络、lifecycle合成父Gate未真实重跑。其冻结逻辑只有独立REPLAY回归，不能拼接成same-run生产证明。

解析错误、执行错误、缺报告分别拒绝为ERROR/NOT_CONFIGURED，没有Policy PASS。
破损文本最初未触发错误：原生prefilter没有选中规则，errors=[]且paths.scanned列出目标；原输出已保留。
没有修改规则或谎报真实解析负例VERIFIED。**原生实际报告parse-error的负例本轮NOT_TESTED**；非空errors/畸形JSON的拒绝由单元测试覆盖。
真实异常隔离由受控超时、未授权路径及缺能力验证。

## Result、Artifact与Router

14个独立artifact均由verifyArtifact反复验证；每插件包含managerVersion/runId/projectId/effectiveProfile/policyVersion/
securityEnabled/globalMode/securityLevel/pluginId/pluginVersion/executionStatus/policyDecision/rawReportDigest/factDigest/resultDigest/evidenceRefs。
每个已完成插件Policy evaluationCount=1；disabled/error/unsupported/blocked为0，没有“未执行的PASS”。
Semgrep raw collection保留每次stdout的完整原始UTF-8字节及SHA，并另保留parsed objects；normalize后的Finding与原对象逐项相同。
Gate与Summary在真实测试中strictEqual为同一个冻结Result，Router复用相同resultDigest且无扫描/Policy计数增加。

首次Router投递：DRY_RUN / DELIVERED_LOCAL_ONLY / DISABLED；重复投递到独占目录产生单独ERROR Receipt，其他consumer和插件事实不变。
没有向生产Dojo/Loki/Grafana写入。Candidate Artifact为可验篡改封存，不宣称WORM或生产ImmutableArtifact完成。

## 测试、失败记录和历史证据事件

- 最终本地相关测试：89/89（Manager含Semgrep26项、既有Manager52项、原Semgrep分类2项、Gitleaks源锁9项）。STATIC/FIXTURE。
- Policy/command相关回归：141/141，属于STATIC/FIXTURE/CONTROLLED_REPLAY，不计真实扫描。
- 最终临时干净checkout：**230/230**；老测试写入仅发生在临时树，随后删除。见clean-checkout-attempt3.json/tap。
- 真实Linux：14个受控用例、5个权限检查、2次Router投递；见execution-verification.json和real-linux/outputs/attempt3-*。
- 所有早期失败保留：准备脚本误写文件数28（实际27，未扫描）；首次真实包漏Gitleaks动态冻结依赖；解析负例预期不成立；
  首次干净包未带旧未跟踪测试、第二次缺旧test hook输出目录。未过滤失败日志、未伪造通过。

**历史证据写入事件（本轮操作错误）：**我在仓库根运行旧command-parent回归，其hardcoded输出覆盖了78个历史synthetic replay文件。
发现后停止该类根目录测试，保留全部本轮生成副本、原始基线SHA和事件记录。原文件未被Git跟踪，Git/现有副本检索未找到完整原bytes。
两份可由不变catalog payload复原；其余根据不变replay输入与仅变化的VM报告时间字符串恢复候选，
**只有候选完整SHA与本轮开始前SHA严格相等时才写回**。最后修复differential原hash，78个文件均恢复原字节。
这不是修改真实运行事实，也没有改任何旧manifest或把旧完整性改为VERIFIED。
文件确实被写过，mtime发生变化；不宣称历史从未被触碰或WORM。该错误与修复是本轮证据的一部分。
`legacy-evidence-incident.json`、生成副本、exact-byte-recovery-receipt.json和exact-byte-tail-recovery-receipt.json保留全过程。
最终**12,030个受保护文件的bytes SHA全部匹配起始基线**；ORIGINAL_EVIDENCE_INTEGRITY仍FAILED。

## 生产、清理、未完成项及回滚

前后只读一致：Jenkins petclinic-ci #270 SUCCESS、lastBuild270、job定义SHA不变；
V1 SHA ec9ee51a06d4b9f61c6c0eaf50b374d1e25e6d3ca687908b7596d3a2c794f5d8；Argo Synced/Healthy；
三节点Ready；PetClinic3/3、快照HTTP200；socket0660；Deployment UID/generation/spec/digest不变。
生产digest仍489cb821573ff1f98edd846d5949d74bf3391b24e2f1fe5bcfb71c6be0793137。
Trivy仅只读核对Pod和metadata.json hash/stat；Dojo仅Pod元数据，不宣称检查其全部数据库字节。
这不是持续负载/无中断测试。

导出407个证据文件前逐字节排除假PAT明文；未导出源码、binary、生产Secret或key。
清理前再验证全部导出SHA和无临时域进程；工具、七份源码、approval、临时Git、package与outputs全部定向删除，残留进程0。
准备失败的首个临时目录也已定向删除。Pod/Node/SA/RBAC/NetworkPolicy创建/删除均0；Docker/服务配置变更0；
image build/push、Jenkins CI、Git push、release、rollout均0。

未完成：Jenkins独立身份与真实CI、Cosign真实Runner、Trivy/Dojo Runtime、正式Summary V2与Security Manager激活。
原禁用CI release继续固定Candidate.2；其source guard不能直接接纳Candidate.3，应在未来独立阶段审核新版本包，绝不改旧manifest放行。
本轮不推进这些分支。代码回滚只需停用Candidate CLI，或定向撤回本轮本地提交并保留证据；生产无需回滚。

**唯一下一步允许操作：评审本轮Semgrep与双插件真实证据及事件修复记录，确定下一阶段专项范围。**
本轮不启用CI/Agent、不推进Cosign/Trivy/Dojo或生产迁移；到此STOP。
