# Cosign 第三个真实 Candidate 插件与历史证据写保护

2026-11-05；本地基线34c4b783，Candidate版本2.0.0-candidate.4。本轮没有push、Jenkins CI、Agent、生产签名、发布或rollout。
验收限于**受控离线对象、公钥固定、Linux ARM64工具专用执行**。不是生产registry/keyless/admission验收，不增加canonical 14/16。

## 历史事件复核及写保护

上轮覆盖事件继续为CONFIRMED。读取上轮incident清单及两份恢复receipt，78个历史文件的内容SHA与上轮事前基线完全一致。
上轮mtime变化不消除；ORIGINAL_EVIDENCE_INTEGRITY永久保持FAILED。本轮没有重新生成或修复任何旧evidence。

具体危险入口：`infra/security/policy/command-parent.test.mjs`写`evidence/2026-11-01/command-parent/{fixtures/*,differential.json}`；
`command-evidence.test.mjs`写remaining-policy；本轮旧`cosign-parent.test.mjs`同样写`evidence/2026-11-01/cosign-parent/`。
因此所有Node测试都只能运行在新建、唯一、无symlink/hardlink的临时Git副本，cwd禁止指向实际仓库。

新增`infra/security/testing/evidence-boundary.py`调用macOS原生sandbox-exec：禁止网络、禁止全部文件写操作，
仅允许唯一临时树和/dev/null。实际预检对本轮自有canary的overwrite/unlink/chmod/mkdir均DENIED，
临时树写入正常，实际仓库作为cwd被前置校验拒绝。没有拿历史文件进行删除/覆盖探测。
命令在初始外层sandbox中被系统拒绝后，通过明确批准在外层执行原生sandbox能力检查成功；没有绕过测试内部保护。
这是本地测试边界，不是Linux生产scanner隔离声明。

三轮隔离回归都通过，最终393/393；每次前后分别核对内容与元数据。
最终**12,581个受保护文件**SHA、size、mtime、ctime、mode、UID/GID、inode、symlink状态均不变；历史文件列表新增0/删除0。
atime可能因读取变化，不做atime不变声明。本轮测试临时副本均删除，旧历史输入只复制不修改；生成摘要只从临时树导出到本轮新目录。
证据：write-boundary-preflight.json、offline-attempt3.json、protected-after-comparison.json。

## 实际代码变更及兼容性

新增Cosign runner、测试、三插件真实suite、写保护脚本、新的版本化Candidate evidence模式。
修改现有Manager registry/core/CLI/README，复用原core、Policy owner、Result/Artifact、Summary和离线Router。
没有第二套Manager或Policy Engine；**Gitleaks Runner、Semgrep Runner、Router和Consumer业务逻辑均未改**。

- `realThreePluginsRegistry()`在原双插件定义上增加固定ID cosign、candidate.4、默认disabled的verify-only runner。
- 独立10秒deadline；工具、对象、身份和报告各有能力检查。
- `COSIGN_BINARY/COSIGN_VERSION/OFFLINE_SIGNED_OBJECT/TRUSTED_VERIFICATION_IDENTITY/SIGNATURE_SOURCE/POLICY_VERSION/VALIDATION_OUTPUT_DIR/TRUSTED_VALIDATION_WORKSPACE`。
- 能力声明不授予信任；root-owned不可写approval绑定project、object hash、signature hash、public key hash、工具SHA、输出域及执行UID。
- 禁止自由命令、项目JS、任意私钥路径、自动接受签名自带身份或下载。实际二进制缺失返回NOT_CONFIGURED，不产生PASS。
- CLI增加`--cosign-approval`和`--cosign-object`，可组合原两个插件的批准/source参数。
- Summary追加兼容字段validationRunId与overallDecision，保留runId/overallStatus及全部既有字段。

原`signing.mjs`、生产Cosign Gate和原manifest不变。原cosign-parent源码SHA为
cacf526148868324f82e8b0ad073674eaf59bdeb9da4123d833fa7b008bd3d33。
原manifest SHA为4d497c2de02ce04489c6203c7e733cac343f011dace3cdeb64782f32ebd688ea，8项源码身份全部匹配。
在现有Policy入口增加明确`candidate-offline-blob-v1`分支；去掉唯一标记的import/dispatch块后必须逐字节还原原parent，运行时与测试均校验。
版本记录为`cosign-blob-candidate-v1.json`，没有改旧manifest或放宽旧规则。

Candidate分支调用原signing.mjs中的**完整、未重写的cosign command checker**，以真实命令观察作为输入：
原wrapper成功→PASS，原wrapper拒绝→FAIL。没有在Policy里做密码学、生成签名或重新推断信任。
原Engine源码/生产Gate不改；旧阶段仍走原分支。隔离REPLAY中**260个旧Gate差分（18 PASS、242 FAIL）全部一致**。
历史Jenkins security-runtime-facts-20261102 #32 SUCCESS及原receipt只读复核为HISTORICAL_ARCHIVE，未恢复旧私钥，不计入本轮真实验证。

## 固定工具、测试信任及真实执行

- Cosign3.1.4，gitCommit0e48502cf5ef34e2e60bbd3617aa19945712f705、linux/arm64。
- Binary SHA ade83b7aac62e131cacfe96d958948b2150cc9efec46a570a2649b8e27dedad2，136,437,761 bytes。
- 来源为既有已锁定生产离线工具包的只读复制，工具manifest SHA4fdb335010b9bf57d61d5e28d1397285c813bfa9bbf2ac008efddb8f27e3b703。
- Semgrep1.182.1与Gitleaks8.30.1复用前轮固定来源；Semgrep27个native依赖逐一校验，Gitleaks从已有k3s缓存验证OCI链提取。
- 不下载、不安装、不用rootful Docker、不创建容器/Pod、不推registry。工具临时副本预算900MiB，开始前磁盘和内存均要求大于2GiB；未改生产或Trivy阈值。

在既有工具专用受控执行方式运行：UID/GID65534、无额外组、NoNewPrivs、零capabilities、清空环境、固定参数。
仅解析root拥有的合成源码，不执行项目代码；不能当作通用不可信Jenkins Agent或对抗性进程隔离。

在独立700目录由真实Cosign生成**两对本轮专用测试密钥**，分属java-fixture与service-fixture；
仅签署本地JSON，生成3份测试签名。原临时生成私钥不复用，生产私钥未读取；没有sign IMAGE或生产registry访问。
签名完成后，整个私钥目录在Manager启动前删除，最终再次确认`.key`文件0。
批准记录固定测试公钥，scope=CONTROLLED_TEST_ONLY_NOT_PRODUCTION；不能把测试身份变成生产可信身份或Promotion资格。

实际`verify-blob --key <固定测试pub> --insecure-ignore-tlog=true --signature <固定sig> <本地对象>`。
无签名负例故意不传--signature，让真实Cosign拒绝。该选项沿用原本地key-based生产命令形态，
**仅验证对象签名，不验证transparency log、keyless certificate/issuer或registry trust**。
Cosign原生警告被完整保留；没有把警告抹去或宣称Sigstore透明日志验收完成。
[Cosign3.1.4原生实现](https://raw.githubusercontent.com/sigstore/cosign/v3.1.4/cmd/cosign/cli/verify/verify_blob.go)定义此本地公钥/签名验证路径。

## 真实矩阵与次数

主验收轮attempt2：同一Manager进程、同轮源码与对象、三个真实工具，没有用历史报告代替执行。

| 用例 | Gitleaks | Semgrep | Cosign | 结论 |
|---|---|---|---|---|
| A 全启用有效对象 | PASS | PASS | PASS | 真实Verified OK/exit0 |
| B 只关Cosign | PASS | PASS | DISABLED | Cosign调用0 |
| C 只关Semgrep | PASS | DISABLED | PASS | Semgrep调用0 |
| D 只关Gitleaks | DISABLED | PASS | PASS | Gitleaks调用0 |
| E 全关 | DISABLED | DISABLED | DISABLED | 无扫描/Policy PASS |
| F 对象篡改 | PASS | PASS | FAIL | 原生invalid signature、exit1 |
| G Semgrep高危 | PASS | FAIL | PASS | 各结果独立 |
| H Gitleaks假凭证 | FAIL | PASS | PASS | 各结果独立 |
| I Cosign超时 | PASS | PASS | ERROR | 版本进程受控超时，无Policy PASS |
| J globalMode=off | DISABLED | DISABLED | DISABLED | Candidate Build允许，Promotion BLOCKED |
| K master=false | DISABLED | DISABLED | DISABLED | 同上 |
| L 错误信任身份 | PASS | PASS | FAIL | service测试key签署，java固定pub拒绝 |
| M 缺失签名 | PASS | PASS | FAIL | 原生missing flag --signature |
| N 格式损坏签名 | PASS | PASS | FAIL | 原生Invalid IEEE_P1363 encoded bytes |
| O 工具能力缺失 | PASS | PASS | NOT_CONFIGURED | verifier调用0 |
| P 第二项目 | PASS | PASS | PASS | container-service，独立公钥/对象/输出 |
| Q 冒用另一项目对象 | PASS | PASS | POLICY_ERROR | 启动前拒绝，verifier调用0 |

attempt2主轮**17个用例**：Gitleaks13 scans/26 binary calls、Semgrep13 scans/26 binary calls、Cosign10 verifications/21 binary calls。
Cosign10次包括6次成功、4次签名拒绝；21次调用包括10组version+verify和一次超时version。不能把timeout叫签名验证成功。
首轮同一17用例也通过，单独保存，不拼接成一次same-run。
整个本轮两个主轮合计：Gitleaks26 scans、Semgrep26 scans、Cosign20 verifications/42 runner binary calls；
另有准备期Cosign版本探测1次、测试key生成2次、测试sign-blob3次，全部与生产签名严格分开。

**补充的实际文件缺失**：另一个不安装扫描binary、不生成密钥的临时域，用公开测试材料仅建立批准前提。
能力hint均AVAILABLE但Cosign文件实际不存在，返回NOT_CONFIGURED/COSIGN_TOOL_NOT_CONFIGURED、Policy=null、evaluation0、binary调用0。
它是REAL filesystem prerequisite test，不是本轮额外Cosign密码学验证；其签名材料明确为公开测试fixture重用。
临时域已删除。证据actual-missing-tool-execution.json。

## Gate等价、错误及结果复用范围

真实Cosign事实完整绑定项目、对象SHA、签名SHA/缺失、固定key hash、工具版本/SHA、命令/exit/stdout/stderr、批准摘要及runId。
每个completed结果都保留原raw、fact、runtime facts；Policy每插件只求值一次，原事实不修改、不增造severity。
有效PASS、篡改FAIL、错误身份FAIL、必须签名缺失FAIL、损坏签名FAIL，均与原verify-blob checker一致。
签名格式损坏是原生非零验证拒绝，对应Policy FAIL，不伪造ERROR诊断。

操作超时/工具不存在属于Candidate执行状态ERROR/NOT_CONFIGURED，没有完成验证事实、Policy=null且0次求值。
原生产同步wrapper没有这些typed plugin状态，其失败会阻止原Gate成功；本轮没有编造两套typed状态逐字相等。
本地测试证明两者都不能PASS，Candidate Promotion始终BLOCKED。
恶意/malformed evidence返回明确POLICY_ERROR或缺证据null；这属于新输入契约拒绝，**不声称旧生产Gate接受过该新schema**。
COSIGN_OLD_GATE_POLICY_EQUIVALENCE=VERIFIED仅表示原验收命令的已测PASS/FAIL及260个旧完整阶段差分。
不宣称本轮真实重跑生产signing/Lease/registry/准入/透明日志链。

Manager Gate与Summary真实测试strictEqual同一个冻结Result；每个completed evaluationCount=1，其他状态0。
独立rawReportDigest/factDigest/resultDigest与Artifact seal均验证通过。Summary包含所有三个独立结果和状态别名，缺证据不补PASS。
Router沿用dry-run/local-evidence：首次成功，重复独占目录投递返回独立ERROR receipt，其他consumer结果不变。
Router前后工具/Policy计数不增，三个resultDigest均复用；无Dojo/Loki/Grafana生产投递。
跨项目java-web/container-service真实执行、独立公钥和artifact；跨项目对象冒用在验证前拒绝。
Candidate Artifact只提供篡改检测，不宣称生产WORM或canonical16/16。

## 测试与保留的异常

- REAL：17个主矩阵用例、5个真实文件/权限拒绝、2次Router投递；另1个实际缺工具前置检查。
- STATIC/FIXTURE/REPLAY：最终**393/393**，全部在OS写保护的临时副本执行；含260个旧Cosign Gate差分。
- HISTORICAL_ARCHIVE：#32、既有Trivy/Helm兼容证据；未重跑无关大规模实验，未计为本轮真实调用。
- 未运行：Jenkins CI、Agent、生产签名/registry、Trivy/Dojo、生产Summary V2。

补充缺工具用例首次被测试suite的prefix白名单拒绝，未进入任何插件。失败stderr与controller记录保留。
修复仅调整测试入口参数/补充receipt文件名，不更改工具/Gate判定。之后用独立最小临时域真实补验文件不存在。
主矩阵和实际缺失的代码包都保存SHA；主矩阵之后唯一harness变化是该补充模式的输出文件名/统计显示，
Runner/Core/Registry/Policy等实际执行代码与最终版本一致；最小缺失检查使用完整最终包且hash全一致。

## 清理、生产及下一步

导出790个文件前排除测试假PAT明文和全部私钥PEM标记；未导出扫描源码、二进制或生产资产。
允许导出本轮无害JSON、公钥和签名，以绑定密码学测试材料；公开材料不是私钥。
清理前全部导出hash重验、临时域进程0、private目录不存在/.key=0；工具、源码、批准、package、outputs全部定向删除。
实际缺失补充临时域也删除，没有删除任何非本轮资源。遗留高权限组件0。

生产前后只读快照完全一致：#270 SUCCESS、lastBuild270、V1 Summary和job定义SHA不变；
Argo Synced/Healthy、三节点Ready、PetClinic3/3、快照HTTP200；image digest仍489cb821573ff1f98edd846d5949d74bf3391b24e2f1fe5bcfb71c6be0793137；
socket0660；Docker MainPID983、activeEnter monotonic10842937、NRestarts0不变。
Trivy仅核对metadata.json hash/stat与Pod身份，不宣称全DB字节不变；Dojo仅Pod UID/image/readiness/restarts，不读取数据库。
这是健康快照，不是持续HTTP压测或生产发布验收。

生产Security Manager NOT_ACTIVE；Jenkins真实CI、Trivy/Dojo、REAL_RUNTIME_FACT_CAPTURE、REAL_POLICY_OWNER、
IMMUTABLE_ARTIFACT_RUNTIME、SUMMARY_V2_MIGRATION仍INCOMPLETE；FINAL_WIRED_CAPABILITY仍14/16；原完整性FAILED。
Agent Pod/Kubernetes资源创建0、Docker配置变更0、生产签名/registry写0、Git push0、release0、rollout0。

回滚：停用Candidate CLI或定向撤回本轮本地提交，保留新证据；生产没有配置需要回滚，不删除历史、namespace或业务资源。
唯一下一步建议：评审本轮三个真实插件的限定验收范围、写保护和后续独立阶段；未授权进入Jenkins/Trivy/Dojo或生产激活。
本轮到此STOP。
