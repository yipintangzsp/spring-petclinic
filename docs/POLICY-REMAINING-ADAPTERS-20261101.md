# Remaining production Gate adapter 差分阶段

结论：**尚不具备全生产Gate standard兼容证明，不允许进入实际Summary接入。** 本轮增加adapter和独立差分，没有改生产Gate、业务发布、Dojo耦合、Loki查询或Provenance opt-in。未触发Jenkins、scanner、rollout或创建常驻组件。

Sonar真实负例继续按最新约定DEFERRED_REAL_NEGATIVE_EVIDENCE保留，不作为本轮结构性blocker。

## 本轮实际实现与验证

新增 `frozen-contract-evidence.mjs`、`sbom-evidence.mjs`、`command-evidence.mjs`，Policy Engine仅增加独立调用分支；原manager/业务入口尚未接入。原pure contract直接复用，未改规则或severity，proof类不应用严重级别覆盖或audit降级。

- SBOM：对比原 `sbom-verify.mjs` 在无I/O VM中的实际执行，原字节一致性、CycloneDX版本/非空依赖及唯一引用条件原样保留，6个样本。
- Cosign CLI：调用原 `checkCosignVerification`，6个样本。unsigned/wrong-key被正确拒绝是安全自检PASS，不误记为整个Gate失败；registry连接失败不能冒充有效签名负例。
- Falco历史退出/连续性/持久行为：复用原pure contracts，分别3/4/3个样本；已有历史非干净退出保留WARN，重启/身份变化和确认持续行为仍FAIL。不等于整个sensor健康阶段已覆盖。
- 两类Attestation签名/身份：分别5个样本。直接读取已有Jenkins270归档的真实signed envelope/public key/expected identity作正例，原verifyEnvelope+validate/validateBuildStatement作为对照；改变expected image/source/builder或tampered envelope属于明确标记的本地合成负例，不伪称自然生产失败。
- 安全审批证据及签名集合：分别5/2个样本，复用原validateGate/approvedRelease；未运行Git mutation或签名发布。只是审批子契约，不是整个promotion执行链兼容证明。
- 命令分析：5个样本执行原command-audit.mjs内嵌的纯静态Python分析程序，原policy源码不变；从不执行被检查代码。固定命令、未知环境输入维持旧Gate PASS；确认直接外部shell/interpreter流维持FAIL；原解析器crash无JSON时，旧wrapper JSON.parse失败，adapter保留ERROR/FAIL而非构造空成功报告。

**本轮新增44个差分样本（39个纯契约+5个命令样本），加已有测试合计62/62通过。** 每个差分记录有legacy/standard及原事实不变验证。对照Oracle为未修改原函数或原执行片段，未使用新adapter产生期望结果。

命令语法错误用例第一次测试失败：原analyzer在该路径没有JSON输出，测试原先假定总有报告。原失败日志command-tests.log保留；补充run事实归一化后command-tests-after.log通过，没有改原解析器或绕过失败。

## A/B/C/D：全部18个生产来源的当前状态

表中“样本数”是已有独立差分记录数；NOT_TESTED行即便有子契约样本，也**不意味着整个父生产阶段兼容已验证**。此前用户认可的四个VERIFIED保留其分类范围，未擅自升级为执行生命周期覆盖。

| 生产来源 | 当前状态 | 差分样本数 | 尚缺/范围 |
| --- | --- | ---: | --- |
| sbom | NOT_TESTED | 6 | 字节/内容验证已验证；Maven构建/打包失败及工具运行前置事实未冻结 |
| regression | NOT_TESTED | 0 | 原测试runner失败/超时/中止事实与新模型尚未映射；不能把生产安全回归Gate排除为N/A |
| falco-baseline | NOT_TESTED | 3 | prior-exit子契约已验证；DS/Pod/image/rules/稳定运行时间/HTTP等聚合条件未覆盖 |
| kyverno | NOT_TESTED | 0 | RBAC/CRD/聚合角色、GitOps健康、server dry-run结果/具体策略拒绝及exception绑定尚无完整adapter差分 |
| kubescape | NOT_TESTED | 0 | 工具/离线制品hash、最小权限、四份完整原始报告、运行失败与AUDIT聚合尚未映射；历史finding不能被提升FAIL |
| gitleaks | VERIFIED | 7 | 限既有精确审查分类；扫描隔离/执行/回收不在7例范围 |
| semgrep | VERIFIED | 8 | 限原规则分类；其他前置自检/执行故障不在8例范围 |
| sops | NOT_TESTED | 0 | 解密成功、精确scope、type/data一致、Secret UID/values不变、两组RBAC边界；需要脱敏但足以复核的证据模型，不能归档明文凭据或仅相信success |
| trivy | VERIFIED | 8 | 限既有漏洞分类；candidate前置与平台报告完整性不在8例范围 |
| cosign | NOT_TESTED | 6 | CLI分类已验证；实际server admission/policy身份、fixture manifest身份、私钥清理等未完整映射 |
| sonarqube | DEFERRED_REAL_NEGATIVE_EVIDENCE | 1真实正例 | 正例VERIFIED；真实负例缺task/analysis直接绑定，继续延后，不阻塞其他来源 |
| zap | VERIFIED | 4 | 限既有无确认finding分类；确认利用证据绑定/过期/fixture等完整生产阶段未覆盖 |
| falco-final | NOT_TESTED | 7 | continuity/persistence子契约已验证；baseline/source/build绑定、采样/driver/HTTP/覆盖与执行约束未全覆盖 |
| defectdojo | NOT_TESTED | 0 | native报告完整性、source/build绑定、导入查询/分页/reimport稳定性和已有误报同步失败事实尚未完整映射；本轮不改文件耦合 |
| provenance | NOT_TESTED | 5 | 签名/身份子契约有真实正例；generate/create/verify聚合失败、工具/lock、负控及临时文件清理尚未全覆盖；opt-in未变 |
| build-provenance | NOT_TESTED | 5 | build签名/statement子契约有真实正例；完整consumer阶段执行/负控/清理尚未全覆盖；opt-in未变 |
| semgrep-command-audit | NOT_TESTED | 5 | 组合静态分类/无JSON故障已验证；Pod准入/镜像/等待/UID保护/清理未覆盖 |
| security-approval-promotion | NOT_TESTED | 7 | 审批/签名集合子契约已验证；已签approval与manifest并发身份等下游校验未全部适配；不执行发布 |

没有把任何未覆盖的当前Gate标成NOT_APPLICABLE。没有将真实正例+合成负例提升为真实生产负例VERIFIED。

## E：兼容证明的剩余blocker与停止点

本轮并无standard差分判定漂移（已执行的44个新增样本均一致），但**完整覆盖的前提仍不成立**：

1. SOPS、Kyverno/RBAC、Kubescape、Dojo尚无完整事实adapter和独立冻结正反例。
2. 新增pure contract的父阶段还有未表示的operational/lifecycle/aggregate条件。旧Gate不能被简化为某个pure helper通过，更不能以归档status=success代替所有原始条件。
3. 原四项VERIFIED也是分类范围，执行条件需要在“全生产Gate”口径明确保留并验证；当前不能宣称所有来源已经兼容。

这是尚未完成的adapter/证明工作，不是声称平台故障、Gate已损坏或资源权限阻塞。按“仍有影响standard兼容证明的blocker则停止、不进Summary”要求，本轮停在上述可复核状态，未自行豁免来源。

最小后续工作仍是adapter阶段：先冻结SOPS精确比较与权限边界的安全证据契约，禁止凭据进入输出；再按原源码predicate逐项补Kyverno、Kubescape、Dojo，补父阶段执行/聚合条件，纯对照执行不得触发网络写入或业务动作。全部完成前不接实际security-summary.json。Sonar真实负例继续独立延后。

## 证据

`evidence/2026-11-01/remaining-policy/production-differential-status.json` 给出18项状态与子契约计数；contract-differential.json、command-differential.json保存新增差分记录；all-policy-tests.log记录62/62；archived-270.json保存只读取得的既有公开签名与脱敏Gate原始报告。没有获取私钥或Secret值。

原108个非policy目录安全实现文件hash全部与冻结清单一致，见original-source-integrity.json。没有修改扫描器、Gate脚本、现有Summary消费者或生产配置。源码与新增文档仅本地未提交，回滚只需撤销本轮新增policy文件/分支与证据报告，不涉及平台数据。
