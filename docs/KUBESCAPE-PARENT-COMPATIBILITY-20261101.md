# Kubescape production compatibility 收口

**Kubescape = VERIFIED**，范围限当前冻结源码在baseline-v1/standard的完整Gate判定兼容性。不是新生产扫描验收，不证明当前主机工具/集群实时健康或全量CIS合规。本轮结束停止，不开始DefectDojo或Summary接入。

## 1–3. 原入口、消费事实、capability

生产adapter的Kubescape Audit阶段执行 `node --max-old-space-size=128 infra/security/governance/kubescape.mjs`。原框架与聚合由kubescape-report.mjs处理，tool/framework/artifact锁来自governance/tools-lock.json的kubescape段。

原Gate顺序：读取lock、创建输出目录、读取.git-sha；核验binary与4个离线artifact摘要；读取现有outer Lease并匹配holder；创建0700临时目录；读取kubectl当前server和namespace CA，请求原30分钟只读token并写临时kubeconfig；确认Secrets list和业务patch均no；按NSA/CIS顺序分别扫描cluster与k8s/production YAML，共4次。参数保留host-scan=false、keep-local、exclude-kinds Secret、固定context/离线artifacts/exceptions/controls-inputs、5分钟scan和20秒control timeout，进程限时330秒。

没有新增“manifest缺失即SKIPPED”等规则。原代码没有事先stat manifest或验证server URL/token非空；相应能力问题由实际CLI错误或原解析/编码错误表现，不能补造新Gate。缺少本轮重放事实本身返回NOT_CONFIGURED且decision=null；已观察到的执行失败仍FAIL。

消费原生JSON字段：results[].resourceID、controls[].controlID/status/severity，resources数量，summaryDetails.controls/complianceScore/resourcesSeverityCounters。复用原summarizeKubescape/combineKubescape，不重新计算Kubescape complianceScore，不发明severity。原聚合按scope+control去重failedControls、按scope+resource+control去重finding，High/Critical只用于highRiskFindings计数。

## 4. Adapter

新增kubescape-parent.mjs和版本绑定；Engine增加kubescape完整输入入口。保留之前kubescape-evidence.mjs及3项局部测试，没有重写或丢弃它们。

adapter核验原执行/读取/写入/cleanup事实，调用原report helpers生成相同四份摘要和聚合。原Gate与helper的冻结SHA变化则POLICY_ERROR，不默用旧baseline。没有调用Kubescape扫描器或新增Kubernetes操作。

## 5–10. 样本与AUDIT/错误语义

真实历史原生报告4份来自Jenkins #270，仅通过已有权限读取归档。为避免导出资源spec/配置值，服务端仅读取并投影**原helper实际消费字段**；resources以相同长度空对象数组表示，其余被消费的控制/风险字段保留。原文件字节数和SHA保留；原远端文件未改。不能声称本地投影是完整原始文件副本。

**45个完整Gate fixture全部是受控冻结重放**：1个基础fixture含上述历史投影，其余为合成变体；不是45次真实扫描，也不是历史生产事故。旧Oracle完整执行原kubescape.mjs，只将外部命令/文件/时钟相关环境换为冻结观察；hash调用使用输入的observed digest，不声称重新验算真实二进制字节。无网络、真实token、扫描或临时kubeconfig文件。

| 样本分组 | 数量 | old / standard |
| --- | ---: | --- |
| AUDIT与去重聚合 | 4 | PASS/PASS |
| 前置/执行/报告/cleanup故障 | 38 | FAIL/FAIL |
| 后续三次framework分别失败 | 3 | FAIL/FAIL |

4个成功输入覆盖历史findings、零findings、跨framework同control/resource重复、仅failed controls而无resource配对。失败覆盖lock/输出/source、binary/artifact缺失或hash错、Lease请求/JSON/holder、临时目录/chmod、context/CA/token、kubeconfig写、最小权限检查、进程非零/timeout、报告缺失/JSON损坏/结构错误/风险分数损坏/摘要再读失败、日志/最终报告写入、cleanup单独失败和与其他失败组合。

### AUDIT不是安全PASS

原Gate没有基于failed controls、severity或finding数量阻断的条件：完整扫描成功时status=success，CLI退出0；历史finding始终AUDIT。adapter保留：

- `decision=PASS`：仅指原流水线Gate未阻断，与旧Gate一致；
- `executionStatus=success`：原进程/报告执行完成；
- `auditMode=AUDIT`、`auditDisposition=WARN`：有finding或failed control时风险仍可见；
- 全部原摘要、severity计数、resource/control关联保留。

零发现另标NO_FINDINGS，不宣称系统安全或宿主CIS完整。不能把High/Critical计数改成新FAIL；strict/override亦不重新解释冻结的AUDIT Gate。

## 11–15. 完整差分与不变性

- complete Gate differential总数 **45**。
- matched **45** / mismatched **0**。
- old：PASS4、FAIL41；standard：PASS4、FAIL41。
- raw facts preserved：YES；逐例检查整个输入JSON和返回证据不变。
- 所有成功样本逐字段比较旧/新scope/framework、failed controls、resources/controls数量、resourceControlFindings、nativeSeverityCounters、complianceScore与聚合计数。

最初“报告第二次读取/hash失败”用例发现Oracle未区分首次读JSON和第二次读摘要观察，导致预期失败未触发。修正测试观察映射后全部一致；初始日志保留，没有改原Gate或放宽判定。

## 16–19. 缺口、状态、测试与离开条件

本轮没有已知结构性standard兼容分支缺口。自然生产执行故障的完整历史记录仍未取得，分类DEFERRED_REAL_NEGATIVE_EVIDENCE；控制条件已用完整旧代码冻结重放，不因未发生自然事故永久阻塞。

最终Kubescape **VERIFIED**（限定冻结逻辑兼容）；本来源可离开compatibility阶段。本轮46项测试（45差分+1缺证据），全部Policy tests **232/232 PASS**。不等于真实扫描工具执行、token创建、权限即时验收或覆盖所有可能输入的形式证明。

原kubescape.mjs、report helper、tools-lock及实际Summary SHA未变。未修改Jenkins/Argo/业务，未读取Kubernetes Secret，未创建资源或token，无权限扩大，无rollout和新组件。

保留全局未解项：SOPS/age=NOT_TESTED/ENVIRONMENT_BLOCKED，Sonar真实负例=DEFERRED_REAL_NEGATIVE_EVIDENCE。它们没有被本轮结果清除。未进入DefectDojo、Result Router或Summary接入。

证据目录：evidence/2026-11-01/kubescape-parent。acceptance.json为最终范围与计数，archived-consumed-fields.json为历史投影及原SHA，differential.json为逐例结果，source-integrity.json为不变性证明，all-policy-tests.log为总测试。
