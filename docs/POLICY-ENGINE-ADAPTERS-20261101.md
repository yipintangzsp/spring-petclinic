# Policy Engine 剩余 Adapter：本轮结果

**FAILED：全生产 Gate 兼容性尚未证明。按失败即停要求停止，未接 Summary、未发布。**

## 已实际完成

新增 `infra/security/policy/gitleaks-evidence.mjs`，输入为原始脱敏 Finding、精确源行SHA、审查条目及扫描根前缀；转换为审查匹配事实。Policy Engine 根据匹配事实判定 PASS/FAIL。未知/变化的规则、路径、行哈希不得套用旧误报审查。源代码不包含业务路径、namespace、Deployment或专有环境变量。

Gitleaks 原始 report 没有 severity 字段，adapter 不补造 Critical/High；policy evaluation 的 severity=null 表示未评分。原始 Finding 按原值保留，已审查项也不被 strict 重新判成漏洞。原 production source-gate.mjs 完全未改。

独立差分测试不是用新函数生成 expected：直接从未修改的 source-gate.mjs 提取原审查循环，在 VM 中提供合成源文件内容并运行。7种冻结用例：已审查、全新发现、行内容变化、规则变化、审查路径变化、零发现、重复发现，旧决策与standard一致。另验证缺源行证据、越界和路径逃逸返回 POLICY_ERROR。

本轮全部独立测试 **13/13通过**（5项已有核心测试+8项Gitleaks测试）；其中 Gitleaks 7个实际旧循环差分用例、既有 Semgrep/Trivy/ZAP 20个局部分类样本通过。Finding 前后不变；没有新scanner调用或集群变更。不能把27个局部用例称为全生产门禁覆盖。

## 生产来源盘点

完整静态入口与摘要见 `evidence/2026-11-01/policy-engine/production-gate-inventory.json`，共18个来源记录：14个production adapter阶段、2个可选Provenance阶段、Semgrep前置命令分析及下游安全审批/签名约束。没有把当前未适配项填成 NOT_APPLICABLE。

当前分类差分仅覆盖 Gitleaks/Semgrep/Trivy/ZAP；其扫描执行前置条件、资源锁、身份验证、超时/cleanup分支并未被四项纯分类测试覆盖。尚缺 SBOM、regression、Falco baseline/final、Kyverno/RBAC、SOPS/age、Cosign、Sonar、Kubescape、Dojo及条件性Provenance、命令分析和下游审批的完整原始证据差分。既有这些工具历史VERIFIED仍保留，不等于新Policy adapter已验证。

## 本轮停止依据

- **blocker**：生产 Sonar 由 `sonar.qualitygate.wait=true` 等待服务器 Quality Gate。仓库仅有执行命令和查询漏洞/评分的Summary逻辑，没有完整且绑定具体analysis的服务端Gate阈值/条件快照。不能用漏洞计数代替Quality Gate，也不能拿#270 SUCCESS构造所有负例。
- **affected gate/source**：SonarQube冻结基线；继而阻断“所有Gate standard等价”的B验收，以及必须在其后进行的F/G实际Summary接入。其余未适配来源另列NOT_TESTED，不能据Sonar阻塞掩盖。
- **evidence**：`resources/security-manager/petclinic-adapter.json` Sonar命令含wait；`infra/security/security-summary.mjs`只读measures。只读连接 `192.168.64.11`：沙箱内Operation not permitted，经权限通道重试后 `Host key verification failed`。这是SSH主机身份校验未通过，不推断为集群/服务宕机，也未使用 StrictHostKeyChecking=no、删除known_hosts或盲目信任新指纹。
- **minimal fix**：恢复独立验证过主机身份的管理入口，仅读取固定analysis的Quality Gate配置/判定、条件和原始指标；再补其余来源的冻结正反例。只有全差分通过才把metadata追加至实际统一Summary，不改旧字段或提前宣称兼容。

当前policyVersion/securityLevel/profile/effectivePolicy/appliedOverrides仍只是引擎返回字段，**未写入实际security-summary.json；policyDecision和下游兼容验收尚未完成**。没有改变DefectDojo耦合、Loki查询、Provenance opt-in、Manager、既有Gate或发布逻辑，没有rollout/新常驻组件。

证据：`adapter-smoke.log`、`gitleaks-differential.json`、`production-gate-inventory.json`、`frozen-source-hashes-current.json`。旧轮acceptance.json是历史失败记录，未覆盖它；本轮状态写入adapter-acceptance.json。没有输出全验收成功标记。
