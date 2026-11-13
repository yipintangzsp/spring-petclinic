SUMMARY_INTEGRATION_READINESS =
READY

本轮仅权威 readiness 重检；不代表 Summary V2 已实现或在线验收。

1. **production source count**：18；当前 14 adapter stages＋2 conditional Provenance modules＋Command Analysis＋Promotion，逐项重读入口和冻结源码。

2. **complete source inventory**：完整来源、入口、source/adapter/Policy SHA、分类、索引、证据限制见下表及 authoritative-source-matrix.json。

3. **VERIFIED count**：17

4. **DEFERRED count**：1（Sonar）

5. **ENVIRONMENT_BLOCKED count**：0

6. **NOT_TESTED count**：0；Sonar 的真实负例子路径仍 NOT_TESTED，不把它包装成全项 VERIFIED。

7. **FAILED count**：0

8. **Falco baseline final status**：VERIFIED；新 authoritative time-contract repair，89 MATCH / 0 DRIFT。

9. **Falco final final status**：VERIFIED；新 authoritative time-contract repair，91 MATCH / 0 DRIFT。

10. **SOPS status**：VERIFIED；12 approved/applicable/old Gate executions/Policy executions，MATCH 12，DRIFT 0，final evidence 88 个文件身份重核，cleanup 仍有完整记录；本轮不重建 fixture。

11. **Sonar status**：DEFERRED；真实正例 VERIFIED；真实负例直接 build→task→analysis→ERROR/conditions 绑定缺失。独立 synthetic ERROR 逻辑测试仍 PASS。既定非阻断接受条件有效，不提升 Sonar。

12. **per-source authoritative sample counts**：见下表。Semgrep 与 Command Analysis 共用 136 条、只计一次；Sonar 真实正例 1 单列，不计完整 parent。

13. **new Falco baseline authoritative count**：89＝原 52＋时间 37；不是 52＋89。

14. **new Falco final authoritative count**：91＝原 54＋时间 37；不是 54＋91。

15. **old Falco evidence handling**：SUPERSEDED_FOR_TIME_BOUNDARY_COVERAGE；原件未改，历史索引继续核验；不再作为当前/辅助差分记录重复计数。修复前 20 个 controlled drift 仅作缺陷历史，不计当前兼容样本。

16. **authoritative deduplicated total**：2202；从当前 JSON pointers 重算，不沿用旧 2128。

17. **total MATCH**：2202

18. **total DRIFT**：0

19. **old decision distribution**：{"PASS": 346, "FAIL": 1828, "NOT_CONFIGURED": 1, "SKIPPED": 16, "WARN": 11}；NOT_CONFIGURED/SKIPPED 保留其 null-decision 状态，不等同 PASS。

20. **Policy decision distribution**：{"PASS": 346, "FAIL": 1828, "NOT_CONFIGURED": 1, "SKIPPED": 16, "WARN": 11}；与原 Gate 一致。

21. **main evidence total**：2203＝parent 2202＋Sonar real positive 1。

22. **layered evidence total**：2404＝main＋辅助 201；辅助包含 Trivy release20/DB41、旧 Kyverno child49、Command child5、contracts39、SOPS unit20、Gitleaks classifier7、原 classifier recheck20；不是独立完整 parent 执行。

23. **evidence index count**：48：既有 46＋Falco 新索引 1＋上一轮 readiness 审计索引 1。本轮自己的输出索引另计。

24. **evidence hash validation**：3118 refs；3116 直接匹配，2 条历史 guard 转换通过保留旧字节及已批准 transition 收据验证；未解决失败 0；2882 个 distinct referenced files。新 Falco 索引 107/107 全部核验。

25. **source hash validation**：455 冻结 source refs / 229 distinct files 全部匹配；另核验 18 来源 adapter 引用/16 distinct adapters（Semgrep/Command 与两 Falco 各共享实现），以及 Engine/baseline；source/index 重复引用不是样本。

26. **new Falco adapter hash status**：ACCEPTED_CURRENT：2c31980a19c9443215fd196e6aab3e89e312c6bca535857a869b6fe2a610519b；旧 SHA 与 archive/transition 显式绑定，未修改旧快照。

27. **frozen Falco Gate hash status**：UNCHANGED：65ab133a4248b9900265a47d943f9e6430b9ec9581ddd624b1d9257322b0d921。

28. **Policy baseline hash status**：UNCHANGED：02c3f5499dc39a53009a69e8f267dbbd247b4d89d4de14fafaa4dd5cff974f1a。

29. **Policy core result**：5/5 PASS；既有只读 contract checks 10/10 VERIFIED；默认 standard、显式 low、strict、overrides、POLICY_ERROR、raw preservation 均有效。未修改 Policy。

30. **Summary producer/schema identification**：PetClinic infra/security/security-summary.mjs（Jenkinsfile.security-audit:48/:75）；generic resources/security-manager/summary.mjs（Shared Library）及相同仓库副本 infra/security/manager/summary.mjs；schema=1 内联，无独立 schema 文件。消费者为 Promotion evidence/contract/sign-approve/promote、Jenkins archive、Loki sink 和 Grafana JSON queries。metadata 契约 policyVersion/securityLevel/profile/effectivePolicy/appliedOverrides/policyDecision 已识别；当前 Engine 字段 decision，尚未接入实际 Summary。

31. **remaining deferred debt**：Sonar 真实负例直接逐构建 task 归档及完整 analysis/conditions 链；其他 controlled replay 的完整历史 CLI/prerequisite/live 认证范围限制继续保留。REAL_CONTROLLED_EXECUTION 不冒充生产事故，历史样本不冒充本轮 live run。

32. **later architecture work**：见 blocker-disposition.json：Summary V2 migration、统一插件契约、SECURITY_ENABLED、globalMode、per-plugin switches、capability、Dojo 解耦、Result Router、Loki/Grafana closure、portability smoke、Provenance opt-in。inactive V2 candidate 仍有两个预期 Falco hash stale，不可激活；下轮授权迁移必须建立新 reviewed identity。本轮不重写该锁。

33. **active Summary integration blockers**：无 source compatibility/readiness blocker；后续实现债没有被当作已完成。READY 不授权启用未更新的候选版本。

34. **SUMMARY_INTEGRATION_READINESS**：READY

35. **exact blocker if NOT_READY**：不适用，本轮 readiness blocker 为空。

36. **exact next permitted action if READY**：STOP，等待下一阶段单独授权；本轮不恢复 Summary V2、不改 producer/security-summary.json、不迁移 Promotion/Regression、不启动插件架构工作。

| Source | Status | Parent 样本 | 旧 = Policy 判定分布 |
|---|---|---:|---|
| sbom | VERIFIED | 171 | {"PASS": 45, "FAIL": 121, "NOT_CONFIGURED": 1, "SKIPPED": 4} |
| regression | VERIFIED | 38 | {"PASS": 9, "FAIL": 29} |
| falco-baseline | VERIFIED | 89 | {"PASS": 26, "FAIL": 63} |
| kyverno | VERIFIED | 49 | {"PASS": 5, "FAIL": 44} |
| kubescape | VERIFIED | 45 | {"PASS": 4, "FAIL": 41} |
| gitleaks | VERIFIED | 127 | {"PASS": 15, "FAIL": 112} |
| semgrep | VERIFIED | 136；与 Command 共用 | {"PASS": 26, "FAIL": 110} |
| sops | VERIFIED | 12 | {"PASS": 1, "FAIL": 11} |
| trivy | VERIFIED | 123 | {"PASS": 43, "FAIL": 80} |
| cosign | VERIFIED | 260 | {"PASS": 18, "FAIL": 242} |
| sonarqube | DEFERRED | 0；真实正例 1 单列 | {"PASS": 1} |
| zap | VERIFIED | 191 | {"PASS": 34, "FAIL": 157} |
| falco-final | VERIFIED | 91 | {"PASS": 25, "FAIL": 66} |
| defectdojo | VERIFIED | 68 | {"PASS": 19, "FAIL": 49} |
| provenance | VERIFIED | 181 | {"PASS": 30, "FAIL": 142, "WARN": 4, "SKIPPED": 5} |
| build-provenance | VERIFIED | 363 | {"PASS": 30, "FAIL": 322, "WARN": 7, "SKIPPED": 4} |
| semgrep-command-audit | VERIFIED | 136 | {"PASS": 26, "FAIL": 110} |
| security-approval-promotion | VERIFIED | 258 | {"PASS": 16, "FAIL": 239, "SKIPPED": 3} |

计数与范围：2202 个完整 parent 样本＋Sonar 正例 1＝main 2203；辅助层 201＝layered 2404。Semgrep/Command 去重、Trivy parent 与辅助阶段分开、SOPS execution JSON 只计一次；旧 Falco complete suite 和新时间矩阵中的 before/after 不重复计数。历史 evidence index 的多个引用不是多个执行。全部结论限冻结 standard 兼容性，不声明所有安全规则正确、在线 sensor 验证或 Jenkins/V2 集成已完成。

生产访问/新 Jenkins build/release/rollout 均为 0。已有源码、Summary、GitOps、Gate、Policy、证据全部不变。本轮只在此新目录写审计脚本、日志、矩阵和报告。

