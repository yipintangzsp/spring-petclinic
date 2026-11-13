# Policy Engine production compatibility 最终总盘点（2026-11-01）

**SUMMARY_INTEGRATION_READINESS = NOT_READY**。本轮仅盘点/证据核对，未新增 adapter、未修改现有生产逻辑或实际 Summary、未 rollout。

## 权威范围与计数

原始 18 个来源全部有对应行；现行 14 个 adapter stage、2 个条件插件、命令分析及下游审批均已核对，无新增遗漏。HEAD `741ea2866ea142b24c7838e1ef25c8327c79d279`。这里只证明冻结当前源码兼容，不证明实时生产服务健康。

最终状态互斥计数：VERIFIED=13；NOT_TESTED=3；ENVIRONMENT_BLOCKED=1；DEFERRED_REAL_NEGATIVE_EVIDENCE=1；FAILED=0；NOT_APPLICABLE=0。SOPS 最终分类 ENVIRONMENT_BLOCKED，验证状态仍 NOT_TESTED，不重复计入两类。

## 完整生产来源矩阵

Adapter 的 VERIFIED 有明确范围；parent 未完成时最终不得借用 classifier 的 VERIFIED。M/X 是该行明确范围内 match/mismatch；带 * 的不是完整 parent 样本。

| source / production stage | adapter / complete parent | M / X | evidence | raw | gap / final status |
| --- | --- | ---: | --- | --- | --- |
| sbom / Package SBOM | VERIFIED / VERIFIED | 171 / 0 | CONTROLLED_REPLAY | True | 冻结父阶段无已知结构性缺口；历史/在线认证不在本轮范围；**VERIFIED** |
| regression / Regression | VERIFIED / VERIFIED | 38 / 0 | CONTROLLED_REPLAY, REAL_HISTORICAL | True | 冻结父阶段无已知结构性缺口；历史/在线认证不在本轮范围；**VERIFIED** |
| falco-baseline / Falco Baseline | VERIFIED / VERIFIED | 52 / 0 | CONTROLLED_COMPLETE_STAGE_WITH_HISTORICAL_SENSOR_IDENTITY | True | 冻结父阶段无已知结构性缺口；历史/在线认证不在本轮范围；**VERIFIED** |
| kyverno / Kyverno | VERIFIED / VERIFIED | 49 / 0 | SYNTHETIC_COMPLETE_PARENT_WITH_HISTORICAL_PROBE_RESULTS | True | 冻结父阶段无已知结构性缺口；历史/在线认证不在本轮范围；**VERIFIED** |
| kubescape / Kubescape Audit | VERIFIED / VERIFIED | 45 / 0 | CONTROLLED_COMPLETE_GATE_WITH_HISTORICAL_CONSUMED_FIELDS, SYNTHETIC_COMPLETE_GATE | True | 冻结父阶段无已知结构性缺口；历史/在线认证不在本轮范围；**VERIFIED** |
| gitleaks / Secret Source | VERIFIED / NOT_TESTED | 7* / 0 | SYNTHETIC_UNIT_ONLY | True | 仅分类器；缺前置/执行/清理父阶段；**NOT_TESTED** |
| semgrep / Semgrep | VERIFIED / VERIFIED | 136 / 0 | CONTROLLED_REPLAY, REAL_HISTORICAL | True | 与Command Analysis同一完整生产父命令；136样本只计一次；**VERIFIED** |
| sops / Encrypted Credentials | NOT_TESTED / NOT_TESTED | 20* / 0 | SYNTHETIC_UNIT_ONLY, EXECUTION_ENVIRONMENT_INSPECTION_ONLY | True | 仅20合成单元；真实受控及runtime前置证据0；**ENVIRONMENT_BLOCKED** |
| trivy / Trivy | VERIFIED / NOT_TESTED | 8* / 0 | SYNTHETIC_UNIT_ONLY | True | 仅分类器；缺候选镜像+Harbor扫描完整父阶段；**NOT_TESTED** |
| cosign / Cosign Admission | VERIFIED / VERIFIED | 260 / 0 | SYNTHETIC_FROZEN_COMPLETE_STAGE | True | 冻结父阶段无已知结构性缺口；历史/在线认证不在本轮范围；**VERIFIED** |
| sonarqube / SonarQube | VERIFIED / DEFERRED_REAL_NEGATIVE_EVIDENCE | 1* / 0 | HISTORICAL_ARCHIVE, SYNTHETIC_UNIT_ONLY | True | 正例真实；负例build→task→analysis绑定缺失；**DEFERRED_REAL_NEGATIVE_EVIDENCE** |
| zap / ZAP Passive | VERIFIED / NOT_TESTED | 4* / 0 | SYNTHETIC_UNIT_ONLY | True | 仅分类器；缺runtime/fixture/目标绑定/清理父阶段；**NOT_TESTED** |
| falco-final / Falco Final | VERIFIED / VERIFIED | 54 / 0 | CONTROLLED_COMPLETE_STAGE_WITH_HISTORICAL_SENSOR_IDENTITY | True | 冻结父阶段无已知结构性缺口；历史/在线认证不在本轮范围；**VERIFIED** |
| defectdojo / DefectDojo Governance | VERIFIED / VERIFIED | 68 / 0 | SYNTHETIC_COMPLETE_STAGE_WITH_HISTORICAL_RECEIPT_IDENTITIES | True | 冻结父阶段无已知结构性缺口；历史/在线认证不在本轮范围；**VERIFIED** |
| provenance / Conditional securityProvenance | VERIFIED / VERIFIED | 181 / 0 | CONTROLLED_REPLAY | True | 冻结父阶段无已知结构性缺口；历史/在线认证不在本轮范围；**VERIFIED** |
| build-provenance / Conditional securityBuildProvenance | VERIFIED / VERIFIED | 363 / 0 | CONTROLLED_REPLAY | True | 冻结父阶段无已知结构性缺口；历史/在线认证不在本轮范围；**VERIFIED** |
| semgrep-command-audit / Command Analysis before/in Semgrep | VERIFIED / VERIFIED | 136 / 0 | CONTROLLED_REPLAY, REAL_HISTORICAL | True | 冻结父阶段无已知结构性缺口；历史/在线认证不在本轮范围；**VERIFIED** |
| security-approval-promotion / Security Approval / Approved Promotion / Git Promotion | VERIFIED / VERIFIED | 258 / 0 | CONTROLLED_REPLAY, REAL_HISTORICAL | True | 冻结父阶段无已知结构性缺口；历史/在线认证不在本轮范围；**VERIFIED** |

逐行 production entry、证据路径、旧/standard 决策分布、完整范围及缺口见同目录 `authoritative-source-matrix.json`。

## 差分与证据完整性

- 完整父阶段去重：1675/1675（samples/matches），drift=0。Semgrep/Command Analysis的136只计一次。
- 当前主证据选择集：1695（完整父阶段 + Gitleaks7/Trivy8/ZAP4分类器 + Sonar真实正例1），drift=0。
- 所有保留范围的差分记录及20个原冻结分类器重查合计：1816，drift=0；这是分层记录总数，不把旧child/unit-only提升为完整parent，不是1873个Policy tests。
- 全部选取记录raw preservation=True；保留SKIPPED/NOT_CONFIGURED，无改成PASS。完整父阶段旧/standard均为 `{"PASS": 239, "FAIL": 1408, "NOT_CONFIGURED": 1, "SKIPPED": 16, "WARN": 11}`。
- 校验14份既有artifact/evidence哈希索引、1642条引用，成功1642；源码锁检查414条，失败0。矩阵引用缺失0（详见reference-check）。
- 原始108源码快照与现有version locks逐项核验；本轮前后保护文件2595份，变化0份。旧报告和旧失败acceptance未覆盖。

## Policy Engine readiness

现有核心tests 5/5 PASS；只读审计10项全部 VERIFIED：baseline-v1、默认standard、显式low、strict、component/project override、policyVersion、effectivePolicy、override source、错误配置POLICY_ERROR。对不可读/损坏JSON/错误schema仅在一次性审计进程注入读取故障，不改策略文件。metadata当前仍仅引擎返回值，不代表已接Summary。
累计1873 Policy cases保留上一轮验收记录，本轮未重跑全量、未新增计入累计的Policy test cases。真实Sonar正例和合成ERROR映射只读复核，合成ERROR仍不是历史负例。

## A：阻断 Summary integration

1. Gitleaks：原source-gate包含Lease、scanner身份/隔离、正负canary、源码转移、report及清理；7个review-loop差分不能证明全父阶段。
2. Trivy：ensure-audit-candidate + audit-trivy的候选源/registry/双架构扫描/runtime/请求失败及报告路径缺完整差分；8个漏洞分类样本不覆盖这些执行失败。
3. ZAP：scanner-runtime、JVM/fixture、确认记录hash/target绑定、生产GET探测、native report及session清理缺完整差分；4个classifyZap样本不足。
4. SOPS/age：NOT_TESTED / ENVIRONMENT_BLOCKED。20个合成Gate-body差分不能替代完整scanner-runtime prerequisite或真实受控执行。现有context不是安全隔离环境，禁止读取生产Secret补证。属于A，同时留下最终portability证据债；不能只按“历史没发生事故”豁免。

前三项保留原先分类器VERIFIED，最终完整兼容状态为NOT_TESTED；这是范围校正，不是检测到decision drift，也不是修改Gate。旧覆盖矩阵的blockers数组只列SOPS，且保留过时inheritedBlockersSnapshot；它不能作为本次唯一权威结论。

## B：最终 portability debt

Sonar positive VERIFIED；negative NOT_TESTED / DEFERRED_REAL_NEGATIVE_EVIDENCE。已有task→analysis→conditions正例，当前权威OK→PASS/ERROR→FAIL逻辑测试通过且拒绝无绑定事实；历史失败日志确实存在，但缺直接build/task/analysis链。按已批准的延期规则，属于B，不单独阻断架构推进，绝不标负例VERIFIED。正例与build仍是workspace/time关联，未夸大为逐构建直接task归档。

其他B债：Global Master Switch、per-plugin统一独立禁用及DISABLED状态、capability隔离和统一plugin contract、Dojo私有文件解耦、Provenance opt-in统一、Result Router、Loki publish/query闭环和portability smoke。它们没有在本轮被实现或豁免。

## 保留的架构硬约束

`SECURITY_ENABLED → Security Manager → globalMode → securityLevel(default standard) → per-plugin switch → capability check → independent execution → raw → normalize → Policy Engine → Unified Summary → Result Router → consumers`。

必须有全局开关；每插件可独立关闭；disabled只能DISABLED不能PASS；缺capability不能拖累无关插件；scanner只产事实、Policy判定；consumer不直接依赖私有scanner文件。现有早期合同部分要求未显式写为该完整链，本次将其作为用户要求的目标设计保留，未谎报已实现。详见architecture-constraints.json。

## GO / NO-GO 与停止

**SUMMARY_INTEGRATION_READINESS = NOT_READY**。inventory complete、drift=0、core ready均成立；A类兼容证据缺口未清零。不得进入实际security-summary.json集成。

下一允许阶段仅是单独限定范围的兼容补证：Gitleaks/Trivy/ZAP完整父阶段，以及SOPS真正隔离/可丢弃/已授权环境中的受控执行及prerequisite差分。获得证据后重新做readiness判定。本轮到此停止，不实施该阶段，不输出全Policy/portability成功标记。
