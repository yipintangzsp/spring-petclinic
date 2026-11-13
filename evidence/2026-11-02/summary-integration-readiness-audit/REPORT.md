SUMMARY_INTEGRATION_READINESS =
READY

本轮仅进行仓库与既有证据审计；不代表实际 Summary 集成已完成。

1. **production source count**：18。重新核对 14 个现行 adapter stage、2 个条件 provenance 插件、Command Analysis 和下游 Promotion；不是沿用旧 totals。

2. **complete source inventory**：见下表及 authoritative-source-matrix.json；每行包含生产 stage/entry、实现与 adapter 路径、Policy mapping、源码 SHA、最新状态和证据索引。

3. **VERIFIED count**：17

4. **DEFERRED count**：1（Sonar）

5. **ENVIRONMENT_BLOCKED count**：0

6. **NOT_TESTED count**：0 个未解释的生产来源；Sonar 真实负例子路径仍为 NOT_TESTED，不改称 VERIFIED。

7. **FAILED count**：0

8. **SOPS final status**：VERIFIED。12 个 REAL_CONTROLLED_EXECUTION；旧 Gate/Policy 各 12；MATCH 12、DRIFT 0；88 文件 final index 与当前冻结 Gate/adapter/Policy/guard 哈希核对通过；raw fact、生产访问 0、cleanup 证据俱在。

9. **Sonar final status**：DEFERRED。真实 positive VERIFIED；real negative NOT_TESTED / DEFERRED_REAL_NEGATIVE_EVIDENCE；synthetic ERROR 仅逻辑测试。task→analysis→condition 真实正例存在；与 #270 的关联为 workspace/time correlation，并非逐构建直接 task 归档。按既定延期规则，此历史补证债不单独阻断 metadata 集成。没有新增 Sonar run。

10. **per-source parent-stage sample counts**：见完整来源表；Semgrep 与 Command Analysis 共用 136 条，只计一次。Sonar 的 1 个正例不是完整 parent 证明。Trivy release-scan 20 与 DB prerequisite 41 单列辅助层。

11. **authoritative deduplicated sample total**：2128 个完整 parent 样本；不是 18 行简单求和，也不是累计 Policy tests。

12. **total MATCH**：2128 个 parent MATCH；加入 Sonar 已验正例后 main evidence 为 2129 MATCH。

13. **total DRIFT**：0；分层保留的 2330 条记录同样为 0。

14. **old-decision distribution**：{"PASS": 332, "FAIL": 1768, "NOT_CONFIGURED": 1, "SKIPPED": 16, "WARN": 11}；SKIPPED/NOT_CONFIGURED 是保留的 null-decision 状态，没有转成 PASS。

15. **Policy-decision distribution**：{"PASS": 332, "FAIL": 1768, "NOT_CONFIGURED": 1, "SKIPPED": 16, "WARN": 11}；与旧结果一致。

16. **main evidence total**：2129＝去重 parent 2128＋Sonar 真实正例 1。

17. **layered evidence total**：2330＝main 2129＋辅助层 201。辅助层＝Trivy release20＋DB41＋旧 Kyverno child49＋旧 Command child5＋旧 contracts39＋SOPS unit20＋Gitleaks classifier7＋原 classifier 重核20。它们不提升 parent 样本数。索引重复引用不计作新执行。

18. **evidence index count**：46 个既有选定索引；本轮自身最终索引另存，不混入该数。

19. **evidence hash/reference validation**：2989 条引用；直接匹配 2987，另 2 条旧 guard 历史快照按原始 .before 字节及明确修改收据核验恢复可追溯性；未改写旧索引、未隐藏 mismatch。未解决失败 0。共 2753 个不同引用文件。

20. **source hash validation**：455 条冻结源码引用、229 个不同文件，全部匹配。各 adapter 另与 SOPS 前权威快照复核。

21. **Policy core validation status**：VERIFIED（readiness 范围）：既有核心 tests 5/5；只读 contract checks 10/10；版本、默认 standard、显式 low、strict、分层 override、POLICY_ERROR 及 raw 保持均通过。override 来源现由 appliedOverrides[].layer 等提供，当前没有字面 overrideSource 字段；下一轮需追加映射，不能声称已写入 Summary。

22. **Summary producer location**：生产：infra/security/security-summary.mjs，由 Jenkinsfile.security-audit:48/:75 调用；generic：resources/security-manager/summary.mjs，经 vars/securityManager.groovy 的 libraryResource 使用；infra/security/manager/summary.mjs 是内容相同的仓库副本。

23. **current summary schema location**：schema:1 位于三个 producer 的内联对象定义；输出为 .devsecops/security-summary.json；没有独立 JSON Schema 文件，也没有本地当前 run 的输出文件。本轮未生成任何替代 Summary。

24. **downstream consumers**：promotion/evidence.mjs → promotion/contract.mjs → sign-approve.mjs / promote.mjs；Jenkins archive；Loki sink；Grafana governance panels 的 JSON 查询定义。只识别消费关系，未执行 publish/query。Dojo 当前仍直接依赖 scanner 私有文件，不冒充 Summary consumer。

25. **remaining deferred debt**：Sonar 真实负例 build→task→analysis→ERROR→conditions 直接绑定；正例逐构建 task 归档。其他 controlled replay 的历史完整 CLI/live 环境证明保留范围限制；不宣称历史上发生全部负例。

26. **remaining later architecture work**：统一插件契约、SECURITY_ENABLED、独立禁用/capability 隔离、Provenance opt-in、DefectDojo 解耦、Result Router、Loki/Grafana query closure、portability smoke。按既定顺序留后，未豁免或实现。

27. **actual Summary integration blockers**：无。Policy compatibility core 与 SOPS blocker 为 CLOSED_FOR_SUMMARY_INTEGRATION；统一插件契约/Dojo 解耦/Result closure 为 STILL_LATER_ARCHITECTURE_WORK。

28. **SUMMARY_INTEGRATION_READINESS**：READY

29. **exact blocker if NOT_READY**：不适用；无未解决的 source/evidence/hash/compatibility blocker。

30. **exact next permitted action if READY**：STOP。下一轮可单独限定为：现有 Summary producer 追加兼容 Policy metadata，并验证既有 schema 字段与消费者；保持 Gate 和发布行为不变。当前不实施，不自动启动插件契约、解耦或 Router。

| Source | Status | 完整 parent 样本 | 旧 / Policy 决策分布 |
| --- | --- | ---: | --- |
| sbom | VERIFIED | 171 | {"PASS": 45, "FAIL": 121, "NOT_CONFIGURED": 1, "SKIPPED": 4} |
| regression | VERIFIED | 38 | {"PASS": 9, "FAIL": 29} |
| falco-baseline | VERIFIED | 52 | {"PASS": 19, "FAIL": 33} |
| kyverno | VERIFIED | 49 | {"PASS": 5, "FAIL": 44} |
| kubescape | VERIFIED | 45 | {"PASS": 4, "FAIL": 41} |
| gitleaks | VERIFIED | 127 | {"PASS": 15, "FAIL": 112} |
| semgrep | VERIFIED | 136（与 Command Analysis 共用） | {"PASS": 26, "FAIL": 110} |
| sops | VERIFIED | 12 | {"PASS": 1, "FAIL": 11} |
| trivy | VERIFIED | 123 | {"PASS": 43, "FAIL": 80} |
| cosign | VERIFIED | 260 | {"PASS": 18, "FAIL": 242} |
| sonarqube | DEFERRED | 0；真实正例 1 单列 | {"PASS": 1} |
| zap | VERIFIED | 191 | {"PASS": 34, "FAIL": 157} |
| falco-final | VERIFIED | 54 | {"PASS": 18, "FAIL": 36} |
| defectdojo | VERIFIED | 68 | {"PASS": 19, "FAIL": 49} |
| provenance | VERIFIED | 181 | {"PASS": 30, "FAIL": 142, "WARN": 4, "SKIPPED": 5} |
| build-provenance | VERIFIED | 363 | {"PASS": 30, "FAIL": 322, "WARN": 7, "SKIPPED": 4} |
| semgrep-command-audit | VERIFIED | 136 | {"PASS": 26, "FAIL": 110} |
| security-approval-promotion | VERIFIED | 258 | {"PASS": 16, "FAIL": 239, "SKIPPED": 3} |

兼容性边界：A＝冻结当前生产行为的兼容证明；B＝一般产品/安全正确性；C＝在线生产验证。这里只满足 A 的既定 readiness 范围，不宣称 B、C、SLSA 认证或全量历史负例。CONTROLLED_REPLAY/完整父阶段受控样本与 classifier-only 单元样本分开计数；SOPS 是真实隔离受控执行，不是生产事故。

只读核验范围：既有 2026-11-01/02 artifact/evidence/implementation 哈希索引、所选历史 parent 索引、最新 SOPS baseline/precleanup/final 索引、全部 Policy source locks。不同目录的准备期 project-before 快照不是额外差分样本；旧 frozen verdict 作为历史保留，由本轮权威矩阵替代当前状态。

两条历史 guard 索引的处理：旧文件路径与当前已批准版本不同；旧字节在 sops-preparation-blocker-closure/*.before 中仍精确匹配旧 SHA，protected-after.json 明确记录预期改动，新版 source-sha256 与 SOPS authoritative freeze 匹配。因此是已解释的版本替换，不是未解释源码漂移。原始索引和来源文件均未改写。

审计脚本首次只在 historical/ 子目录查找 Regression excerpt；随后按既有 artifact 索引定位到根目录 historical-270-regression.log，精确 SHA 匹配。仅修正审计定位，没有补造证据或更改任何既有结果。

证据入口：readiness.json、authoritative-source-matrix.json、differential-reconciliation.json、index-integrity.json、source-integrity.json、summary-preconditions.json、blocker-disposition.json、no-mutation-proof.json、artifact-sha256.json、final-validation.json。
