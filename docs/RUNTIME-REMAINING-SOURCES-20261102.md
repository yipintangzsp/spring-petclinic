# Runtime remaining sources — 本轮结果

真实专用 Jenkins #9 捕获 8/16 来源；本轮新增 3 项接线，其中两个只覆盖原 helper 的默认未启用分支。整体 INCOMPLETE，未生成 COMPLETE artifact，未激活 Summary V2。

更正：早先进度中“#6 SBOM 已通过”不准确。原始日志与归档证明 #6–#8 的 Maven NoHttp 检查失败，old Gate 与 Policy 同为 FAIL。#9 从精确 tracked HEAD 临时 checkout 构建，全部原检查及 verifier 才实际 PASS；没有跳过检查、改 Gate 或修改生产代码。

证据类别严格区分：REAL_DEDICATED_NONRELEASE_JENKINS_EXECUTION、REAL_JENKINS_CPS_DEFAULT_RETURN、REAL_READ_ONLY_EXISTING_ANALYSIS_OBSERVATION、CONTROLLED_ACCEPTED_GATE_REPLAY、HISTORICAL_CONTROLLED_EXECUTION_REDACTED_SHAPE_ONLY、SYNTHETIC_UNIT_ONLY。

1. **canonical runtime source count** — 16；来自 canonical registry，18 compatibility labels 中 Semgrep 为 alias，Promotion 为 post-approval。

2. **previously wired source count** — 5。

3. **remaining source count before this iteration** — 11。

4. **remaining-source inventory** — remaining-source-inventory.json：由 registry、生产 plan、原 Shared Library helper 和前轮真实 coverage 重建；逐项包含命令、路径、依赖、权限、副作用、adapter 与缺失事实。

5. **risk grouping** — A: sbom；B: sonarqube, build-provenance；C: gitleaks, sops, trivy, cosign, zap, defectdojo, provenance, semgrep-command-audit。分类先于执行；C 默认返回与正常写分支分别审查。

6. **newly wired sources** — SBOM 原 Maven+verifier；Provenance 和 Build Provenance 冻结原函数的实际默认 SKIPPED 返回。未宣称 enabled branch 已覆盖。

7. **total wired sources** — 专用真实 Jenkins #9 中 8/16；6 PASS，2 explicit SKIPPED。

8. **still-unobserved sources** — gitleaks, sops, trivy, cosign, sonarqube, zap, defectdojo, semgrep-command-audit；仍 NOT_OBSERVED，未补默认状态。

9. **per-source fact producer** — 详见 source-fact-contracts.json。原五项保持原命令；SBOM 从精确 tracked HEAD 临时 checkout 执行原命令；两 helper 核对冻结源码 hash/library commit 后真实调用。

10. **per-source collector mapping** — source-fact-contracts.json；原始 source-specific payload 保留于内存 facts.raw，receipt 只存 digest/安全元数据。SBOM 保留真实生成器退出、unzip bytes、Maven bytes、原报告写入与源码输入身份。

11. **per-source evaluation counts** — 8 个已接入来源各 1；另 8 个 null，不能视作已求值。Sonar 额外只读观察为 0 次 Policy 求值。

12. **duplicate-evaluation result** — 39 项测试覆盖重复 source、并发、第二 owner 与 Gate 重复 handoff；第二次求值前拒绝。真实 #9 每项 claim/receipt 一份。

13. **per-source result IDs** — sbom=69eb479fc92fd9858357b0ca441515e27760f646236e440e2d3657eb52699a9b；regression=60e80e326e10d484ab9d91f823414b4a9f09ab6b05d0c1b4dfd37cd7e28d1808；falco-baseline=783e3d15055dc1302826705ffe4e6e96af082dc409958e5dde0464b409caf845；kyverno=7445b6c1634d127eeae3294412f7b7523814a00ca4c65186fc1d2ce354a2602f；kubescape=b43c785ba0c7ddfbefcd073e2ec49fd4086fa7e90eec708f47090599b5b0e563；falco-final=7adabded6597b035ed0831e5eecbf961b4aa145f76a43a6ce36396bf0d4570d3；provenance=9832f479faccb9a824b4fcdd15835da22d3ae12688259da3cf499fd51f528fec；build-provenance=71cf7379a0638fdf824c89207643028bc33d835ed8b204e2f903f0268e94c371

14. **Gate reuse result** — 8 项 capture/result/gate/coverage 的 resultDigest 完全一致；实际 CPS 返回用真实 RETURNED + exitStatus=null，不捏造进程 exit 0。

15. **sources with complete facts** — 原五项、SBOM 执行分支，以及两个 helper 的默认未启用分支。此处不代表两个 helper 的 enabled attestation branch。

16. **sources with incomplete facts** — gitleaks, sops, trivy, cosign, sonarqube, zap, defectdojo, semgrep-command-audit。缺少真实扫描/导入/清理/隔离/分析血缘证据；source-fact-contracts.json 不把 shell success 提升为完整 wrapper facts。

17. **read-only credential-bound sources** — Sonar 使用现有 Jenkins sonar-token 仅 GET 已知 task 与 exact analysis；不导出 token、不查凭据存储、不重试已知受限 history API。Build Provenance 默认分支不读取 Harbor 凭据；启用 verify 分支未验证。

18. **external-write-risk sources** — Gitleaks/Semgrep/ZAP 创建临时扫描 Pod；Trivy POST scan/候选拷贝；Cosign/Provenance sign/push；Dojo POST/PATCH；SOPS 只限专用隔离夹具。均未为证明 collector 而直接运行写分支。

19. **Sonar runtime status** — 真实已有 task/analysis GET 200/200，Quality Gate OK；当前源码/候选血缘未证明，因此没有 owner receipt，不把旧结果重绑定本轮。真实负例仍 DEFERRED_REAL_NEGATIVE_EVIDENCE。

20. **SOPS runtime boundary** — CONTROLLED_ISOLATED_RUNTIME 边界保留；原隔离夹具已清理，本轮新 SOPS 执行 0。正向/decrypt/tool-missing 3 类脱敏历史 shape 保持映射；未重新求值脱敏正例，未恢复或打印 plaintext。生产 Secret/key 访问 0。

21. **DefectDojo runtime boundary** — 完整父阶段需真实 import/Test/reimport/dedupe/queryback/API observations；只读预查询不能提供未执行写操作的结果。未新导入/PATCH，未解耦私有文件依赖。

22. **Promotion/pre-approval boundary** — Promotion 不在 canonical preapproval 16 项中；没有 future PromotionResult/self-approval；Promotion 与 Regression 生产逻辑均未迁移。

23. **Falco normal result** — #9 baseline/final 原命令均 PASS；once/same receipt。每个真实查询窗口保留 observed since-time + 15000ms，无固定延迟推导。

24. **Falco 2-second result** — accepted whole-Gate controlled replay 4 MATCH/0 DRIFT，baseline/final 两个 2 秒边界均 old FAIL = Policy FAIL，same receipt。不是本轮线上故障。

25. **Regression 147/147** — 本轮专用 #5/#6/#7/#8/#9 均实际运行原命令，147/147、0 fail/skip/todo/cancel。等价事实 result identity 稳定由隔离确定性测试验证；不同 build 的 digest 不应相同。

26. **collector/owner tests** — 39/39 PASS（含 source-specific）；旧五项基线在每次新增来源后重跑，见 baseline-after-each-source.json。

27. **candidate tests** — 40/40 PASS；unchanged 候选测试在临时 checkout 执行，旧 accepted evidence 未改。这不是 COMPLETE runtime artifact 证据。

28. **Policy core** — 5/5 PASS。

29. **contract checks** — 10/10 PASS；默认 standard/显式 low/strict/override/POLICY_ERROR 保持。

30. **source-specific tests** — SBOM 4 项 unit（3 项 old-vs-Policy differential）、clean checkout 2 项、原 helper return 9 项、Sonar read-only 3 项及原五项 observer/owner 回归均在 39 项内。单元夹具不是新生产兼容性样本。真实 SBOM #6–#8 FAIL/FAIL，#9 PASS/PASS；真实 helper defaults 在 #7/#8/#9 观察。

31. **canonical completeness result** — INCOMPLETE：8/16；#9 missing-source rejection 实际执行，未放宽完整性。

32. **immutable artifact status** — NOT_GENERATED；partial receipt bundle 不称 COMPLETE artifact。

33. **artifact identity/hash** — 无 COMPLETE runtime artifact，identity/hash NOT_APPLICABLE；当前 input bundle SHA256 a1ae9629ab572158aa46ddfa00fc405eb5e64307d61ad1a866450ac1cdc5237a，不能用它冒充最终 artifact hash。

34. **candidate/build binding** — {"candidate": "core.harbor.domain/petclinic/petclinic@sha256:489cb821573ff1f98edd846d5949d74bf3391b24e2f1fe5bcfb71c6be0793137", "build": 9, "project": "petclinic", "source": "741ea2866ea142b24c7838e1ef25c8327c79d279", "runId": "security-runtime-facts-20261102#9", "job": "security-runtime-facts-20261102", "targetScope": "runtime"}；667 文件 bundle hash + 精确 tracked build checkout hash；每个已接入 receipt 与同一 binding 一致。Sonar 旧目标未混入。

35. **aggregate Gate result** — INCOMPLETE；8 项 per-source Gate reuse MATCH，不宣称全量 aggregate 已验证。专用 Jenkins #9 FAILURE，原 source decision 和缺项拒绝均保留；生产 job 未执行。

36. **source hash preservation** — 6781 个旧文件基线；仅 7 个允许的 collector/专用 pipeline 文件变更；455 frozen refs / 229 distinct 路径、3118 prior index refs 与 r2 hash 全匹配。

37. **V1 active path unchanged** — YES。petclinic-ci #270 SUCCESS，V1 Summary SHA ec9ee51a06d4b9f61c6c0eaf50b374d1e25e6d3ca687908b7596d3a2c794f5d8；实时生产 workspace hash 与前轮逐项一致。

38. **production Jenkins build count** — 本轮触发 0；最新仍 #270。

39. **validation Jenkins build count** — 本轮 #5–#9 共 5 次；专用 job 累计 9 次。#5 baseline；#6 SBOM 实际失败事实；#7 Provenance default；#8 Build Provenance default；#9 clean SBOM + Sonar 只读取证 + 八项回归。定义上传前 Groovy 引号错误已修正，未因此创建构建或修改生产 job。

40. **release count** — 0。

41. **rollout count** — 0。

42. **REAL_RUNTIME_FACT_CAPTURE** — INCOMPLETE。

43. **REAL_POLICY_OWNER** — INCOMPLETE。

44. **IMMUTABLE_ARTIFACT_RUNTIME** — INCOMPLETE。

45. **SUMMARY_V2_MIGRATION** — INCOMPLETE。

46. **exact remaining blocker** — verdict.json 五类 blocker：6 项外部写边界后完整事实缺失、SOPS 新隔离事实/transport 缺失、Sonar 当前候选血缘缺失、两个 optional helper enabled scope 未观察、全量 artifact producer/aggregate 输入未接线。本轮无权限升级，无 COMPLETE 伪造。

47. **exact next permitted action if all three runtime verdicts VERIFIED** — 当前未满足，不能进入 Summary。只能继续审查/补齐本阶段上述事实边界；需要新写操作或隔离 transport 时先明确对应授权范围。即使未来三项 VERIFIED，本附件仍要求 STOP，不能自动接 Summary V2。

```text
REAL_RUNTIME_FACT_CAPTURE =
INCOMPLETE
REAL_POLICY_OWNER =
INCOMPLETE
IMMUTABLE_ARTIFACT_RUNTIME =
INCOMPLETE
SUMMARY_V2_MIGRATION =
INCOMPLETE
```

已停止本阶段。节点均 Ready，临时 heavy Lease 已释放；没有新常驻组件或扫描 Pod，干净 SBOM checkout 已删除。
