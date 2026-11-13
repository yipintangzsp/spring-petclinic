# Controlled non-release runtime sources：本轮报告

1. **starting canonical count**

   16；原 registry 未改变，Promotion 仍在 pre-approval 集合之外。

2. **starting wired count**

   10，原 Jenkins #12 证据保持其原 build binding。

3. **exact final-six list**

   Gitleaks、Semgrep/Command Analysis、Trivy、Cosign、ZAP、DefectDojo；final-six-inventory.json。

4. **side-effect classification per source**

   前两项 LOCAL_EPHEMERAL_WRITE + TEST_EXTERNAL_WRITE。后四项现有完整父路径含 PRODUCTION_EXTERNAL_WRITE，未执行；禁止 UNKNOWN/IRREVERSIBLE write。

5. **controlled execution boundary per source**

   前两项：独立 exact tracked HEAD workspace + 短时最小 SA + 命令/Pod/UID guard + 原网络隔离。后四项的具体 blocker 与最小动作见 blocked-boundaries.json。

6. **validationRunId**

   rfv-20261103-29dad1。Pod 保留原命名语义，通过 build/UID ledger 绑定此 run；管理资源名称含 run ID。

7. **Gitleaks execution/result**

   #14：真实 frozen parent，当前 source 741ea2866ea142b24c7838e1ef25c8327c79d279，old Gate PASS == Policy PASS；三个实际 scan 调用：原正例、原负例、真实 tracked source。#13 前置失败不计 normal completion。

8. **Gitleaks cleanup**

   source-14-42491f UID 正常删除并验证 absence；临时 checkout/guard/token 目录移除，5 个短时 SA/RBAC 对象按 UID 删除。

9. **Semgrep/Command Analysis execution/result**

   #15：原 combined && command，command-audit 与 Semgrep 各执行一个父阶段；old Gate PASS == Policy PASS。

10. **shared-observation/double-count result**

   canonical=semgrep-command-audit，一次 Policy。实际原 per-file/fixture/repeat core 调用数保存在 fact-formation-receipts.json，未伪称 core 只启动一次；未因多个消费者重跑 source scan。

11. **Trivy execution/result**

   BLOCKED：Harbor API 架构保持；未用本地 CLI。既有身份是全局 admin，缺最小 validation writer 与已验证的非发布 digest/清理契约。

12. **Harbor write/read boundary**

   #16：3 次 Harbor GET 200；0 POST/PUT/scan/signature/tag write。active runtime digest 不被当作 disposable artifact。

13. **Cosign execution/result**

   COSIGN_RUNTIME_BOUNDARY_BLOCKED：冻结 admission 父阶段解密既有 signing bundle 并核对冻结生产公钥；test-only key 不能满足当前信任绑定。

14. **signing/write boundary**

   生产签名密钥读取/解密=0，新签名=0，registry signature writes=0。独立 VERIFY 不能冒充完整 admission parent。

15. **ZAP execution/result**

   ZAP_RUNTIME_BOUNDARY_BLOCKED：原代码固定 petclinic Deployment/Service + Jenkins 网络上下文，独立非生产目标尚未满足此冻结入口。

16. **ZAP target identity**

   只读清单只找到 active production PetClinic；未启动 ZAP、不重定向到生产、不用假的 Kubernetes response 替代目标。

17. **DefectDojo execution/result**

   DEFECTDOJO_RUNTIME_BOUNDARY_BLOCKED：存在验证 Product，但独立 run Test/cleanup 权限及 Trivy/ZAP 等本轮原生报告尚未建立。

18. **DefectDojo test identity**

   GET 可见 Product 2 Security Manager Contract Samples / Engagement 2 Shared Library Mode Contracts；它们不是本轮 disposable run identity。配置的正常 Product 1/Engagement 1 未用于写入。

19. **DefectDojo cleanup**

   未创建/导入/PATCH 任何 Dojo 对象，无测试对象残留；未以纯 mocked API 宣称 real runtime。

20. **new sources successfully wired**

   Gitleaks、Semgrep/Command Analysis 两项完整原始父阶段。

21. **final wired/16**

   累计已实现/真实验证 capability=12/16。尚无单次构建 12 项或 16 项全量采集：#12=10，#14/#15 各有当前 Regression + 一个新 source。未跨 build 合并。

22. **blocked sources**

   Trivy、Cosign、ZAP、DefectDojo；状态保持 BLOCKED，不映射 SKIPPED。

23. **executionScope for all 16**

   runtime-source-matrix.json；已执行 scope 来源明确，四项 blocked 的 scope 是批准的目标边界，executionStatus=BLOCKED_NOT_EXECUTED，不冒充运行结果。

24. **RuntimeSourceFacts completeness**

   新两项完整 parent schema / native reports / observations / process / cleanup / classifier facts；旧十项 receipts 校验保持有效；四项缺失，不产生全量 completeness。

25. **per-source evaluation counts**

   wired-smoke.json：各原 runId+sourceId=1；不同 build 的 Regression 是独立 run，并非同 run 重复。blocked=null。

26. **duplicate-evaluation result**

   完整 collector/owner suite 中 sequential/concurrent/second-process duplicate fail-closed；本轮 smoke 不求值、不事后去重。

27. **per-source resultDigest**

   gitleaks=42b29a8698d4fe2fb0df037a2e58cd934a5721fd0b9a086367496abc6bc60141；semgrep-command-audit=297880fecc8756a7087ff0b173123a4ef56674efa5886398f577faf488dd8448。旧十项完整 digest 见 matrix，保留 #12 binding。

28. **Gate reuse result**

   owner resultDigest == Gate resultDigest，每条 receipt 逐项断言；Gate 不重读报告再求值。

29. **fact-formation receipts**

   fact-formation-receipts.json（两条正常路径）及 fact-formation-build-13.json（真实前置失败）；含 input/candidate/build/run、write target、output hash、cleanup、factDigest。

30. **write operations performed**

   仅临时 scanner Pods、短时 SA/Role/RoleBinding、既有 heavy Lease 生命周期和临时本地报告；具体命令 action/exit 写在 receipts/ledger，外部 release write=0。

31. **external objects created**

   3 个真实扫描 Pod（Gitleaks 1，audit 1，Semgrep 1）；两轮各 5 个短时身份/RBAC 对象；3 次原 heavy Lease transaction（#13/#14/#15）。

32. **external objects cleaned**

   3 Pods、10 个临时身份/RBAC 创建实例、heavy Lease 和 token/guard/workspace 目录全部验证删除；无 force/finalizer 操作。

33. **SOPS regression**

   原 #12 CONTROLLED_ISOLATED_RUNTIME / MIN_RBAC receipt 与 digest 校验通过；不重建测试密钥，不把历史正例改绑定为本轮。

34. **production SOPS Secret/key access**

   0。

35. **Sonar lineage regression**

   原 #12 fresh task c146a69e-cb30-4708-9535-d7f923a2ae20 → analysis db7cf501-fc84-40d6-9fbe-a28fb745b94b 的原 binding 校验通过；本轮不新增分析。

36. **Sonar deferred compatibility debt**

   DEFERRED_REAL_NEGATIVE_EVIDENCE，未升级。

37. **Falco normal regression**

   baseline/final 两个 ACCEPTED_GATE_REPLAY 正常样本 PASS/PASS，owner=Gate digest；明确非本轮 live sensor 扫描。

38. **Falco 2-second regression**

   baseline/final 两个 2s 样本 old FAIL == Policy FAIL == owner FAIL，Gate 同 digest；未增加固定 +16s。

39. **canonical completeness**

   16-set 不变；当前缺四项，且来源保留各原 build binding；不调用全量 completeness 造 COMPLETE。

40. **immutable artifact status**

   INCOMPLETE，未生成 COMPLETE ImmutablePreApprovalArtifact。

41. **artifact hash**

   COMPLETE artifact 不存在，hash 不编造。证据集合由 artifact-sha256.json 独立封存。

42. **candidate/build binding**

   真实 current source + pinned live runtime audit context；新结果分别绑定 #14/#15，不混成一个 build，不宣称新镜像/source attestation。

43. **aggregate Gate**

   全 16 项 aggregate 尚不可生成。局部构建 #14/#15 SUCCESS 是对应 transaction 成功，不等于全量安全通过。

44. **portability classifications**

   runtime-source-matrix.json 按 PORTABLE / NEEDS_ADAPTER / PIPELINE_COUPLED / EXTERNAL_SYSTEM_COUPLED 审视；目前每项均有明确依赖，未强行标成 PORTABLE。

45. **pipeline coupling debt**

   Jenkins workspace/credential/CPS return、Harbor endpoint/repository、Dojo 私有文件和身份、固定 K8s target、toolchain/signing identity；逐来源 futurePluginBoundary 已记录，未实现抽象。

46. **display readiness**

   新两项包含 source/scope/status/decision/start/end/risk/evidence/fact/result digest；旧十项部分缺 source-level 时间/风险摘要，四项无 runtime，明确 PARTIAL，不宣称 Router/Loki/Grafana 接入。

47. **collector/owner tests**

   84/84 PASS，包含 owner duplicate、canonical incomplete、artifact refusal、side-effect guard 等。

48. **candidate tests**

   40/40 PASS，独立可删除测试 checkout。

49. **Policy core**

   5/5 PASS。

50. **contract tests**

   10/10 PASS。

51. **Regression 147/147**

   真实 #14/#15 均 147/147 PASS；#13 前置尝试也 147/147。

52. **final-six specific tests**

   Gitleaks frozen differential recheck 113/113，Command parent 131/131；在 disposable copy 运行，不覆写旧 evidence。后四项未假称执行；权威累计 2202 不增加。

53. **side-effect guard tests**

   27 项 guard 测试包含在 84 中：精确 Pod、禁止生产操作、wrong UID/foreign Pod、Git push、Cosign sign、绝对 kubectl、真实 preload 的 execFile/HTTP 禁止路径。后续 guard 加固经本地真实 preload 负向集成；不假称此前 #14/#15 执行了该加固后的字节。

54. **cleanup tests**

   wrong UID/foreign Pod 拒绝；真实 parent cleanup + 两轮 min-RBAC 12 checks + exact UID 管理清理 + final remote absence checks 通过。

55. **source/hash preservation**

   source-preservation.json：冻结 455 refs、旧 index、baseline-v1、r2、前轮 87-file seal、active V1 workspace 均核对；变更只在 runtime plumbing/dedicated job/new evidence。

56. **V1 active path**

   V1 active；Summary SHA ec9ee51a06d4b9f61c6c0eaf50b374d1e25e6d3ca687908b7596d3a2c794f5d8 未变；PetClinic generation 175、revision 164、spec hash、3/3 Ready 保持。

57. **production Jenkins state**

   petclinic-ci #270 SUCCESS；生产 pipeline 未触发。

58. **validation Jenkins builds**

   #13 前置 FAIL 曾被独立 wrapper 错标 SUCCESS，已修正 oldExit 传播；#14 Gitleaks SUCCESS；#15 combined SUCCESS；#16 read-only discovery SUCCESS。不存在全 16 项成功声明。

59. **release count**

   0。

60. **rollout count**

   0。

61. **REAL_RUNTIME_FACT_CAPTURE**

   INCOMPLETE。

62. **REAL_POLICY_OWNER**

   INCOMPLETE。

63. **IMMUTABLE_ARTIFACT_RUNTIME**

   INCOMPLETE。

64. **SUMMARY_V2_MIGRATION**

   INCOMPLETE。

65. **exact blocker if incomplete**

   四项缺安全的完整 real parent runtime boundary：Harbor admin/validation candidate 与 scoped cleanup；Cosign production-key trust；ZAP 固定 production target；Dojo unique identity/cleanup/native-report 依赖。另无单 build 全量事实，不拼接历史构建。

66. **exact next permitted action if all three runtime verdicts VERIFIED**

   条件未满足。下一步先收口 scoped test registry identity/candidate，隔离 signing/admission trust 与 ZAP context，以及 Dojo exact-run Test cleanup；验证全部 16 项同 build 后才可生成 COMPLETE artifact。任何情况下本轮 STOP，不启用 Summary V2、不迁移 Promotion/Regression、不启动 Plugin Registry。

```text
REAL_RUNTIME_FACT_CAPTURE = INCOMPLETE
REAL_POLICY_OWNER = INCOMPLETE
IMMUTABLE_ARTIFACT_RUNTIME = INCOMPLETE
SUMMARY_V2_MIGRATION = INCOMPLETE
```
