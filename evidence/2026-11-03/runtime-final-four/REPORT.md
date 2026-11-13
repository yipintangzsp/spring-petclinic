# Final four runtime boundaries：本轮报告

1. **starting wired count**

   12；已冻结 branch fix/security-manager-plugin-switches / commit 741ea2866ea142b24c7838e1ef25c8327c79d279、runtime-facts/owner/projection/collector/schema/V1 hashes 和回滚命令，见 baseline.json / rollback-commands.txt。

2. **final-four blocker matrix**

   final-four-boundary-matrix.json 在所有本轮执行前建立；各项原实现、依赖、凭据、写入、绑定、facts、最早边界、对象、清理、权限、fallback 和 blocker 均已记录。

3. **validationRunId**

   rf4-20261103-004987；日期按 Asia/Shanghai，执行记录原始时间戳为 UTC。

4. **Trivy minimum-permission identity**

   未创建。运行中 Harbor 的 RobotPermission schema 按 project/system namespace + resource/action/effect 配置，没有 per-digest 条件；不能在冻结固定共享 project 中证明仅验证候选可 scan-create。详情 trivy-permission-boundary.json。未授予 push/delete/admin。

5. **Trivy candidate image**

   真实只读识别到已有非发布候选 sha256:2fbaea65ab030c56c60c62e3ee9fbe362deb8bbbb8216a891ef4c7bbbcea6d55，tag 0.10.0-ci-1000002，amd64/arm64；未新建镜像。tag immutable=false，未把它宣称为本轮可完整运行的安全候选。

6. **Trivy execution scope**

   要求 CONTROLLED_NON_RELEASE，实际 runtime NOT_EXECUTED；只有 LIVE_READ_ONLY metadata/permission/candidate inspection。

7. **Trivy runtime result**

   BLOCKED，无 scanner/Policy result，不替换本地 CLI，不拿历史报告当本次 facts。

8. **Trivy cleanup**

   0 新 artifact/tag/robot/scan write；历史非发布 artifact 明确保留，未删除既有数据。

9. **Cosign production-key access count**

   0。

10. **Cosign validation key/signature scope**

   先盘点 verification / signing / candidate binding 三类事实；完整 canonical admission 还需要独立 registry writer 与 test-only admission trust。安全前提未齐，未生成无用途测试 key，也未以 VERIFY-only 替代完整父阶段。

11. **Cosign runtime result**

   BLOCKED：test-only key 本身不能替代当前完整 registry/admission 绑定；不使用 production private key，不改现有信任策略。

12. **Cosign cleanup**

   新私钥/密码/签名/registry 对象=0，无残留。

13. **ZAP validation target**

   namespace rf4-20261103-004987，真实 Deployment/Service petclinic；相同应用 digest 通过只读校验本地 registry manifest 复用；只连接 jdbc:h2:mem:runtimevalidation，无 PVC/生产 Secret/生产 DB。

14. **ZAP production-target access count**

   实际 DAST/HTTP 访问生产目标=0。基线仅只读生产 Kubernetes 元数据以记录 digest 和禁止的 Service IP；扫描调用由 guard 映射真实验证对象，CNI default-deny 仅允许 scanner→validation app:8080。

15. **ZAP runtime result**

   #20 SUCCESS；old Gate PASS == Policy PASS，完整原 passive stage/三次原 scan 生命周期/原 synthetic auth probes 均真实执行。#19 清理 wrapper 缺陷导致真实 FAIL/FAIL，保留证据，未重写为 PASS。

16. **ZAP cleanup**

   2 个原扫描 Pod（#19/#20）UID 删除确认；11 个直接创建对象、Deployment 所属 Pod/ReplicaSet、namespace、min-RBAC/token/本地 workspaces 均清理；独立 remote absence 检查通过。

17. **DefectDojo validation identity**

   未创建；现有非 staff CI 身份读取 /api/v2/users/ 实际 403，无已建立的合法最小账号/token provision 管理入口和清理权限；未提权或借用生产写身份。

18. **DefectDojo Product/Engagement/Test IDs**

   只有既有验证 Product 2 / Engagement 2 的只读观察；本轮新 Product/Engagement/Test IDs=[]，未重用 production Tests。

19. **DefectDojo import/query-back result**

   未执行。除权限外，真实 frozen full parent 还需要完整本轮 Trivy、4份 Kubescape、Gitleaks、Semgrep、ZAP、Sonar 原生报告链，当前不齐；不以单个报告/纯 mocked API 冒充完整父阶段。

20. **DefectDojo cleanup/retention**

   0 imports/reimports/PATCH/deletions；既有 production/validation records 未被本轮写入。

21. **final-four source-specific result IDs**

   ZAP=57c2721f6d44be76647a5daa4a2f1291ad26e50db128cc468ad4a73284b58a78；另外三项未生成 resultId。

22. **final-four Policy evaluation counts**

   ZAP #20=1；Trivy/Cosign/Dojo=0（未执行）。#19 是另一个真实失败 run，单独=1，不与 #20 混合。

23. **final-four Gate digest reuse**

   ZAP owner.resultDigest == Gate.resultDigest；逐文件 capture/result/Gate 校验；其他三项 N/A，不假造 Gate。

24. **previously wired 12 regression**

   #20 前后真实执行 twelve-smoke：原 14 条 receipts 对应 12 个 capabilities，校验原 binding/schema/hash/count，不再求值、不将旧结果改绑成本次。collector 兼容性测试也通过。

25. **individual wired total**

   13/16，新增 ZAP。

26. **same-run canonical validation build**

   未触发全 16 项运行，因为其余三边界尚未 individually closed；#20 是 ZAP transaction validation，不冒称全量 canonical run。

27. **same-run source count**

   #20 当前真实观察=2：Regression、ZAP。

28. **missing same-run sources**

   sbom, falco-baseline, kyverno, kubescape, gitleaks, sops, trivy, cosign, sonarqube, falco-final, defectdojo, provenance, build-provenance, semgrep-command-audit。其中已在其他原 build 验证的来源仅作 smoke；未拼接。

29. **duplicate source check**

   #20 两个 sourceId/resultDigest distinct，每项一次。前置 canonical manifest 仍 16，无 alias/Promotion 新增。

30. **cross-run stale result rejection**

   standalone completeness-negative 8/8 含 wrong runId / previous-build receipt / wrong candidate；candidate suite 40/40 含 stale source/build/project/job；旧 #12/#14/#15 未合并。

31. **fact contract completeness**

   ZAP 真实完整 facts 经现有 frozen adapter；native report 字节哈希与 Jenkins 归档完全一致。Trivy/Cosign/Dojo 没有 runtime envelope，不映射 SKIPPED。

32. **16/16 canonical completeness**

   INCOMPLETE；expected 16，当前 #20 observed 2；未降低 validator。

33. **immutable artifact path**

   无 COMPLETE artifact path。

34. **artifact hash**

   未生成 artifact，因此不编造 artifact hash；证据目录有独立 artifact-sha256.json seal，不与 runtime artifact 混淆。

35. **same-run binding result**

   #20 两个实际结果同 job/build/runId/source/candidate binding，验证通过；这不等于全 16 项 binding proof。

36. **candidate/build binding**

   验证目标使用 127.0.0.1:30050/petclinic/petclinic@sha256:489cb821573ff1f98edd846d5949d74bf3391b24e2f1fe5bcfb71c6be0793137，原 namespace/真实 Service IP/Pod imageID 记录可追溯；应用镜像复用已有 build，不伪称由当前 collector source 重新构建或签名 attestation。

37. **aggregate Gate result**

   只复用单项 Gate；全 16 aggregate 未生成，不从部分 PASS 推断全量 PASS。

38. **all-source evaluation counts**

   runtime-source-matrix.json 保留各原 build 的一次求值证据；#20 counts={regression:1,zap:1}。未执行来源=0，无 Summary/Promotion 求值。

39. **all-source Gate resultDigest reuse**

   原 12 receipts 保留既有相同 digest；新 ZAP 同 digest；未声称缺失三项已有 Gate。

40. **negative completeness tests**

   8/8：missing、duplicate、wrong run、stale build、wrong candidate、invalid/tampered factDigest、invalid resultDigest、malformed status；仅 SYNTHETIC_UNIT_ONLY/in-memory，不作为真实 COMPLETE。

41. **Falco normal regression**

   ACCEPTED_GATE_REPLAY baseline/final 各一个 normal PASS/PASS；明确不是本轮新 live sensor 结果。

42. **Falco 2-second regression**

   两个 2s 原边界 old FAIL == Policy FAIL == owner FAIL，Gate 同 digest；固定 +16s 未引入。

43. **SOPS production access counts**

   生产 Secret=0，生产 age private key=0；原 #12 CONTROLLED_ISOLATED_RUNTIME/MIN_RBAC receipt 不变；本轮未重建/访问生产凭据。

44. **Sonar lineage regression**

   原 #12 current-build fresh task→analysis→server Quality Gate 原关联与 binding 保持；本轮不把历史结果伪装成新分析。

45. **Sonar compatibility debt**

   DEFERRED_REAL_NEGATIVE_EVIDENCE，未提升。

46. **portability classification**

   runtime-source-matrix.json 对全部 16 项保留 PORTABLE / NEEDS_ADAPTER / PIPELINE_COUPLED / EXTERNAL_SYSTEM_COUPLED 分类；ZAP 是 NEEDS_ADAPTER，不把验证 wrapper 当最终插件架构。

47. **pipeline/external coupling debt**

   Harbor 固定 project/repo 与 robot scope；Cosign signing/trust/registry；ZAP namespace/controller/toolchain target；Dojo API/治理身份/私有前序文件；均记录，未启动最终 plugin abstraction/decoupling。

48. **display contract readiness**

   全部 16 条 review rows 有 source/scope/status/decision/time/evidence/fact/result 字段；blocked/missing 值保留 null，旧 receipts 时间/风险摘要缺口明确 PARTIAL；不宣称已有全量 normalized runtime result 或 Router/Loki/Grafana 接线。

49. **collector/runtime tests**

   114/114 PASS。

50. **side-effect guard tests**

   49 个既有+ZAP guard 检查包含在 114 中；包括真实 wrapper 已删除 Pod/替换 UID 负向回归。

51. **candidate tests**

   40/40 PASS，disposable checkout。

52. **Policy core**

   5/5 PASS。

53. **contract checks**

   10/10 PASS。

54. **Regression 147/147**

   真实 #20 147/147 PASS，#19 也 147/147；未改 Regression 语义。

55. **Trivy tests**

   frozen parent differential recheck 129/129 PASS，独立临时复制；不冒称 real Harbor scan。

56. **Cosign tests**

   frozen parent differential recheck 268/268 PASS；不冒称新 test-key signing。

57. **ZAP tests**

   frozen parent 177/177 PASS；真实 #20 full stage PASS；target/wrapper guard 22 tests 在 runtime suite 内。

58. **DefectDojo tests**

   frozen parent differential recheck 69/69 PASS；不把 canned API tests 当本轮真实导入。

59. **completeness tests**

   standalone 8/8，亦包含在 runtime suite；权威兼容性累计仍 2202，不累计这些重复测试。

60. **artifact integrity tests**

   candidate trusted-digest/tamper/immutable-file tests PASS；native-report-identity-checks 全 match；无真实 COMPLETE artifact，不能宣称其运行完整性通过。

61. **cleanup tests**

   错误 UID/foreign target 拒绝；真实 #19 failed-parent 和 #20 successful-parent scanner deletion 均证实 absence；precleanup ownership/foreign/PVC checks、11对象删除和 token/workspace absence 全通过。

62. **source/hash preservation**

   source-preservation.json：本轮前 baseline 6209 files；只允许 runtime plumbing 与专用 Jenkinsfile；冻结 refs/index/r2/前轮87-file seal/owner/collector/projection/canonical manifest/V1 全核对。

63. **production V1 state**

   V1 active，Summary ec9ee51a06d4b9f61c6c0eaf50b374d1e25e6d3ca687908b7596d3a2c794f5d8 未变；PetClinic generation 175 / revision 164 / spec hash unchanged，3/3 Ready；Argo Synced/Healthy 同 revision，3 nodes Ready。

64. **production Jenkins state**

   petclinic-ci #270 SUCCESS 未变，未触发 production build。

65. **validation Jenkins builds**

   #17 只读发现 SUCCESS；#18 binding 前置失败；#19 wrapper 清理判定失败且 old/Policy 都 FAIL；#20 正常目标扫描 SUCCESS。完整失败证据保留。

66. **release count**

   0（临时验证 Deployment 创建不属于生产 release）。

67. **rollout count**

   0 production rollout；仅本轮验证目标为同 digest 的本地 transport alias 做过一次受控修改，已删除该目标。

68. **REAL_RUNTIME_FACT_CAPTURE**

   INCOMPLETE。

69. **REAL_POLICY_OWNER**

   INCOMPLETE。

70. **IMMUTABLE_ARTIFACT_RUNTIME**

   INCOMPLETE。

71. **SUMMARY_V2_MIGRATION**

   INCOMPLETE。

72. **exact blocker if incomplete**

   Trivy：当前权限无法在冻结固定共享 project 证明 validation-only scan；Cosign：缺独立 test-only registry writer/admission trust 全父阶段边界；Dojo：当前用户管理 403、无已验证最小身份/cleanup 权限，且缺完整本轮原生报告链。三项停止，不强行16/16。

73. **exact next permitted action if all three runtime verdicts VERIFIED**

   条件尚未满足。先审查可保留 frozen Gate semantics 的独立 validation Harbor target binding/最小权限、Cosign registry+test-trust、Dojo provision+cleanup+native-chain 方案；四项 individually closed 后才运行一个真实同 run 16/16。若未来三项 runtime verdicts VERIFIED，本轮仍 STOP，不自动连接 Summary V2、不迁移 Promotion/Regression、不启用 SECURITY_ENABLED/Plugin Registry。

```text
REAL_RUNTIME_FACT_CAPTURE = INCOMPLETE
REAL_POLICY_OWNER = INCOMPLETE
IMMUTABLE_ARTIFACT_RUNTIME = INCOMPLETE
SUMMARY_V2_MIGRATION = INCOMPLETE
```
