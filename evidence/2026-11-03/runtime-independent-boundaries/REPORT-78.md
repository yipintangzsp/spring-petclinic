# Runtime Facts：Cosign 与 DefectDojo 收口报告

本轮结果：Cosign VERIFIED，DefectDojo INCOMPLETE，capability 14/16。整体四项仍INCOMPLETE。未发布、未rollout、未重开Trivy。

证据分类：本轮Cosign为REAL_CONTROLLED_EXECUTION；负向父阶段/回放为SYNTHETIC_UNIT_ONLY或CONTROLLED_ACCEPTED_GATE_REPLAY；原13来源为已接受历史runtime回执的原绑定复核，未重绑定。

1. **starting wired capability** — 13/16。原13来源保留各自原始build/run/candidate绑定，仅重验，不重绑定、不再次评价。

2. **Trivy blocker state** — ENVIRONMENT_BLOCKED / INCOMPLETE。主机权威可用25.21GiB，扩容最低guard37GiB，缺11.79GiB；无独立外部容量、有效backup/restore。没有把环境阻塞改成PASS/SKIPPED/NOT_CONFIGURED。

3. **Trivy blocker receipt** — trivy-engineering-blocker.json：EngineeringEnvironmentBlocker，sourceId=Trivy，blockerType=ENVIRONMENT，reason=HOST_CAPACITY_AND_BACKUP_UNAVAILABLE，runtimeResultPresent=false。不是ResolvedPolicyResult，无factDigest/resultDigest。

4. **Trivy execution attempts this iteration** — 0。没有存储重试、代理修改、DB刷新、镜像删除、扫描请求。所有Trivy边界单元测试使用synthetic输入，未执行真实Trivy。

5. **Cosign frozen contract** — 实际读取原signing.mjs admission、scanner-runtime.mjs、cosign-verification.mjs与冻结adapter。冻结入口先验证Lease/工具，再SOPS解密、派生公钥比较、写本轮OCI空层fixture、签名/验签、三种server dry-run、清理和写报告。完整6类事实清单见cosign-frozen-contract.json。

6. **Cosign signing requirement** — VERIFY-only能否覆盖实际冻结父阶段：NO。必须取得signed实际签名成功、wrong-key独立密钥生成/签名、派生公钥一致、post-sign digest claim、真实admission三例结果；没有使用生产签名身份的必要条件。

7. **Cosign validation trust model** — run=rf3-20261103-9730f2。一次性EC prime256v1测试Cosign keypair、测试age key与加密bundle，只放/tmp私有目录及临时checkout。public SHA256=c92bf03766ebfe16e52d27e50fe04334bc6126ba174f76ea07c1ecfc06a6fdec。12个临时Kubernetes对象含两个单独的namespace精确selector webhook；原webhook/生产公钥策略未改。

8. **production key access count** — 0。没有绑定生产platform-signing-age、读取/解密生产私钥、将生产私钥注入job或归档。只解密本轮测试bundle；生产签名变更0。

9. **Cosign validation artifact** — petclinic/signature-fixtures，ci-32-signed / ci-32-unsigned / ci-32-wrong-key，三个manifest digest分别见cosign-source-receipt.json。signed candidate=core.harbor.domain/petclinic/signature-fixtures@sha256:a786348b1bfb3125c150d94d58d6edc51beb36fb832ad258e000b03fbab7d899；空层OCI fixture非应用发布。

10. **Cosign registry write scope** — VALIDATION_ONLY_SIGNATURE_WRITE。仅本轮三份fixture及signed/wrong-key签名，测试robot249仅petclinic project pull/push/artifact-read；额外command/request guard固定build32仓库/immutable digest。创建前三个fixture tag均404；没有release tag、GitOps引用、生产签名覆盖。

11. **Cosign execution result** — REAL_CONTROLLED_EXECUTION：专用job security-runtime-facts-20261102 #32 SUCCESS，原entrypoint exit0；signed CLI=true/admission=true，unsigned=false/false，wrong-key=false/false。真实Kyverno拒绝原因分别为no signatures found、invalid signature。

12. **Cosign old Gate decision** — PASS。未修改的signing.mjs admission真实exit0。

13. **Cosign Policy decision** — PASS。现有cosign-parent adapter + baseline-v1 / default standard，与真实旧Gate一致。

14. **Cosign evaluation count** — 1。evaluationId=security-runtime-facts-20261102#32:cosign；factDigest=3c4ebafa611fb3f9e1e15ade68b255d60452b5673e25b77f73cbd33910e5dfb1。owner原子claim；未另建第二owner重算真实样本。

15. **Cosign resultDigest** — c7dbafbf7cf496456c872297eedcf800cebf110073793ad02ebfda70842de2b1。capture/result/Gate/receipt四处一致，rawPayload未写入归档。

16. **Cosign Gate reuse** — GateInputDigest=c7dbafbf7cf496456c872297eedcf800cebf110073793ad02ebfda70842de2b1，等于owner.resultDigest。Gate不调用第二次Policy。

17. **Cosign negative tests** — 真实本轮：wrong key、missing signature的CLI和admission均拒绝。冻结完整父阶段268/268：错误claim/candidate digest、source/artifact绑定、外部repository、malformed验签结果及registry/tool/report/cleanup失败等；guard拒绝外仓库/其他build/生产image。subject/repository负例属于受控单元/冻结回放，不冒充本轮真实生产攻击。原Gate没有的规则未补造。

18. **Cosign cleanup** — 测试私钥/password/age key、临时Docker auth与checkout已删；robot249删除且GET404；12个Kubernetes对象按UID清理（包括两个临时webhook），SA短时token/kubeconfig删，/tmp私有目录在#33确认移除。三份测试manifest和两份签名明确VALIDATION_RETAINED，精确digest与GET200/unsigned-signature404见validation-registry-retention.json；保留作可追溯证据。

19. **COSIGN_RUNTIME_FACT_CAPTURE** — VERIFIED。范围为测试信任根下真实冻结admission路径；不代表生产私钥身份验收、全16同run或生产发布。

20. **Dojo frozen API contract** — 实际defectdojo.mjs + dojo-client.mjs未改。父阶段需完整当前Trivy、四份同source Kubescape、Sonar native issues、Gitleaks/Semgrep/ZAP与source证明；对每report执行import或reimport→query→同报告reimport→query，要求Finding ID稳定，再精确FP PATCH与Product全量分页统计。不是CVE scanner。

21. **Dojo required operations** — dojo-required-api-operations.json逐项列METHOD/endpoint/object/read-write/scope。GET Product、tests、findings；POST import-scan/reimport-scan；既有精确FP PATCH。Product/Engagement create和delete/close不在冻结parent中，若将来允许仅validation bootstrap/cleanup。UNKNOWN=0；本轮API操作=0。

22. **Dojo identity model** — 现有jenkins-petclinic id2为非staff/非superuser、groups0/global model权限0，但可访问生产Products1/2，不用其写测试。最小未来模型：独立非staff用户，无全局权限，仅授权自己的validation Product；具备全部report prerequisites后才发临时token。

23. **Dojo privilege scope** — 本轮只读SSH管理入口读取DB对象元数据/计数摘要与现有用户授权关系，未读token值，未创建用户或扩大权限。未使用生产admin API token。新隔离Dojo环境也无法解决缺失当前Trivy输入，未部署。

24. **Dojo validation Product ID** — null；本轮未创建。没有复用生产Product ID作为写目标。

25. **Dojo validation Engagement ID** — null；本轮未创建。

26. **Dojo validation Test ID** — null；本轮未创建。

27. **Dojo report identity/digest** — null。当前验证workspace没有trivy-audit.json，Gitleaks/Semgrep/ZAP native也缺失；Kubescape文件存在并不证明本轮完整链。没有读取历史PASS报告冒充当前报告，也没有制造report digest。

28. **Dojo import/reimport result** — NOT_TESTED，imports=0/reimports=0。先验报告依赖未满足，停在真实父阶段执行之前。

29. **Dojo query-back result** — NOT_TESTED；DB只读元数据盘点不是import之后的API query-back。

30. **Dojo pagination result** — NOT_TESTED（真实API）；现有same-origin、bounded next循环已读代码并在69项冻结单元中复验，但不能替代真实分页链。

31. **Dojo dedupe result** — NOT_TESTED（真实API）。原同报告再导入Finding ID稳定语义未改变，单元通过不升级在线验收。

32. **Dojo old Gate decision** — null / NOT_EXECUTED。没有将本轮缺证据伪造成旧Gate执行成功；缺Trivy在冻结合成测试中确实FAIL，但不是本轮真实parent执行结果。

33. **Dojo Policy decision** — null。未送缺失原始API事实到owner，不造PASS/WARN/FAIL。

34. **Dojo evaluation count** — 0，evaluationId=null。

35. **Dojo resultDigest** — null，factDigest=null。

36. **Dojo Gate reuse** — NOT_TESTED；没有result可供Gate复用。

37. **Dojo cleanup/retention state** — NO_VALIDATION_OBJECTS_OR_TOKENS_CREATED。无需删/关/archive正常对象；本轮新Product/Engagement/Test/token均0。

38. **production Dojo mutation count** — 0。前后Product2、Engagement2、Test35、Finding6627；IDs/选择的治理元数据SHA256完全相同。原生产对象未导入、修改或删除。

39. **DEFECTDOJO_RUNTIME_FACT_CAPTURE** — INCOMPLETE。冻结parent仍耦合当前Trivy原生报告；本轮明确禁止Trivy与最终Dojo解耦，因此不能安全完成完整生命周期。

40. **final wired capability** — 14/16＝既有13个来源已接受边界 + 本轮Cosign已接受边界。不是同run14份artifact，不合并历史facts。

41. **canonical expected count** — 16，EXPECTED_SOURCES未修改。不存在把缺失来源从expected移除的做法。

42. **canonical missing sources** — capability层缺trivy/defectdojo。#32当前owner只有cosign，snapshot实际missing另外15个来源；全16同run未启动，既有13保持原绑定。详见runtime-source-matrix.json。

43. **artifact completeness result** — INCOMPLETE。没有真实COMPLETE/ImmutablePreApprovalArtifact，artifact path/hash=null。engineering receipt和封存SHA清单不作为Policy artifact。

44. **Plugin portability classifications** — Cosign overall EXTERNAL_SYSTEM_COUPLED：registry外部耦合、trust/signer NEEDS_ADAPTER、candidateDigest PORTABLE、当前stage输入PIPELINE_COUPLED。Dojo overall EXTERNAL_SYSTEM_COUPLED：API/lifecycle外部耦合、credential NEEDS_ADAPTER、report私有文件PIPELINE_COUPLED。见architecture-readiness.json。

45. **future capability metadata** — 仅设计元数据：Cosign IMAGE_REF/CANDIDATE_DIGEST/REGISTRY_ACCESS/CREDENTIALS/BUILD_METADATA/PROVENANCE_METADATA；Dojo SECURITY_REPORTS/DEFECTDOJO_API/CREDENTIALS/BUILD_METADATA。无capability engine/Plugin Registry。

46. **display readiness** — Cosign提供sourceId、scope、executionStatus、decision、start/end、fact/result digest、evidenceRefs、artifact与signature摘要；Dojo同字段保留null/NOT_EXECUTED并明确missing，不能伪造Finding/Test/dedupe数据。无Dashboard/Router修改。

47. **Falco regression** — 4/4受控完整Gate回放：baseline正常、final正常均old/Policy/owner PASS；两个2秒IO边界均FAIL；每例evaluationCount1、Gate同resultDigest。样本保持各自observed windowEndMs，没有fixed+16s。不是本轮线上重新运行Falco。

48. **SOPS production access count** — 本轮真实生产Secret访问0、生产age私钥访问0。既有SOPS scope=CONTROLLED_ISOLATED_RUNTIME由13来源smoke验证；本轮Cosign的SOPS只解本轮测试key/bundle。三份历史已脱敏SOPS只复验shape，不重评脱敏内容。

49. **Sonar compatibility debt** — DEFERRED_REAL_NEGATIVE_EVIDENCE。已接受runtime/lineage保持原样；没有提升真实Sonar负例验收。

50. **runtime/collector tests** — 154/154＝runtime基础143/143 + disposable candidate completeness负例11/11。另boundary-evidence十项工程回执/隔离/清理测试10/10。不计入2202 compatibility基线。

51. **candidate tests** — 40/40，全部disposable checkout，旧封存证据未写入；不是V2启用。

52. **Policy core** — 5/5。

53. **contract tests** — 10/10。默认standard、显式low、strict、override边界与POLICY_ERROR等未改变。

54. **Regression 147/147** — 本地147/147，专用Jenkins #33也147/147，最终SUCCESS。既有Regression流程未迁移。

55. **Cosign tests** — 268/268 frozen complete parent测试 + runtime中Cosign boundary17/17 + 本轮3例真实CLI/admission；重复测试不改变权威2202样本数。

56. **Dojo tests** — 69/69 frozen parent单元/差分，真实import lifecycle仍NOT_TESTED。

57. **authorization tests** — runtime side-effect guards与Cosign command/request allowlist通过；本轮实际robot249 live权限验证通过，最小SA只具备validation Pod create及指定Lease get。Kyverno只增加读取本轮测试registry Secret的临时named Role。错误/外部namespace、生产image、其他build、任意exec/Secret get命令被guard拒绝。

58. **cleanup/retention tests** — boundary-evidence10/10覆盖12对象UID清理、临时凭据移除；#33原只读postcheck确认私有目录移除且生产artifact unchanged。本轮5份测试registry artifact显式保留，unsigned signature不存在，不假称全registry删除。

59. **incomplete-set tests** — 11/11：missing source、duplicate、stale/wrong run/source/candidate、tampered digests、invalid status、missing executionScope、duplicate evaluation receipt；runtime原子owner/source claim与Gate重复handoff fail-closed通过。Trivy工程receipt被RuntimeSourceFacts validator拒绝，无ResolvedPolicyResult字段。

60. **source/hash preservation** — 455/455 frozen hash references，229个unique文件一致；本轮8文件基线全同。六个旧证据封存共497文件全部一致。兼容样本数2202保持不变。原冻结Gate、Policy baseline、Summary producer均未修改。

61. **production Jenkins state** — petclinic-ci #270 SUCCESS未变化；本轮只执行专用validation #31 bootstrap/#32 Cosign/#33 Regression，均SUCCESS。专用job和本地Jenkinsfile.runtime-facts均恢复本轮前文本SHA。

62. **V1 state** — V1仍active。Summary SHA256 ec9ee51a06d4b9f61c6c0eaf50b374d1e25e6d3ca687908b7596d3a2c794f5d8。活动manager SHA6854436a…、producer038320f0…未变；线上workspace没有新增Policy Engine或Summary V2 owner文件。

63. **nodes state** — devops、aliyun-worker、ucloud-worker均Ready；platform-heavy验证Lease已释放。没有k3s/tunnel/node配置变更。

64. **PetClinic state** — 3/3 Ready、3个Ready Endpoint、HTTP200；Deployment UID/generation175/revision164/spec不变，Argo Synced/Healthy、同revision/spec。Harbor7个Pod均Ready；现网/前一revision/#214 rollback/既有非发布candidate保留。

65. **release count** — 0。

66. **rollout count** — 0。

67. **TRIVY_STORAGE_ENVIRONMENT** — ENVIRONMENT_BLOCKED

68. **TRIVY_RUNTIME_FACT_CAPTURE** — INCOMPLETE

69. **COSIGN_RUNTIME_FACT_CAPTURE** — VERIFIED

70. **DEFECTDOJO_RUNTIME_FACT_CAPTURE** — INCOMPLETE

71. **FINAL_WIRED_CAPABILITY** — 14/16

72. **REAL_RUNTIME_FACT_CAPTURE** — INCOMPLETE

73. **REAL_POLICY_OWNER** — INCOMPLETE

74. **IMMUTABLE_ARTIFACT_RUNTIME** — INCOMPLETE

75. **SUMMARY_V2_MIGRATION** — INCOMPLETE

76. **exact blocker if Cosign incomplete** — 无。本轮测试信任根完整冻结admission边界VERIFIED。未使用生产私钥，不把它扩展为生产signer身份/全16同run的证明。

77. **exact blocker if Dojo incomplete** — FROZEN_PARENT_REQUIRES_CURRENT_TRIVY_REPORTS_WHILE_TRIVY_ENVIRONMENT_BLOCKED。还缺当前其他native reports与真实API观察collector/生命周期；禁止用synthetic/mock/历史PASS替代。该父阶段在冻结语义下并非独立于Trivy。

78. **exact next permitted action** — STOP。等待用户对外部容量恢复/Trivy前置条件，或独立Dojo解耦方案的另行授权；本轮不执行任一路径，不开Summary V2/Registry/Router，不发布。

```text
TRIVY_STORAGE_ENVIRONMENT = ENVIRONMENT_BLOCKED
TRIVY_RUNTIME_FACT_CAPTURE = INCOMPLETE
COSIGN_RUNTIME_FACT_CAPTURE = VERIFIED
DEFECTDOJO_RUNTIME_FACT_CAPTURE = INCOMPLETE
FINAL_WIRED_CAPABILITY = 14/16
REAL_RUNTIME_FACT_CAPTURE = INCOMPLETE
REAL_POLICY_OWNER = INCOMPLETE
IMMUTABLE_ARTIFACT_RUNTIME = INCOMPLETE
SUMMARY_V2_MIGRATION = INCOMPLETE
```

STOP。
