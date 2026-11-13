# Runtime Facts 最后三项边界验证报告

validationRunId: `rf3-20261103-7d6715`

结论：尚未满足同run16/16条件。保留Trivy/Cosign真实FAIL回执及Dojo身份验证证据；不把失败分支事实完整当作尚未发生的native-report/admission/import生命周期完成。生产未发布、未rollout。

本报告中的测试回归、历史回执复核、当前真实执行分开标注；不拼接历史结果生成COMPLETE。

1. **starting wired count**：13/16。当前已接受的完整来源边界仍为 13/16；新增两条真实失败分支回执，见第25项。

2. **Trivy required Harbor API operations**：GET 指定 candidate root、GET child scan_overview、POST 指定非发布 child /scan、成功后 GET additions/vulnerabilities。候选已存在，原 ensure-candidate 仅 GET；copy/push/tag/delete 分支由 guard 禁止。详见 required-api-operations.json。

3. **Trivy minimum permissions**：project petclinic：artifact:read、scan:read、scan:create；无 push/delete/admin/tag/promotion。运行期请求 guard 进一步限制到指定 candidate/root/两个架构 child，禁止扫描当前发布镜像。

4. **Trivy validation identity**：robot$petclinic+rf3-20261103-7d6715-scan，Harbor ID246；#21/#23 实际验证 grant；#23 post 撤销并确认404。管理身份仅用于 bootstrap/revoke，未传入 scanner。

5. **Trivy validation candidate**：预先存在的非发布候选 petclinic/petclinic@sha256:2fbaea65ab030c56c60c62e3ee9fbe362deb8bbbb8216a891ef4c7bbbcea6d55；生产者 petclinic-candidate-build #2；amd64/arm64 child 见 trivy-source-receipt.json。未创建/覆盖 release tag，无 GitOps 消费；保留既有候选。

6. **Trivy runtime result**：真实 #23 FAILURE。POST scan=202，随后服务端 scan=Error；job 4c304eedbe6aea086bdfbf49。下载 ghcr.io Trivy DB 时代理192.168.1.238:10808拒绝连接。old FAIL == standard FAIL。没有 CVE native report，Critical/High/Medium、DB freshness 均 UNKNOWN，不能填写0或宣称扫描成功。adapter对已发生失败分支 evidenceComplete=true；未补齐成功扫描/报告生命周期。

7. **Trivy resultDigest reuse**：9c3318b7cfef6af72907402273bb278bb71644fe3d501a39106bc7b894e7f4d7；owner == GateInputDigest，evaluationCount=1，raw facts未改变。

8. **Trivy production mutation count**：生产 artifact/tag/GitOps/release变更均0；仅触发非发布候选 child 的 scan metadata，未改共享 Trivy 配置。生产 root/children/tag 前后相同，#30 再核对。

9. **Cosign frozen fact requirements**：原 signing.mjs admission：锁定工具/Lease、SOPS解密、key与输入public key一致、registry fixture digest、sign/verify、unsigned/wrong-key分类、真实server admission、临时key清理及原报告写入；不使用verify-only替代。

10. **Cosign validation trust boundary**：独立一次性 age + Cosign keypair，在独立临时checkout覆盖测试输入文件，未改仓库生产公钥/密文。namespace rf3-20261103-7d6715-cosign 内创建测试 Policy；public SHA256 3d537f14db1f5088b4a88666d584cfbcc71cef2381e628b00bfcaea8f388d896。测试 Policy 被共享 webhook namespaceSelector 排除，admission边界未验收。

11. **production Cosign key access count**：0；没有绑定 platform-signing-age，未读取生产私钥或解密生产 signing bundle。测试私钥仅生成/解密在临时目录和内存fd3；未归档。

12. **Cosign validation artifact**：仅 petclinic/signature-fixtures 的 ci-26-signed / ci-26-unsigned / ci-26-wrong-key；三个精确digest见 cosign-source-receipt.json。没有 production release/GitOps/tag 覆盖。

13. **Cosign runtime result**：真实 #26 FAILURE：签名及CLI验签实际成功，unsigned CLI正常拒绝；signed server dry-run=0，unsigned server dry-run也=0，原父阶段以 Actual signature admission mismatch: unsigned 失败。Policy正确FAIL；未伪造deny，wrong-key admission尚未执行。现有allowlisted namespace另有限定image repositories，不能绕过全局Gate强行换目标。

14. **Cosign resultDigest reuse**：92bcc507fa6ad1d6b24ca19598895da1f9ff49fb5538c81e34f1a85d274ba498；old FAIL == standard FAIL，owner == Gate，evaluationCount=1。失败分支事实完整不等同于所有admission cases已覆盖。

15. **Cosign cleanup**：测试age/Cosign私钥、password、临时Docker auth、短时kubeconfig/token、robot248、10个测试Kubernetes对象均已移除；#30对三个fixture tag及对应三个.sig tag全部GET404。删除父artifact会级联删除signature：#28/#29出现过后续DELETE404；最终只读查无残留，未绕过registry权限或改保留规则。

16. **Dojo required API actions**：Product可见性；Engagement/Test列表；import/reimport-scan multipart；按Test查询Finding及分页；同报告二次reimport/dedupe；对验证Finding的既有false-positive PATCH；最终Product finding query。完整顺序仍采用未改原父阶段。

17. **Dojo minimum permission model**：Dojo_User非staff/非superuser，无groups/global model permissions，仅新Product.authorized_users授权。管理bootstrap使用既有可信SSH的manage.py，仅创建/删除自己的fixture；runtime仅临时用户token，无生产admin token fallback。

18. **Dojo validation identity**：rf3-20261103-7d6715-dojo，user5；实际只可列出Product5，生产Product1/2均404，错误测试token=403。身份边界真实验证通过，不代表import/dedupe权限已完整验证。

19. **Dojo Product/Engagement/Test IDs**：Product5=security-manager-runtime-validation-rf3-20261103-7d6715；Engagement3=runtime-rf3-20261103-7d6715；Test未创建。没有复用生产Test ID。

20. **Dojo import result**：NOT_EXECUTED：原父阶段强制要求当前完整Trivy native reports，#23没有报告。未用历史报告、合成Finding或私有前序文件伪装当前上下文；imports=0。

21. **Dojo query-back result**：完整scan import query-back NOT_TESTED；只完成Product授权边界真实GET及专属Engagement POST201。

22. **Dojo dedupe result**：NOT_TESTED。没有发生真实import/reimport，不使用69个本地测试替代在线dedupe。

23. **Dojo cleanup/retention state**：REMOVED：Product5、Engagement3、user5、短时API token及Jenkins私有文件已删除。删除前确认Test0、Finding0；正常Product1/2完整元数据摘要不变。

24. **Dojo production mutation count**：0。只创建过自己的验证Product/Engagement/user/token；没有生产import/PATCH/DELETE。

25. **final three successfully wired**：完整边界验收新增0。Trivy/Cosign已实际执行并完成失败分支 RuntimeSourceFacts→冻结adapter→owner一次→相同digest Gate；两者已有事实完整回执，但未将未生成的漏洞报告或未生效的admission负例冒充验收完成。Dojo只有身份/生命周期前半段，无父阶段Policy回执。

26. **final wired count**：已接受完整边界13/16；有真实回执的来源ID合计15（含本轮两个FAIL分支），这不是same-run15/16，更不是COMPLETE artifact。runtime-source-matrix.json同时保留这两个不同计数。

27. **existing 13 regression**：#21/#23/#24/#25/#26/#27/#28/#29/#30轻量smoke均验证既有13来源原绑定和16条原receipt；原fact/result/Gate digest不变，未重评、未重新绑定。runtime 154/154及candidate40/40通过。

28. **same-run validation build ID**：未执行：三个完整边界尚未全部验收。#30为清理/保留状态及Regression回归，不是canonical16流水线。

29. **same-run canonical source count**：#23=3（Regression/SBOM/Trivy），#26=1（Cosign）；其他来源仍在各自原build。没有同run16。

30. **same-run missing source count**：N/A（16-source execution未启动）；不得将#12/#14/#15/#20/#23/#26拼接成16。

31. **per-source executionScope**：附录及runtime-source-matrix.json逐来源记录，历史来源不重绑定。SOPS=CONTROLLED_ISOLATED_RUNTIME；Trivy/Cosign=CONTROLLED_NON_RELEASE；Dojo=CONTROLLED_VALIDATION_IDENTITY_ONLY。

32. **per-source evaluation count**：既有13各原receipt=1；#23 Trivy=1，#26 Cosign=1，Dojo=0。没有same-run16次评价证明。

33. **duplicate-evaluation result**：PASS（runtime原子claim/重复评价单元测试，新增runtime completeness duplicate evaluation receipt负例拒绝）；真实两个新owner各1次。

34. **per-source resultDigest**：见附录及源receipt；Dojo=null。所有历史digest仅用于原绑定回归，不输入当前artifact。

35. **Gate resultDigest reuse**：#23 Trivy / #26 Cosign均精确复用；既有13原回执smoke一致；16-source aggregate Gate=NOT_EXECUTED。

36. **canonical completeness**：INCOMPLETE；16-source same-run未满足。

37. **immutable artifact status**：NOT_GENERATED；未输出COMPLETE。

38. **immutable artifact path**：null。artifact-sha256.json若生成，仅是本轮证据目录封存清单，不是ImmutablePreApprovalArtifact。

39. **artifact hash**：null（无真实COMPLETE artifact）。

40. **same-run binding result**：全16 NOT_TESTED；两个真实新source各自build/source/candidate绑定已保存，未跨run。

41. **stale cross-run rejection**：PASS（candidate40/40及完整性负例11/11）；只是单元证明，不冒充线上16-source执行。

42. **candidate/build binding**：Trivy=build23非发布候选2fba…；Cosign=build26测试fixture393c…/cabc…/fef2…；Dojo无scan artifact。sourceRevision均741ea2866ea142b24c7838e1ef25c8327c79d279；具体运行工具working-tree hash见各build bundle，不能仅凭Git SHA推断新增collector代码。

43. **aggregate Gate result**：NOT_EXECUTED。两个失败分支独立Gate均FAIL，#30 SUCCESS不会覆盖它们。

44. **negative artifact tests**：11/11：15/16、duplicate source、wrong runId、stale previous build、wrong sourceRevision、wrong candidate、invalid/tampered factDigest、invalid resultDigest、malformed status、missing executionScope、duplicate evaluation receipt。SYNTHETIC_UNIT_ONLY，不生成真实COMPLETE。

45. **Falco normal regression**：baseline正常和final正常：whole-Gate受控replay各PASS，Policy/owner/Gate一致；本轮不是新live Falco runtime观察。

46. **Falco 2-second regression**：baseline/final两条原2秒边界replay：old FAIL=Policy FAIL=owner FAIL，Gate同digest；4/4 Falco矩阵通过，无固定+16s。

47. **SOPS production access count**：Secret/age私钥/credential value读取均0；本轮无新SOPS执行，只复核既有isolated receipt/三条脱敏archive shape，不向Engine输入脱敏的虚假plaintext。

48. **Sonar lineage**：未产生新analysis；已接受#12 task c146a69e-cb30-4708-9535-d7f923a2ae20 → analysis db7cf501-fc84-40d6-9fbe-a28fb745b94b → GateOK保持原绑定。没有将旧analysis替代当前run。

49. **Sonar compatibility debt**：DEFERRED_REAL_NEGATIVE_EVIDENCE，不变。

50. **ZAP isolation regression**：保留#20真实隔离positive原绑定；22项ZAP guard回归通过。本轮ZAP生产target访问0、ZAP新扫描0，没有回退固定生产URL。

51. **portability classification**：附录逐16来源列出PIPELINE_COUPLED / EXTERNAL_SYSTEM_COUPLED / NEEDS_ADAPTER；没有因collector实现就宣布工具可移植。

52. **pipeline/external coupling debt**：Trivy Harbor auth/API/DB/proxy；Cosign trust/key/registry+共享admission路由；Dojo minimum Product身份+原native report文件顺序耦合仍在；本轮不做最终解耦。

53. **future plugin-contract readiness**：部分：id/事实收集/规范化边界已清晰，execute仍含Kubernetes/工作区/外部API耦合；不能直接宣称全部Plugin{requiredCapabilities,execute,collect,normalize}就绪。未实现Plugin Registry。

54. **display-contract readiness**：PARTIAL：sourceId/scope/decision/证据与digest可提供；旧来源部分startedAt/completedAt和规范化finding/risk摘要仍缺。Dojo缺完整结果。不能把当前metadata提升为Router/Unified Summary完成。

55. **runtime/collector tests**：154/154 PASS（含完整性11项，勿重复相加）。collector/owner/projection原hash不变。

56. **side-effect guard tests**：Trivy20、Cosign17、ZAP22及既有通用guard均PASS；真实Cosign admission路由失败另记，单元guard PASS不能覆盖在线边界失败。

57. **candidate tests**：40/40 PASS；临时checkout执行，旧证据未修改。

58. **Policy core**：5/5 PASS，baseline-v1/default standard等既有规则未改。

59. **contract checks**：10/10 PASS。

60. **Regression 147/147**：#23和#30均真实147/147；#30 SUCCESS，regression log hash b59e0dbf39ab505904ad1f99a2d503547ebeb7f0101ce4e51616f92cd4382e28。

61. **Trivy tests**：129/129冻结父阶段差分回归PASS；另20项boundary单元PASS。真实执行为DB Error，不以129单元宣称漏洞扫描成功。

62. **Cosign tests**：268/268冻结父阶段回归PASS；另17项guard单元PASS。真实admission负例失败仍保留。

63. **Dojo tests**：69/69冻结父阶段回归PASS；线上只验证隔离身份/Engagement生命周期，没有import/dedupe runtime完成声明。

64. **permission tests**：Trivy实际7项can-i匹配、错误robot密码401；robot grant读取精确一致。Dojo实际仅Product5可见、Product1/2=404、无效token403。Cosign真实dry-run只进入测试namespace，但namespace不被webhook选择，因此admission边界FAILED/未验收；未降低Gate。

65. **cleanup tests**：真实清理已验证：临时label资源0、两robot已撤销、短时token/private dir已移除；三fixture+三signature引用GET404；Dojo Test0/Finding0后定向删除；无force delete/finalizer绕过。

66. **completeness tests**：11/11 PASS；missing executionScope/duplicate evaluation由runtime artifact前置校验拒绝，未修改冻结Policy或V1 Summary。

67. **artifact integrity tests**：candidate与negative tests通过；实际COMPLETE artifact integrity=NOT_TESTED，因为没有生成artifact。原不可变证据3118引用复核一致。

68. **source/hash preservation**：原6315文件基线：仅5个允许的runtime/专用Jenkins文件变化；455个冻结source引用/229文件和3118历史索引引用全部保持（沿用2个已批准历史snapshot解析）。Policy baseline、canonical、collector、owner、projection、V1、Promotion/Regression语义不变；2202 authoritative compatibility total不变。

69. **V1 active state**：V1 active；Summary SHA256 ec9ee51a06d4b9f61c6c0eaf50b374d1e25e6d3ca687908b7596d3a2c794f5d8不变；live工作区文件hash一致。

70. **production Jenkins state**：petclinic-ci仍#270 SUCCESS；生产job定义未修改、未触发production run。PetClinic generation175/revision164，三个node各一个Pod，3/3Ready、3Ready Endpoint、HTTP200，Argo Synced/Healthy且原revision不变。

71. **validation Jenkins builds**：#21 SUCCESS最小scan身份；#22 FAILURE专用CPS语法（已修）；#23 FAILURE真实Trivy DB；#24 FAILURE测试SOPS stdin参数（已修）；#25 SUCCESS测试信任根；#26 FAILURE真实admission unsigned mismatch；#27 FAILURE清理inventory上限保护；#28 FAILURE级联删除后404；#29 SUCCESS隔离Dojo授权+清理；#30 SUCCESS真实Regression+最终只读清理核对。全部为专用non-release job；逐build定义与bundle已取证。

72. **release count**：0。

73. **rollout count**：0。

74. **REAL_RUNTIME_FACT_CAPTURE**：INCOMPLETE

75. **REAL_POLICY_OWNER**：INCOMPLETE

76. **IMMUTABLE_ARTIFACT_RUNTIME**：INCOMPLETE

77. **SUMMARY_V2_MIGRATION**：INCOMPLETE

78. **exact blocker if incomplete**：①共享Harbor Trivy DB下载走失效proxy，导致当前native report缺失；②独立test namespace未进共享Kyverno webhook allowlist，现有allowlisted namespace又有原始镜像仓库限制，不能修改/绕过生产Gate；③Dojo完整真实report/import/dedupe链依赖①。最小身份与测试签名边界已推进，但不能宣称整体永久收口。

79. **exact next permitted action if all three runtime verdicts VERIFIED**：前置条件不成立，post-VERIFIED阶段不适用。STOP；不启用Summary V2、不迁移Promotion/Regression。下一轮应先提交共享scanner proxy/DB的最小恢复方案，以及独立admission入口的隔离方案；实施共享配置变更须另行限定范围。报告链恢复后仅重建专属身份执行真实父阶段；三个边界通过后，才允许同run16/16。

## 逐来源 metadata 与 portability（非同run清单）

| sourceId | scope | 原build/本轮证据 | evaluationCount | decision | portability |
|---|---|---|---:|---|---|
| sbom | CONTROLLED_NON_RELEASE | 12 | 1 | PASS | PIPELINE_COUPLED |
| regression | CONTROLLED_NON_RELEASE | 12 | 1 | PASS | PIPELINE_COUPLED |
| falco-baseline | LIVE_READ_ONLY | 12 | 1 | PASS | NEEDS_ADAPTER |
| kyverno | CONTROLLED_NON_RELEASE | 12 | 1 | PASS | NEEDS_ADAPTER |
| kubescape | LIVE_READ_ONLY | 12 | 1 | PASS | NEEDS_ADAPTER |
| gitleaks | CONTROLLED_NON_RELEASE | 14 | 1 | PASS | NEEDS_ADAPTER |
| sops | CONTROLLED_ISOLATED_RUNTIME | 12 | 1 | PASS | NEEDS_ADAPTER |
| trivy | CONTROLLED_NON_RELEASE | 23 | 1 | FAIL | EXTERNAL_SYSTEM_COUPLED |
| cosign | CONTROLLED_NON_RELEASE | 26 | 1 | FAIL | EXTERNAL_SYSTEM_COUPLED |
| sonarqube | CONTROLLED_NON_RELEASE | 12 | 1 | PASS | EXTERNAL_SYSTEM_COUPLED |
| zap | CONTROLLED_NON_RELEASE | 20 | 1 | PASS | NEEDS_ADAPTER |
| falco-final | LIVE_READ_ONLY | 12 | 1 | PASS | NEEDS_ADAPTER |
| defectdojo | CONTROLLED_VALIDATION_IDENTITY_ONLY | 身份#29 | 0 | None | EXTERNAL_SYSTEM_COUPLED |
| provenance | CONTROLLED_NON_RELEASE | 12 | 1 | None | PIPELINE_COUPLED |
| build-provenance | CONTROLLED_NON_RELEASE | 12 | 1 | None | PIPELINE_COUPLED |
| semgrep-command-audit | CONTROLLED_NON_RELEASE | 15 | 1 | PASS | NEEDS_ADAPTER |

所有fact/result digest见 [runtime-source-matrix.json](runtime-source-matrix.json)。其中Dojo缺失字段保持null；既有13来源保留原run绑定。

| source | resultDigest（原绑定，不是aggregate） |
|---|---|
| sbom | a781c2c4ff51492141a80c468f662494dff920014a381ed443e9895cd8a6c2f7 |
| regression | 963d0093b54a0072cc44891c2e5ab02795914e4415297765d1f9d5baebf85603 |
| falco-baseline | da24cacdf9de77d7618ac0534376979d634127f48f182a5bad7611605f71a284 |
| kyverno | f04b7dae6fa5e12af2a20cb8a6ec3205cfb5d0ec200d3847319e9e296e08f973 |
| kubescape | 52ae56380c878af0660427f42dc2eb915f1041199f825395957b143497a8fa7f |
| gitleaks | 42b29a8698d4fe2fb0df037a2e58cd934a5721fd0b9a086367496abc6bc60141 |
| sops | 419d4e908db6a574c99b7438f4be348e412d61a2ad112a6fd3488c015cfb0014 |
| trivy | 9c3318b7cfef6af72907402273bb278bb71644fe3d501a39106bc7b894e7f4d7 |
| cosign | 92bcc507fa6ad1d6b24ca19598895da1f9ff49fb5538c81e34f1a85d274ba498 |
| sonarqube | 7f7ddc4ddab271e477dfae64f18345beebb13883ae9ad999c4a77f76d1ac36bd |
| zap | 57c2721f6d44be76647a5daa4a2f1291ad26e50db128cc468ad4a73284b58a78 |
| falco-final | e6b59ae57e80f921eed5825226c31451e73f46b28aa2fda278e04997d85b3113 |
| defectdojo | None |
| provenance | 93f1716ce43c9f95ecd4c143c06ef715b41653835cffd3125a3d6450bd31a838 |
| build-provenance | d21a74946f4695e62432dc2008106e809a4366f332e66d968f577a7b0f963254 |
| semgrep-command-audit | 297880fecc8756a7087ff0b173123a4ef56674efa5886398f577faf488dd8448 |

## 保留的主要证据

- `trivy-source-receipt.json` / `native/23/trivy-audit.json` / `trivy-server-scan-failure.json`
- `cosign-source-receipt.json` / `native/26/signing-admission.json` / `live-protected-final.json`
- `defectdojo-source-receipt.json` / `dojo-isolation-cleanup.json`
- `jenkins-build-30.json` / `native/30/final-three-postcheck.json`
- `test-results.json` / `source-preservation.json` / `protected-verification.json`
- `validation-build-identities.json` / 各build的runtime-source-bundle与Jenkinsfile

```text
REAL_RUNTIME_FACT_CAPTURE = INCOMPLETE
REAL_POLICY_OWNER = INCOMPLETE
IMMUTABLE_ARTIFACT_RUNTIME = INCOMPLETE
SUMMARY_V2_MIGRATION = INCOMPLETE
```

STOP。
