# Remaining runtime facts：本轮结果

1. **canonical runtime source count**

   16，registry unchanged。

2. **starting wired count**

   8。

3. **exact remaining 8 inventory**

   remaining-eight-inventory.json；由实际 registry/plan/#9 coverage 派生。

4. **risk classification**

   SOPS CONTROLLED_ISOLATED；Sonar LINEAGE_BLOCKED → fresh analysis attempt；其余六项 OTHER_BLOCKED。

5. **new sources wired**

   sops, sonarqube

6. **ending wired count**

   10/16。

7. **still blocked sources**

   gitleaks, trivy, cosign, zap, defectdojo, semgrep-command-audit

8. **per-source execution scope**

   source-fact-contracts.json；SOPS CONTROLLED_ISOLATED_RUNTIME，非 live production。

9. **per-source real fact producer**

   source-fact-contracts.json 中 exact production command；原 Gate/adapter 未改。

10. **per-source write boundary**

   inventory 的 factFormationTrace/earliestAllPolicyFactsExist/beforeAnyExternalMutation。六个父阶段在写入后才形成完整事实。

11. **per-source collector contract**

   source-fact-contracts.json；raw in memory + digest/report identity/actual process observations。

12. **per-source evaluation count**

   已捕获来源均为 1；未观察来源为 null。

13. **per-source resultId**

   source-fact-contracts.json resultId，完整 64 位 digest；无重复。

14. **Gate resultId reuse**

   每项 resultId == gateResultId；最终脚本逐项断言。

15. **local/read-only source results**

   原八项重验：六 PASS、两 actual default SKIPPED；无 enabled provenance 声明。

16. **pre-write source results**

   六项 PRE_WRITE_FACT_BOUNDARY_NOT_AVAILABLE；未强行执行写操作。

17. **Trivy result**

   未执行 mandatory Harbor POST scan；不能用现有 GET 替代父阶段事实。

18. **ZAP result**

   未创建 scanner Pod 或扫描生产目标；单独 loopback 不能替代完整父阶段。

19. **Cosign result**

   未解密生产签名包/签名/写 registry；verify-only 无法覆盖冻结 admission parent。

20. **DefectDojo result**

   未 import/reimport/PATCH；现有 canned in-memory fixture 属单元兼容性，非当前运行事实。

21. **Gitleaks result**

   原 source-gate 创建 Pod 后才产生隔离、native/classifier、cleanup 事实；本轮停止于写前。

22. **Semgrep/Command Analysis result**

   原两阶段创建 Pod 后才形成完整事实；shared canonical source 保持一项，未双求值。

23. **SOPS runtime result**

   真实隔离 positive → same owner；wrong-key/tool-missing → FAIL/FAIL，只是支持观察；positive preflight 不求值。见 sops/ 与 delivery receipt。

24. **SOPS production Secret/key access count**

   0/0；仅复用公开工具二进制。

25. **Sonar candidate lineage result**

   见 sonar-current-lineage.json（如捕获）及 coverage；绑定当前 build/source → fresh report-task → task → analysis → server conditions。runtime image 仅 audit context，不伪称 image-content attestation。

26. **Sonar compatibility-debt status**

   DEFERRED_REAL_NEGATIVE_EVIDENCE；无历史真实负例升级。

27. **pre-approval cycle check**

   无 PromotionResult 依赖；Semgrep alias 不增加 canonical 数。

28. **wired/16 completeness**

   10/16，未补假 SKIPPED。

29. **duplicate source check**

   16 个 canonical ID distinct；所有实际 result digests distinct。

30. **artifact completeness**

   INCOMPLETE；实际完整性拒绝保留。

31. **artifact identity/hash**

   未创建 COMPLETE artifact；各 source resultDigest 与构建输入 bundle 均可追溯。

32. **aggregate Gate result**

   完整 aggregate 未产生；不得由部分来源推断全量 PASS。

33. **Falco normal regression**

   baseline/final 两个 ACCEPTED_GATE_REPLAY 正常样本 PASS/PASS；#12 两阶段真实 PASS。

34. **Falco 2-second regression**

   baseline/final 两个 2s 样本 old FAIL == Policy FAIL；Gate 同 digest；未恢复固定 +16s。

35. **collector/owner tests**

   57/57 PASS。

36. **candidate tests**

   40/40 PASS，disposable checkout。

37. **Policy core**

   5/5 PASS。

38. **contract checks**

   10/10 PASS。

39. **Regression 147/147**

   真实 #12 147/147 PASS。

40. **source-specific tests**

   Sonar 8、隔离 channel 10 包含在 57 中；SOPS 3 条受控路径+1 no-Policy preflight；27 auth checks。不增加权威 2202 compatibility count。

41. **production V1 state**

   petclinic-ci #270 SUCCESS，V1 active；Summary SHA ec9ee51a06d4b9f61c6c0eaf50b374d1e25e6d3ca687908b7596d3a2c794f5d8

42. **source/hash preservation**

   source-preservation.json：冻结 source/index/r2/前轮 seal/production workspace 均匹配。

43. **nodes/Lease cleanup**

   3 nodes Ready；production heavy Lease released；isolated owned 23 resources + private keys/token/root 清理，kind 保留。

44. **Jenkins validation builds created**

   #10 baseline；#11 NoHttp prerequisite failure；#12 clean separate checkout + isolated channel。

45. **production Jenkins builds created**

   0。

46. **release count**

   0。

47. **rollout count**

   0。

48. **REAL_RUNTIME_FACT_CAPTURE**

   INCOMPLETE。

49. **REAL_POLICY_OWNER**

   INCOMPLETE。

50. **IMMUTABLE_ARTIFACT_RUNTIME**

   INCOMPLETE。

51. **SUMMARY_V2_MIGRATION**

   INCOMPLETE。

52. **exact blocker if still INCOMPLETE**

   PRE_WRITE_FACT_BOUNDARY_NOT_AVAILABLE for remaining external-write parents; complete current parent facts do not exist before first write. No write executed to fabricate completion.

53. **exact next permitted action if all runtime verdicts VERIFIED**

   条件尚未成立。本轮 STOP。后续先审查六项完整父阶段的已授权执行边界/专用隔离方案；不得自动执行外部写入，不连接 Summary V2。

```text
REAL_RUNTIME_FACT_CAPTURE = INCOMPLETE
REAL_POLICY_OWNER = INCOMPLETE
IMMUTABLE_ARTIFACT_RUNTIME = INCOMPLETE
SUMMARY_V2_MIGRATION = INCOMPLETE
```
