REAL_V2_PIPELINE_INTEGRATION =
INCOMPLETE

SUMMARY_V2_MIGRATION =
INCOMPLETE

本轮完成 r2 候选重基线、当前 V1 冻结、可信只读生产入口/原生报告契约检查及候选回归；未完成用户要求的真实 pipeline owner/采集器/消费者接线。当前基础设施可达，不能把未完成实施说成权限阻塞，也不能用受控检查冒充实际接线 VERIFIED。

1. **current V1 identity**：SummaryProducerV1-038320f04c67fb1fe5ff711c11d445c2de88cc50b2230eb4c971bf46142f5b34；fresh local snapshot 542 files / tree d6058b707e626e64335335fa1479809925a2d6e65307d9a7edeb3c62e5ec9d59。真实 job petclinic-ci #270 SUCCESS，platform-security@9a78cc89f22fa98fb1ffcc43e2ae279299471793；13 个实际 V1 源文件另存，local/live Manager 身份分开。

2. **existing V2 candidate classification**：633 条旧候选引用中 629 UNCHANGED_COMPATIBLE、4 NEEDS_REBASE（2 个 Falco 文件在 V1/V2 两分支各引用一次）；没有未解释 STALE/INVALID。代码候选不是已经通过实际接线。

3. **stale V2 references found**：falco-parent.mjs 与 falco-parent.test.mjs 的旧哈希；旧候选仍完整保留，不激活。原 2128 不能继续作为当前 aggregate；r2 显式绑定 2202/0 与 Falco 89/91。

4. **V2 rebase changes**：仅新增 candidate-integrity-r2.json，SHA b8fafeab7b7a2e2b78491ba24f25229349046c804388802e9b0b078bf7eaf052；候选 V1 rollback 分支接受当前冻结文件，V2 分支 110 个精确文件身份。生产 V1 integrity contract 未改，producer 实现字节未改。

5. **current authoritative owner**：真实 Policy owner 尚未实现/接线。实际 vars/securityManager.groovy call/plan loop 和两个 helper 仍是 V1 工具编排；owner.mjs 只是候选 helper。已通过受信 SSH 只读证实 workspace 缺 Engine 和 owner。此项不是权限或主机故障。

6. **canonical runtime source count**：16；见 runtime-source-coverage.json。18 compatibility labels 中 semgrep alias 去重、Promotion 为 post scope，Sonar 仍在 runtime expected 集合。

7. **per-source evaluation counts**：真实 16 项均 null / NOT_OBSERVED，没有新 pipeline。受控 fixture 每项 1 单列，不能冒充真实 runtime once。

8. **duplicate evaluation result**：候选单 owner 并发/重复调用在二次求值前拒绝，既有测试通过；跨进程/真实 pipeline duplicate proof NOT_TESTED。

9. **real runtime fact capture result**：未完成。只读检查 #270 的 SOPS、Kyverno、Kubescape、Cosign、Dojo、Falco 六类真实归档成功报告，仅导出字段名/哈希，发现缺完整观察字段；它们是 HISTORICAL_ARCHIVE，不是本轮新 runtime facts。未补造事实。

10. **immutable artifact identity**：真实 artifact NOT_GENERATED / identity=null；4 个 controlled Falco artifact 的 digest/path 在 falco-v2-rebase-preflight.json，明确不是实际 pipeline 产物。

11. **artifact completeness**：真实 NOT_TESTED。候选固定 16-source 完整/缺失/重复/stale 拒绝测试通过；没有拿缺失事实生成真实 COMPLETE。

12. **artifact integrity**：真实 NOT_TESTED。controlled artifacts 0400/create-only、SHA 和 result identity 验证通过。当前 r2 精确文件哈希均匹配，没有 wildcard 或关闭校验。

13. **candidate binding**：真实 NOT_TESTED；受控 build/candidate/stale 绑定和拒绝检查通过。没有把 #270 的历史 binding 套成新运行。

14. **Summary V2 real generation**：未执行。只在 evidence 中生成受控 Summary，并运行真实候选序列化函数；未写 actual security-summary.json。

15. **V1/V2 semantic differential**：真实 pipeline NOT_EXECUTED；既有 6 个状态的实际 V1 序列化 vs 候选 V2 旧字段 deepEqual 通过，范围 CONTROLLED_SERIALIZATION_AND_ENGINE_UNIT。

16. **PASS result**：受控 6-state differential 中 PASS 通过；真实 pipeline NOT_TESTED。

17. **FAIL result**：受控 FAIL 保留；Falco 原 2 秒样本全链 FAIL 一致；真实 pipeline NOT_TESTED。

18. **WARN result**：受控 WARN 保留；真实 pipeline NOT_TESTED。

19. **SKIPPED result**：受控 SKIPPED/null decision 保留，不改为 PASS；真实 pipeline NOT_TESTED。

20. **NOT_CONFIGURED result**：受控 NOT_CONFIGURED/null 保留；真实 pipeline NOT_TESTED。未把“采集器没实现”虚报成合法 runtime NOT_CONFIGURED。

21. **POLICY_ERROR result**：受控错误策略保留明确 error，无静默降级；真实 pipeline NOT_TESTED。

22. **Falco current normal-path result**：baseline/final 各 1 个 frozen 受控正常通过样本：old Gate=Policy=artifact=Summary=PASS；原 Gate 完整 body 再执行，未调用真实 sensor。

23. **Falco 2-second IO boundary V2 result**：baseline/final 两个原反例，均 FAIL=FAIL=FAIL=FAIL；同一个 resultDigest 被 Gate/artifact/Summary 复用。4 个 Falco preflight 合计 MATCH 4/DRIFT 0；不是 live runtime。V2 代码未增加固定 +16s。

24. **Promotion V2 migration**：实际 consumer 未迁移。原 gateEvidence/sign-approve/promote 不变；候选 preApprovalPolicyInput 检查通过不能当作已安装的真实 guard。

25. **Promotion tamper/unknown rejection**：候选 exact-version verifier 的 unknown/tamper/mixed-version 测试通过；真实 dispatch NOT_TESTED。旧 validateGate 忽略附加 metadata 的风险仍由现有测试明确证明，因此不可激活。

26. **anti-self-approval**：ANTI_SELF_APPROVAL(candidate)=PASS；原测试拒绝 future PromotionResult/approval 字段。真实 pipeline 仍 NOT_TESTED，不输出无范围的实际 anti-self-approval PASS。没有执行批准或 Promotion。

27. **Regression V2 migration**：实际 integrity dispatch 未迁移；保留原 top-level Node exit-code Gate，未用 TAP 计数替换 Gate。

28. **Regression 147/147**：本轮原命令 147/147 PASS；独立冻结 V1 snapshot 中再次 147/147 PASS；两次真实本地退出均为 0，分别送 Engine 后 PASS/PASS，2 MATCH/0 DRIFT。没有把本地执行当 Jenkins 新构建。

29. **Jenkins archive regression**：真实 Jenkins 归档读取正常；候选 .devsecops/** glob 静态覆盖检查通过；新 V2 artifact 的真实归档 NOT_TESTED，无新构建。

30. **Loki regression**：受控 JSON 旧字段兼容通过；本轮无 production publish/live query。真实 migrated consumer transport NOT_TESTED。

31. **Grafana regression**：14 个既有 JSON selector 的受控字段兼容通过；未修改查询或执行在线 Grafana 验证。

32. **other consumer regression**：原 Promotion 两项 baseline tests 包含在 147 项内通过；sign-approve/promote/generic Summary 的实际 V2 消费尚未迁移。

33. **Policy core 5/5**：本轮 5/5 PASS。

34. **contract checks 10/10**：本轮既有只读契约 checks 10/10 VERIFIED。

35. **source hash validation**：455 冻结 source refs / 229 distinct 全匹配；3118 条既有 evidence refs 重核无未解决失败；4973 个保护旧文件零修改。旧 evidence 未覆盖。

36. **current Falco adapter hash validation**：2c31980a19c9443215fd196e6aab3e89e312c6bca535857a869b6fe2a610519b，与最新权威矩阵/r2 一致。

37. **Falco Gate hash validation**：65ab133a4248b9900265a47d943f9e6430b9ec9581ddd624b1d9257322b0d921，保持不变。

38. **Policy baseline validation**：02c3f5499dc39a53009a69e8f267dbbd247b4d89d4de14fafaa4dd5cff974f1a，Engine 与 baseline 都未改。

39. **mixed-version matrix**：候选 A/B/C/D/E/F/H、malformed artifact/result 拒绝测试通过；真实消费者未安装，不能标记 production mixed-version matrix VERIFIED。V1 只允许显式 rollback，不自动 fallback。

40. **rollback result**：受控 exact snapshot/hash/显式 V2→V1 选择 PASS，且 snapshot Regression 147/147；真实 pipeline rollback NOT_TESTED，因为未切换。命令 node evidence/2026-11-02/real-v2-current-baseline-integration/check-v1-rollback.mjs 可只读重核。

41. **V1 restored after rollback**：生产 NO_SWITCH_PERFORMED，始终 V1，不声称执行过生产恢复。local Manager 与 live Manager SHA 不同，严禁拿 local 快照批量覆盖 live。

42. **release count**：0；真实 approval/signing/promotion 同为 0。

43. **rollout count**：0；Jenkins new build 0。

44. **REAL_V2_PIPELINE_INTEGRATION**：INCOMPLETE。

45. **SUMMARY_V2_MIGRATION**：INCOMPLETE。

46. **exact blocker if not VERIFIED**：B1 同次执行完整事实采集未实现；B2 真实 non-test Policy owner、跨阶段唯一求值与 Gate receipt 交接未接线；B3 实际 artifact/Summary 和 Promotion/Regression version dispatch 未迁移、真实全链未运行。以上是工程实现缺口，不是当前基础设施故障；r2 与 fixture PASS 不能关闭它们。

47. **exact next permitted action if VERIFIED**：不适用，未 VERIFIED。剩余工作仍是本次授权的真实非发布接线：先实现 B1/B2，再运行 B3 的 complete artifact、consumer/mixed-version/anti-self-approval/rollback 验证；不进入统一插件契约、开关、Dojo 解耦或 Router。

真实 canonical source 列表（16 项，当前新 pipeline counts 全为 NOT_OBSERVED）：sbom, regression, falco-baseline, kyverno, kubescape, gitleaks, sops, trivy, cosign, sonarqube, zap, falco-final, defectdojo, provenance, build-provenance, semgrep-command-audit。

初次受限沙箱 SSH 返回 Operation not permitted，随后授权的严格 host-key SSH 成功；未修改 known_hosts、未关闭校验。初次 Falco V2 preflight 在候选 codec 拒绝 VM 跨 realm 对象，修复测试 JSON 边界后通过，原失败日志保留；没有调整任何 scanner/Gate/Policy 判定。

所有候选 40 tests、Falco 4 项和本地 Regression 2 次执行都在其明确范围内保留；不得从这些数字推导实际 Jenkins 全链通过。生产 V1、旧 candidate-integrity.json 和全部历史证据均保留。新 candidate-integrity-r2.json 仍 inactive。
