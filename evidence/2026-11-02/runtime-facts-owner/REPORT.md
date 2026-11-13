# Runtime facts / authoritative owner 本轮报告

结论：真实专用 Jenkins 已证明 5/16 来源的采集、一次求值及 Gate receipt 复用；整体仍 INCOMPLETE，完整 artifact 未生成。

验证范围严格区分：REAL_DEDICATED_NONRELEASE_JENKINS_EXECUTION、CONTROLLED_ACCEPTED_GATE_REPLAY、HISTORICAL_REDACTED_SHAPE、SYNTHETIC_UNIT_ONLY。

1. **selected real pipeline insertion point** — vars/securityManager.groovy:58 命令返回后、:60 results.add 前；两个 provenance helper 的返回值也须在 Security Gate 前收口。生产文件未接线。

2. **authoritative owner file/function/stage** — 专用 Jenkinsfile.runtime-facts 的 Original command → Runtime facts → Authoritative owner → Gate reuse；run-nonrelease.mjs:stage → captureStage → createRuntimeOwner.accept → reuseForGate。这是实际 Jenkins 执行的非发布编排，目前仅覆盖 5 项。

3. **runtime facts envelope** — schema/kind/sourceId/buildBinding/execution/presence/rawFactDigest/reports/evidence/facts/envelopeDigest；facts.raw 保留来源专用 payload；匿名 fd3 仅传内存原始事实，磁盘保留哈希/安全命令观察/receipt。collector 不调用 Policy。

4. **canonical runtime source count** — 16。

5. **compatibility→runtime source mapping** — 18 compatibility labels；semgrep 是 semgrep-command-audit 的 alias；security-approval-promotion 是 post-approval，不能加入 preapproval。完整映射见 runtime-source-coverage.json。

6. **sources successfully captured** — Regression、Falco baseline、Kyverno/RBAC、Kubescape、Falco final；#4 均为原命令 exit 0 → standard PASS。Kubescape 原 AUDIT 事实未被改写为无漏洞声明。

7. **missing sources** — sbom, gitleaks, sops, trivy, cosign, sonarqube, zap, defectdojo, provenance, build-provenance, semgrep-command-audit。全部 NOT_OBSERVED，未伪造 SKIPPED/NOT_CONFIGURED/PASS。

8. **per-source evaluation counts** — 5 个已接入来源各 1；11 个未观察来源为 null，不把 null 当作 0 或 1。

9. **duplicate evaluation result** — 本轮 owner/collector 测试覆盖重复、并发重复、第二 owner/run claim、重复 Gate handoff：均在第二次求值前拒绝，计数仍为 1。未在 Jenkins 注入重复生产故障。

10. **per-source result identities** — regression=96931a5ee686ea6cdbf110fe138f37270ea29452b8d1b5b04ee0ae0a23476c8a；falco-baseline=e1fe4486fbff8a9f110c860eb3050d9cb1821df7856107e882441ce020b0303d；kyverno=b0dd280ffb4f2090f2cb4b1af6d7ad147704327e8148cb57db6cdf440a705225；kubescape=8ef2d157567ae096c574f6e83392334de5af0585af2b982f319f8239fe803542；falco-final=459b970ecb48ae9b0b70b4e77f5006bc772446b626f34327bd830d17927cb1ed

11. **Gate reuse proof** — #4 五项 result.json、capture.json、gate.json、coverage.gate 的 resultDigest 完全相同；复用不调用 Engine。

12. **aggregate Gate compatibility result** — INCOMPLETE：只证明五项旧命令/Policy/per-source Gate 一致，未声称 16-source aggregate 已验证。#2 的 Kyverno 采集器错读 tools manifest 被 drift guard 拦截；修正为原 tools-lock 后 #3/#4 一致，未改 Gate/adapter。

13. **immutable artifact path** — NOT_GENERATED；没有把 partial receipt bundle 命名为 COMPLETE artifact。

14. **artifact producer/version** — 目标为原 r2 contract V2 producer；candidate-integrity-r2.json 未改。本轮真实 artifact producer evidence 尚未生成。

15. **artifact completeness** — INCOMPLETE：5/16；#4 在真实路径拒绝缺失 11 项。

16. **artifact integrity** — 真实完整 artifact NOT_TESTED；候选 integrity/immutable/mixed-version 行为在隔离 checkout 的 40 项测试中通过，不能替代 runtime artifact。

17. **candidate/build binding** — {"candidate": "core.harbor.domain/petclinic/petclinic@sha256:489cb821573ff1f98edd846d5949d74bf3391b24e2f1fe5bcfb71c6be0793137", "build": 4, "project": "petclinic", "source": "741ea2866ea142b24c7838e1ef25c8327c79d279", "runId": "security-runtime-facts-20261102#4", "job": "security-runtime-facts-20261102", "targetScope": "runtime"}；source commit 不能单独证明含 untracked 实现的工作树，因此同时绑定 504 文件精确 bundle manifest。

18. **missing-source rejection** — 真实 #4 已拒绝；artifactGenerated=false，exit 3；没有伪造补项。

19. **duplicate-source rejection** — collector/owner 19 项及候选 40 项中验证通过；真实全量 artifact 尚无。

20. **stale-result rejection** — collector/候选测试通过；旧 build/candidate 绑定不能用于本轮。

21. **malformed-result rejection** — collector/候选测试通过，篡改 raw facts/envelope/result integrity 均拒绝。

22. **POLICY_ERROR preservation** — 单元及候选测试保留显式 POLICY_ERROR；不能作为 legacy success 复用；本轮在线五项未出现 POLICY_ERROR。

23. **SKIPPED preservation** — 显式观察到 skipped 的受控测试保留 null decision；本轮未把未执行来源替换为 skipped。

24. **NOT_CONFIGURED preservation** — 受控测试保留 null decision；native success 报告缺完整观察时不成为 PASS；未声称未执行来源真实已 not_configured。

25. **Falco runtime facts result** — #4 baseline/final 均真实 PASS、once、same receipt；每次查询 windowEndMs 从当次实际 since-time 下界 + 15000ms 还原，同时记录真实开始/结束时间。baseline 稳定性检查保留首次原 Date.now，不被后续查询覆盖。无固定 +16s 推导样本。

26. **Falco 2-second boundary result** — 4 个 accepted whole-Gate 回放 MATCH/0 DRIFT，其中 baseline/final 原 2 秒边界均旧 Gate FAIL = Policy FAIL；分类 CONTROLLED_ACCEPTED_GATE_REPLAY_NOT_LIVE_RUNTIME。不是线上故障。

27. **SOPS runtime facts result** — 正向/解密失败/工具缺失三类 accepted archive 的脱敏 shape 均可由 envelope 无变化承载。分类 HISTORICAL_CONTROLLED_EXECUTION_REDACTED_SHAPE_ONLY；未拿脱敏 digest 当解密原文重新求值；本轮新 SOPS Gate 执行 0。生产 Secret/key 访问 0；执行入口强制验证真实 isolated MIN_RBAC guard，不能靠环境 flag 绕过。

28. **Policy core 5/5** — 本轮 5/5 PASS。

29. **contract checks 10/10** — 本轮只读 10/10 VERIFIED，未重定义 baseline。

30. **Regression 147/147** — 真实 Jenkins #4 原 Regression 命令 exit 0，147 tests/147 pass/0 fail/skip/todo/cancel；未改 Regression Gate，不用 TAP 计数取代原退出码。

31. **source hash validation** — 5580 个旧文件零修改；455 source refs / 229 distinct 全匹配；3118 prior index refs 重核通过；r2 精确引用和最终上传 504 文件均匹配。关键哈希见 source-preservation.json。

32. **V1 active path unchanged YES/NO** — YES。生产 petclinic-ci 仍 #270 SUCCESS，原 V1 Summary SHA ec9ee51a06d4b9f61c6c0eaf50b374d1e25e6d3ca687908b7596d3a2c794f5d8；生产 workspace 与前轮只读基线逐项一致。

33. **production files changed** — 既有生产文件 0；新增 infra/security/runtime-facts/*、独立 Jenkinsfile.runtime-facts、当轮 evidence/docs。独立 job/config/workspace 是新非发布验证面。临时沿用 heavy Lease，完成后释放；未扩大 RBAC。

34. **Jenkins validation build count** — 4 个专用非发布构建；#1 partial 3 项；#2 Kyverno collector drift 被拦截；#3/#4 五项一致但均因完整性不足 exit 3。生产 build 触发 0。

35. **release count** — 0。

36. **rollout count** — 0。

37. **REAL_RUNTIME_FACT_CAPTURE** — INCOMPLETE。

38. **REAL_POLICY_OWNER** — INCOMPLETE。

39. **IMMUTABLE_ARTIFACT_RUNTIME** — INCOMPLETE。

40. **exact blocker if any** — B1：11-source collector/真实执行未补齐；B2：唯一 owner 仅接入五项，尚无全部 helper 事实；artifact runtime 全量生产身份/外部检查/绑定旧字段输入也尚未接线。均为明确工程缺口，不是 SSH/Jenkins 权限故障。

41. **exact next permitted action if all VERIFIED** — 尚未全部 VERIFIED，所以不存在进入 Summary 的许可。本阶段剩余工作仍是上述 B1/B2 与完整 candidate artifact；Summary/Promotion/Regression migration 均不得推进。

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

已停在本阶段；未接 Summary V2。
