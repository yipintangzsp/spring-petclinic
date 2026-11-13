本轮 REAL_V2_PIPELINE_INTEGRATION = FAILED；SUMMARY_V2_MIGRATION = FAILED。

失败指兼容性接线的验收预检失败，不是 Jenkins #270 失败，不是生产 V1 被改坏，也不是已经运行了 V2 后再回滚。真实 Jenkins 接线、批准、签名、Promotion 和 rollout 均未执行。

当前冻结 Falco adapter 已确认存在旧 Gate FAIL → standard PASS 的反例。必须先纠正“已冻结 adapter 可以直接作为真实运行时权威”的假设，不能继续把它接到 aggregate Gate。用户要求的 no semantic drift 和禁止 FAIL→PASS 是本轮停止依据。没有自行修改 adapter、baseline 或生产 Gate 来修复这个新发现。

实际生产代码 infra/security/runtime/health.mjs 的 liveSample 在读取日志和 workload 前记录 Date.now；完成第一次采样后才 setTimeout(16000)，然后第二次 liveSample 再读取 Date.now。所以两次结束时间差是 16 秒加上第一次 IO 和调度耗时。infra/security/policy/falco-parent.mjs 的 sample 则固定 end=raw.now+i*16000。这个 raw 契约无法同时表达有耗时情况下的两个真实结束时间。

隔离预检执行完整原生产 Gate body，仅移除 import 声明并注入 inert IO/受控时钟，与原冻结测试采用的方式相同；使用实际 runtimeWindow、persistentRuntime 等实现。没有执行真实 kubectl、扫描器、HTTP、业务攻击或注入生产日志。四项样本全部是 CONTROLLED_REPLAY_NOT_LIVE_RUNTIME，不能当作线上事故或真实 V2 runtime facts。

| 模式 | 第一次采样 IO 耗时 | 原 Gate | standard | 结果 |
| --- | ---: | --- | --- | --- |
| baseline | 0ms | FAIL | FAIL | MATCH |
| check | 0ms | FAIL | FAIL | MATCH |
| baseline | 2000ms | FAIL | PASS | DRIFT |
| check | 2000ms | FAIL | PASS | DRIFT |

2 秒样本中，实际第二窗口为 00:00:03–00:00:18；adapter 使用 00:00:01–00:00:16。第二批受控事件发生在 00:00:17 和 00:00:17.5，原 Gate 正确纳入第二窗口并判持久行为失败，adapter 把它们排除，得到 PASS。原事实和源文件不变。即使额外保留真实 sample ends，当前 adapter 仍不消费它们；不得通过提前时间戳、丢弃事件或任意调整 raw.now 来伪造一致。

41 项验收逐项记录如下。

1. active V1 baseline identity：真实 job petclinic-ci，SCM 固定 9a78cc89f22fa98fb1ffcc43e2ae279299471793，LibrariesAction 也确认 platform-security@9a78cc89f22fa98fb1ffcc43e2ae279299471793。生产者 SHA256=038320f04c67fb1fe5ff711c11d445c2de88cc50b2230eb4c971bf46142f5b34。已保存 ACTIVE_V1_IDENTITY.json、13 份 active-v1-tree 源码，以及独立本地 V1_IDENTITY.json/540 文件快照。没有覆盖上一轮快照。
2. real authoritative owner：已追踪到真实 vars/securityManager.groovy 的 call/plan loop 和两个 provenance helper；该处可统一编排 14 个 plan source 加两个 optional source，但当前没有 Policy owner。外部 Snapshot/ReadOnlyVerification 仍属 Jenkinsfile。真实 workspace 不存在 Policy Engine 或 V2 owner。没有创建另一个平行 owner；预检失败后停止安装。
3. canonical runtime source count：固定 16，来自原 18-label inventory。semgrep 是 semgrep-command-audit 的 alias；security-approval-promotion 为 post scope。所有 source 在 runtime-source-coverage.json 显式列出，未删掉 Sonar。
4. runtime facts captured：没有新流水线执行，16 项均未捕获真实本轮 runtime facts。#270 模块和 Summary 只分类为已归档历史记录。Falco 受控反例不是本轮实际运行事实。
5. per-source counts：真实运行计数均为 null/NOT_OBSERVED；不能填 1，也不能把未启动写成实测 0。受控 Falco 各有两个独立测试输入，不是同一个 pipeline/source 重复求值。
6. duplicate-evaluation：本轮真实 pipeline NOT_TESTED。上一轮单实例 owner 测试保持，但不推广成跨进程或 Jenkins once。
7. Gate reuse：真实交接 NOT_TESTED；旧 Gate 保持现状，没有消费候选 result。
8. Summary reuse：真实交接 NOT_TESTED；生产继续使用 V1。
9. artifact identity/path：没有生成真实 COMPLETE artifact。上一轮候选 contract 的目标 .devsecops/policy/pre-approval-<sha256>.json 不等于实际生产输出。当前证据中的 clock inputs 不是 Policy runtime artifact。
10. completeness：真实 NOT_TESTED/NOT_GENERATED，不以缺失事实补齐 COMPLETE。
11. integrity：V1/local snapshot、实际 active snapshot 和既有 455 哈希引用均检查；真实 V2 artifact integrity NOT_TESTED。
12. candidate binding：真实 V2 NOT_TESTED。只读基线拿到 #270 的 source/build/固定 candidate，不能用它们伪造本轮 source receipts。
13. real Summary V2 generation：未生成。没有写 actual security-summary.json。
14. real V1/V2 differential：NOT_EXECUTED；本轮发现的是原 Gate body 与 adapter 在延迟 IO 样本上的真实代码逻辑差分，不冒充完整 pipeline Summary 差分。
15. PASS semantic comparison：未进行真实 pipeline PASS 比较。延迟样本中 standard PASS 恰恰是错误放行，不能计为成功。
16. FAIL semantic comparison：两个延迟受控样本原 Gate FAIL、standard PASS，确认不可接受。两个零延迟受控 FAIL 对照一致。
17. WARN semantic comparison：本轮 NOT_TESTED；上一轮候选 WARN 序列化记录未变。
18. SKIPPED semantic comparison：本轮 NOT_TESTED；没有把阻塞 source 改成 skipped。
19. NOT_CONFIGURED semantic comparison：本轮 NOT_TESTED；没有以缺失生产事实得到 PASS。
20. POLICY_ERROR semantic comparison：本轮真实 NOT_TESTED；没有修改错误配置逻辑或添加 fallback。
21. Promotion V2 migration：未实施；基于失败预检停止 B3。旧 evidence/contract/sign-approve/promote 精确字节均已归档，不执行其中的副作用。
22. Promotion unknown/tampered：本轮真实 NOT_TESTED；不能把上一轮 candidate verifier 测试冒充已安装的生产拒绝路径。
23. Promotion self-approval：本轮 runtime NOT_TESTED；没有生成 approval、签名或 PromotionResult，更没有用未来 PromotionResult 批准自己。上一轮候选 anti-self-approval 测试仍仅是候选范围。
24. Regression V2 migration：未实施；保留原 top-level Node test exit-code Gate，无 TAP/历史框架替换。
25. Regression unknown/tampered：本轮实际新 consumer NOT_TESTED；原本地 frozen locks 未变。
26. Jenkins archive：真实 job 只读查询成功；#270 SUCCESS、74 个归档，只有原 security-manager/security-summary 等，没有 Policy artifact。没有新构建归档回归。
27. Loki regression：本轮未执行或发布。停止条件出现后不继续 consumer 工作。
28. Grafana regression：本轮未执行或修改查询。上轮 14 个字段 selector 兼容结果保持其受控测试范围。
29. other consumers：本轮没有运行签名、批准、promote 或 generic Summary 消费者；生产行为不变。
30. Policy core：本轮停止后未重跑，上一轮 5/5 PASS 记录保留；不能据此忽略新 Falco 反例。
31. original Regression 147/147：这是上一轮允许 loopback 后的真实本地结果。本轮未重跑，未称为本轮执行结果。没有必要在发现必须停止的 adapter 差异后继续全套。
32. source preservation：本轮保护的 4265 个旧文件零变化；本地快照 540 个文件零漂移；实际 active snapshot 13 个文件一致；既有 authoritative 455 refs/229 distinct 全一致。所有旧证据保留，2128 个既有匹配样本未重跑或改写。
33. Policy baseline preservation：baseline-v1 和 Engine 未改。新反例说明先前样本不能覆盖带采样 IO 耗时的所有真实输入；未擅自扩大原 VERIFIED 范围。
34. rollback：真实 V2→V1 未演练，因为没有切换 V2。已冻结本地 540 文件和实际 active V1 13 文件，实际 job/library pin 也记录。不能把“没改生产”描述为已经通过在线 rollback。
35. V1 restored after rollback：NO；原因 NO_SWITCH_PERFORMED，V1 始终保持生效。不要从本地快照覆盖实际 Manager：实际 Manager SHA=6854436a43b347fc94e895eada0b2048be238668817a4af33a228396f1c57c32，本地 Manager SHA=ae297e7313cbf9bdde9e38acb32a3ee3310c571f2d70e289783c5c1c448811af，两个身份明确分开。
36. release count：0。
37. rollout count：0；新 Jenkins 触发、真实批准、签名和 Promotion 同样为 0。
38. REAL_V2_PIPELINE_INTEGRATION = FAILED。是兼容预检失败，真实 V2 未启动，生产 V1 未改。
39. SUMMARY_V2_MIGRATION = FAILED。上一轮候选实现保留；本轮新增反例阻止继续宣称 standard 完整兼容，不能沿用 40/40 unit PASS 标为 VERIFIED。
40. exact blocker：falco-parent 用固定 raw.now+i*16000 代替生产真实采样边界，两个受控延迟场景出现 FAIL→PASS。B1/B2/B3 均仍未关闭。要继续必须先在单独兼容性修复范围内让 adapter 消费实际观测的每个窗口边界，并补延迟/边界/双窗口差分；不能在本轮禁改 source 语义的条件下直接修。不能修改生产等待、时间戳、事件或 Gate 来迎合 adapter。
41. exact next permitted action if VERIFIED：不适用，未 VERIFIED。本轮 STOP。最小后续范围是先单独修正并重新冻结 Falco adapter 的时间观察契约和差分证据，再恢复真实 pipeline integration；不开始插件契约、开关、Dojo 解耦或 Result Router。

回滚入口与命令边界：当前无需任何写操作。核验本轮快照/未修改状态可在仓库执行 python3 evidence/2026-11-02/real-v2-pipeline-integration/finalize.py；它不修改生产或旧文件。未来若发生接线切换，应恢复实际 job SCM 与 platform-security 库到已记录的 9a78cc89f22fa98fb1ffcc43e2ae279299471793，并验证 active-v1-tree 所列原哈希；不得用本地 ae297… Manager 冒充线上 685443… 回滚目标。真实恢复步骤必须针对当时实际改动审查，本轮不输出或执行批量覆盖/重置命令。

可复核证据：evidence/2026-11-02/real-v2-pipeline-integration/ 下 live-jenkins-baseline.json、live-workspace-hashes.json、ACTIVE_V1_IDENTITY.json、falco-clock-preflight.json、四个 clock 输入、runtime-source-coverage.json、owner-trace.json、active-contract-state.json、preservation.json、test-disposition.json、verdict.json 和 artifact-sha256.json。
