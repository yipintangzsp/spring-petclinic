本轮结论：FALCO_TIME_CONTRACT = VERIFIED；FALCO_COMPATIBILITY = VERIFIED。

范围限于 frozen production Falco Gate 的完整受控逻辑兼容性。没有运行真实 Falco sensor、制造生产告警或启动 Jenkins。Summary V2 接线保持停止；SUMMARY_INTEGRATION_READINESS 仍为 SUSPENDED，等待独立的权威 readiness recheck，SUMMARY_V2_MIGRATION 仍为 INCOMPLETE。

生产时序是：进入 liveSample 时先 t1=Date.now()，读取 Falco logs、解析事件、查询 workload，完成后才请求 setTimeout(16000)，第二次进入 liveSample 时再读取 t2=Date.now()。在未调整的墙钟上，t2=t1+第一次 IO/解析耗时+16000ms+定时器调度耗时。第二次 query 的 IO 在 t2 之后发生，不改变已捕获的第二窗口结束边界。第一采样前的诊断 IO 也能令 t1 不同于早先的 raw.now。

旧 adapter 错误地使用 t2=raw.now+16000。修复只让每次 sample 消费显式事实 observations.samples[i].windowEndMs，并按原规则计算 start=end−15000。时间不缺省、不偏移、不猜测；没有更改任何事件、阈值或生产 wait。

| 差分范围 | 旧样本 | 新增时间样本 | MATCH | DRIFT | 判定分布（旧 Gate = standard） |
| --- | ---: | ---: | ---: | ---: | --- |
| baseline | 52 | 37 | 89 | 0 | PASS 26 / FAIL 63 |
| final/check | 54 | 37 | 91 | 0 | PASS 25 / FAIL 66 |
| 合计 | 106 | 74 | 180 | 0 | PASS 51 / FAIL 129 |

修复前的 74 项时间矩阵为 MATCH 54 / DRIFT 20，20 项均为 FAIL→PASS；修复后为 74/74 MATCH。原始两个 2 秒采样 IO 反例在移除新增显式时间记录后与此前输入完全相同，均从 FAIL/PASS 修复为 FAIL/FAIL，原生产 Gate 没有变化。所有 74 项的 runtimeAssessment/window 也与原 Gate 一致，不仅比较最终状态。

32 项验收报告如下。

1. production timing call graph：runtime/health.mjs→liveSample→Date.now→kubectl logs→事件解析→workloads/kubectl get pods→runtimeWindow；仅首窗 candidate.count>=2 时，setTimeout(16000)→第二次 liveSample→persistentRuntime。requireLease、sensor proof、DS/Pod/node 身份检查在采样前；health fetch 和写报告在采样后。
2. authoritative clock：每次 liveSample 入口的实际 Date.now 毫秒整数。每个 query end 都独立观测，不从 sleep 请求、上一次时间或 shell 日志时间反推。事件仍按原 Date.parse(event.time) 解析。
3. first observation：end 在 log/workload IO 前取得；start=end−15000；查询 --since-time=start ISO、--tail=1000。前置诊断 IO 后再次读取墙钟，因此也修复 sample0 与 raw.now 的错误绑定。
4. IO latency：首个 logs、解析、workload IO 和调度耗时自然进入 t2−t1；不移动已记录的首窗 end。第二次 IO 同样不移动已捕获的第二窗 end。raw.timing 中保留每次 startedAtMs/completedAtMs/ioDurationMs、命令时间、query bounds 和事件时间。
5. wait：原生产请求固定 16000ms，只有首窗达到既有重复候选条件才等待。setTimeout 不是严格 16 秒上界，迟唤醒不能忽略。未修改 wait 或覆盖实际时钟。
6. second window：使用第二次 liveSample 入口的实际 clock，区间 [end−15000,end)。下界包含，上界排除。Date.now/ISO 保留毫秒精度，事件 Date.parse 的子毫秒处理保持原实现；矩阵验证边界及纳秒形式。时钟调整不假设单调，继续由原 persistentRuntime 拒绝重叠窗口。
7. old defect：falco-parent 原 sample 使用 raw.now+i*16000。IO 或定时器迟唤醒大于 0 时可能把真实第二窗事件判为“窗口外”。旧 adapter SHA256=906addbb70afed7178f8bfa8c09cdd53f7d5a4de02526e21596056bdeb837803。
8. original drift reproduction：baseline/check 两个原始 2s 样本复现 FAIL/PASS；零耗时对照匹配。扩展的修复前 74 项时间矩阵发现 20 个相同方向 drift。它们均为 CONTROLLED replay，不是生产事故或自然历史负例。
9. minimal fix：adapter 消费 samples[i].windowEndMs，只派生生产已有的 15000ms start。成功采样却缺少或传入非整数时间时明确 NOT_CONFIGURED/null，绝不补写 +16s 或 PASS；失败 query 仍先按原执行事实判 FAIL。没有发明 severity。新 adapter SHA256=2c31980a19c9443215fd196e6aab3e89e312c6bca535857a869b6fe2a610519b。
10. production Gate files changed：NO。baseline/final 共用 health.mjs，前后 SHA256 均为 65ab133a4248b9900265a47d943f9e6430b9ec9581ddd624b1d9257322b0d921；event-policy、health-contract、lock、manifest 和 sensor proof 同样未改。
11. adapter files changed：实现仅改 infra/security/policy/falco-parent.mjs。既有 falco-parent.test.mjs 只给零 IO fixture 添加显式 windowEndMs、断言它与原 Gate 实际 clock/query bounds 一致，并把输出转到新 evidence；106 个原 case 名、branch、旧 decision 和 standard decision 全部保留。新增 falco-time-contract.test.mjs 为时间证据契约保护测试。未修改其他 adapter、Engine 或生产 Gate。
12. Policy baseline changed：NO；baseline-v1 SHA256 仍为 02c3f5499dc39a53009a69e8f267dbbd247b4d89d4de14fafaa4dd5cff974f1a；Engine SHA256 仍为 dcfe4d6b0716897c6fc16c959bd89fef5dd3f62f8f85048d371efa073c308102。
13. timing matrix case count：74，baseline/final 各 37。覆盖 IO=0、1ms、250ms、999ms、1s、2s、近 15s 边界；首 logs/workload 耗时；采样前诊断耗时；第二 query 耗时；定时器迟唤醒；两个窗口的下/上界、边界前后 1ms；纳秒形式；墙钟回拨；各 query timeout。
14. timing matrix MATCH：修复后 74。before/after 每个 input digest 完全相同，raw facts 保持不变，runtimeAssessment 与实际原 Gate body 的结果相同。
15. timing matrix DRIFT：修复前 20；修复后 0。原 Gate 不重试，timeout 用 status=null/ETIMEDOUT 和原失败路径验证；没有为不存在的 retry 编造成功样本。
16. baseline previous cases：完整 52 项；原分布 PASS 19 / FAIL 33，全部维持。
17. baseline added cases：37 项时间差分，PASS 7 / FAIL 30。缺失/错误时间证据的单元保护测试另计，不冒充生产 Gate 差分样本。
18. baseline total MATCH/DRIFT：89/0，PASS 26 / FAIL 63。
19. final previous cases：完整 54 项；原分布 PASS 18 / FAIL 36，全部维持。
20. final added cases：37 项时间差分，PASS 7 / FAIL 30。
21. final total MATCH/DRIFT：91/0，PASS 25 / FAIL 66。
22. baseline/final continuity：完整旧套件保留健康、历史诊断、当前 fatal、transient、持续风险、query errors、identity/boot/container/restart/source/build 连续性、baseline/report 写失败等全部 branch。历史 warning 继续是信息；不把它改成新的 WARN Gate。baseline 建立和 final 连续性初始化不同，但采样代码完全相同。额外 12 项 guard 测试全部通过。
23. Policy core：5/5 PASS。完整 Falco parent Node tests 为 107/107，其中 106 项原差分加 1 项 uncaptured guard；新增 timing evidence guards 为 12/12。74 项 timing differential 由独立 runner 执行；没有把这些数量混成一个新的全 Policy suite 总数。
24. previous evidence：全部原件未覆盖或删除。旧 Falco evidence 在新 evidence-supersession.json 中明确标记 SUPERSEDED_FOR_TIME_BOUNDARY_COVERAGE，保留原 106 项历史结论和 source bytes。此前 drift preflight 也保留。新接受范围不冒充生产 sensor 认证或真实历史负例。
25. new index/hash：artifact-sha256.json 收录新 fixture、before/after、旧 adapter rollback bytes、生产时间契约、日志、接受矩阵和源码。4841 个保护文件中只有已授权 adapter 和其 fixture test 两个旧文件改变；无意外修改。既有生产 source 455 refs/229 distinct 全通过。旧 adapter 和旧测试的 before/after 哈希转换均显式保存。未改任何 accepted integrity hash；因此上一轮 inactive V2 candidate 有这两个预期 stale 文件，不能激活，必须由下一轮 readiness/version reconciliation 处理，不能静默忽略。
26. production build count：0；没有触发 Jenkins 或访问生产 API。本轮测试均在本地进行。
27. release count：0。
28. rollout count：0。
29. FALCO_TIME_CONTRACT = VERIFIED。
30. FALCO_COMPATIBILITY = VERIFIED。范围为有显式观测窗口的完整受控 frozen parent-stage 兼容性；不是完成真实 V2 pipeline。
31. exact blocker/drift if not VERIFIED：本轮没有剩余兼容 blocker，180 项总 DRIFT=0。仍保留能力边界：未做真实 pipeline facts capture，真实自然历史负例仍 DEFERRED_REAL_NEGATIVE_EVIDENCE，不据此声称线上 sensor 或完整 DevOps 平台已验收。
32. next permitted action：仅 AUTHORITATIVE SUMMARY_INTEGRATION_READINESS RECHECK，合入新 Falco 证据、校验 18-source 汇总与版本/哈希转换后，再判断能否恢复 READY。本轮 STOP，不恢复 Summary V2，不迁移 Promotion/Regression，不开始插件契约或其他架构阻塞。

历史 Jenkins 使用同一 health.mjs 字节；实际 Gate 的业务窗口由 Node Date.now 和 kubectl --since-time 参数决定，Loki/Grafana 不是 Gate 的时间权威。历史 baseline 诊断使用 --since=10m，final 诊断使用 baseline.capturedAt；这两种诊断查询均未改。kubectl wrapper 的 --request-timeout=15s、spawnSync timeout=20000ms、health fetch timeout=5000ms 保持原样；run 和 health fetch 没有应用层重试，出错即失败，不能通过重试重算窗口。本轮只从冻结源码及既有历史哈希重建这些事实，未重新运行生产 job。

回滚 target 为 evidence/2026-11-02/falco-time-contract-repair/before/infra/security/policy/falco-parent.mjs，原字节与原 SHA256 已验证。没有实际回滚；若恢复旧 adapter，将重新引入已确认的时间缺陷，必须保持 REVALIDATION_REQUIRED/SUSPENDED，不能复用新 VERIFIED 标签。

证据入口：evidence/2026-11-02/falco-time-contract-repair/acceptance.json、authoritative-falco-matrix.json、timing-before.json、timing-after.json、differential.json、continuity-check.json、source-preservation.json、evidence-supersession.json、current-status.json、artifact-sha256.json。
