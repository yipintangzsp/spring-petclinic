# Policy metadata Summary integration — INCOMPLETE

本轮在实施前停止：security-summary.mjs 同时被 Promotion、Regression 的冻结源码锁绑定。即使只追加一行注释，两项 adapter 也会抛出 POLICY_ERROR。这是精确源码完整性约束；没有证据表明 Summary JSON 字段集是封闭的。

两次受控检查只替换当前 Node 进程中的文件读取返回值，没有写入源码。同一事实在检查前后均为 PASS，模拟修改时返回明确错误。source-lock-blocker-proof.json 保存结果。没有真实发布、签名、审批、扫描或生产故障。

上一轮 readiness 已列出 source-lock 的未来迁移约束，但没有证明修改 producer 后该约束仍满足。本轮执行前补证确认它是实施前置条件。此前 2128 个冻结兼容样本保持原结论，不能据此推导“可以直接修改被锁定源码”。

## 最终要求逐项结果

| # | 要求 | 真实结果 |
|---|---|---|
| 1 | 当前 producer | infra/security/security-summary.mjs；输出 .devsecops/security-summary.json。 |
| 2 | Generic 关系 | resources/security-manager/summary.mjs 是 Shared Library 运行模板，vars/securityManager.groovy:74-75 加载；infra/security/manager/summary.mjs 是相同字节的仓库副本，没有发现生成声明。 |
| 3 | 原有顶层契约 | before-contract.json 记录显式字段分组、条件字段、输入、状态/计数、写入/错误语义；producer 与直接 helper 完整副本及 SHA 已冻结。 |
| 4 | 消费者 | Promotion evidence/contract/sign-approve/promote、Jenkins archive、Shared Library 调用、Loki、Grafana 查询、冻结源码校验、测试/oracle，详见 consumer-inventory.json。 |
| 5 | Strict/exact consumer | 未发现封闭 JSON 字段集；**存在两个精确源码 SHA 约束**，受控复现均确认阻塞 producer 修改。 |
| 6 | Policy metadata 形状 | 仅保留拟议 policy:{policyVersion,securityLevel,effectivePolicy,appliedOverrides,status}；停止后未实施，不能视为真实输出。 |
| 7 | overrideSource | 不新增；使用现有 appliedOverrides，未重新解释语义。 |
| 8 | POLICY_ERROR 表达 | Summary 显式 policy.status=POLICY_ERROR 是待实施要求；当前未接入，未伪造 standard/low/PASS。 |
| 9 | schema 版本 | 实际仍为 1，未修改；已读 JSON 消费者支持 additive 的初步结论，整体新输出验收尚未完成。 |
| 10 | 生产文件修改 | **0**；仅新增本轮 evidence 文件。未更新锁、Gate、Policy 算法或发布逻辑。 |
| 11 | 旧字段差分 | **NOT_EXECUTED**，未生成新 Summary；未修改源码不能替代新旧输出差分证明。 |
| 12 | PASS Summary 用例 | **NOT_EXECUTED**。 |
| 13 | FAIL Summary 用例 | **NOT_EXECUTED**。 |
| 14 | WARN Summary 用例 | **NOT_EXECUTED**。 |
| 15 | SKIPPED Summary 用例 | **NOT_EXECUTED**。 |
| 16 | NOT_CONFIGURED Summary 用例 | **NOT_EXECUTED**。 |
| 17 | POLICY_ERROR Summary 用例 | **NOT_EXECUTED**；本轮复现的是源码校验错误，不是已序列化错误 Summary。 |
| 18 | 默认 standard metadata | Policy core 测试通过；真实 Summary 传播 **NOT_EXECUTED**。 |
| 19 | low metadata | core 显式选择/错误拒绝测试通过；真实 Summary 传播 **NOT_EXECUTED**。 |
| 20 | strict metadata | core 同事实更严格测试通过；真实 Summary 传播 **NOT_EXECUTED**。 |
| 21 | Component Override | core 作用域测试通过；真实 Summary 传播 **NOT_EXECUTED**。 |
| 22 | Project Override | core 身份/优先级测试通过；真实 Summary 传播 **NOT_EXECUTED**。 |
| 23 | Promotion consumer 回归 | 纯 validateGate 测试接受追加 policy，剥离 policy 后原对象完全一致；**仅契约预检**，非 producer 集成、非审批或发布验证。 |
| 24 | Jenkins archive | 静态确认固定路径归档、无字段解析；**未执行流水线回归**。 |
| 25 | Loki | 静态确认完整 record 序列化为日志字符串、标签不依赖 JSON 字段集；**未发布、未做新增 metadata 运行验证**。 |
| 26 | Grafana/parser | 静态确认 LogQL 提取固定原有字段；**未执行运行时查询回归**。 |
| 27 | 其他 consumer | 已按 A/B/C-D 分类，见 inventory；未把静态检查标为全消费链运行通过。 |
| 28 | 重复 evaluation | 未引入新 evaluation；同时未发现现有生产路径向 Summary 交付 authoritative resolved Policy result 的接口。需先明确单次求值结果交接，不能在 Summary 内新增求值或伪造结果。 |
| 29 | Policy core | **5/5 PASS**，见 core-tests.log。 |
| 30 | Summary 专项 | 实施前检查 **3/3 PASS**（两个阻塞复现 + 一个 Promotion additive 契约）；真实 Summary 集成测试 **NOT_EXECUTED**，不是 VERIFIED。 |
| 31 | 源码保全 | 冻结源码引用 **455**、不同文件 **229**，失败 **0**；本轮开始前已有文件 **4180**，改变/删除 **0**。 |
| 32 | schema 兼容 | Promotion JSON contract 预检通过；整体新 Summary/schema 兼容 **INCOMPLETE**。 |
| 33 | evidence index/hash | artifact-sha256.json 索引本目录制品（排除自身及最终校验回执以避免循环）；final-validation.json 记录全部索引哈希验证。 |
| 34 | 发布/rollout | **0 / 0**；审批、签名、promote 同为 **0**。 |
| 35 | 最终状态 | **POLICY_METADATA_SUMMARY_INTEGRATION = INCOMPLETE**。 |
| 36 | 精确 blocker | promotion-baseline-v1.json:19 与 regression-baseline-v1.json:60 锁定 producer SHA；promotion-evidence.mjs:4-5 / regression-evidence.mjs:5-6 修改后必报 POLICY_ERROR: frozen … source changed。另有单次 evaluation 结果交接尚未定义的前置条件。无已落地语义回归，故不标 FAILED。 |
| 37 | VERIFIED 后下一动作 | **不适用，未 VERIFIED**。本轮按停止条件结束，不进入其他结构性阻塞或统一插件契约。 |

## 精确证据与停止条件

两个版本锁都要求 producer SHA256：

    038320f04c67fb1fe5ff711c11d445c2de88cc50b2230eb4c971bf46142f5b34

source-lock-blocker-proof.json 中两次内存检查均记录 baselinePolicyDecision=PASS、observedError=POLICY_ERROR、restoredPolicyDecision=PASS、rawFactsPreserved=true、onDiskSourceUnchanged=true。

纯 Promotion JSON 契约测试通过只证明 validateGate 不拒绝该额外字段，不能证明源码锁兼容。测试故意区分这两件事。

附件 STEP 12 要求修改 Summary 若涉及 scanner/Gate 变更则 STOP，不扩大范围。继续修改 producer 需要先解决已冻结完整性契约；本轮没有绕过校验、替换旧 SHA 或更改 Gate。仍不存在可验收的新实际 Summary。

## 最小补救范围（本轮未执行）

先单独处理 producer 所涉冻结源码契约的**版本化迁移**：保留旧源码、旧 oracle、历史哈希；证明新旧 Summary 剥离批准新增路径后等价，再建立明确的新版本绑定。不能直接替换旧 SHA 或移除完整性检查。

同时明确现有 Policy Engine 的单次求值位置与 resolved result 交接接口。Summary 仅序列化结果。此前置工作明确后才能重做本轮实际 Summary 集成及消费链运行验收。

新增 parent-stage scanner 样本 **0**；原有 **2128 MATCH / 0 DRIFT** 未重跑、未改写、未增加计数。8 项本轮检查为独立的 5 个 core 测试 + 3 个实施前检查。没有继续其他结构性阻塞。
