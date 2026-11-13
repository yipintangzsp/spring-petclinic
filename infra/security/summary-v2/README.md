Summary V2 候选实现，尚未接入生产。

当前生产仍使用原来的 Summary、Security Manager、Jenkins、Promotion 和 Regression。candidate-integrity.json 是隔离测试的显式版本契约，未加入任何现有 accepted hash。完整验收结论为 INCOMPLETE。

实现路径：owner.mjs 调用既有 Engine；results.mjs 只校验及投影 receipt；artifact.mjs 完成固定 16-source 集合、绑定和完整性检查；producer.mjs 只消费 artifact。消费者的传递依赖中没有 Engine 或 owner。promotion-input.mjs 只是未接入的 Policy 前置检查，不执行批准、签名、发布或 Git 操作。

fixture-harness.mjs、两个 test 文件仅用于受控测试。大部分 source 在这些 fixture 中明确 SKIPPED，不证明真实流水线 16 个来源均完成采集。owner 的重复调用保护目前仅在单个 owner 实例内；真实流水线的唯一 owner、跨进程 receipt 交接和重试防重尚未接入，不能据此宣称 pipeline 级 once 已验证。

artifact 的内容哈希由 owner context 提供，不能从待验证文件自身获取可信哈希。create-only 文件采用 wx、0400；这不防御同 UID 或控制 Jenkins workspace 的攻击者。契约、版本选择、预期 binding 和 artifact digest 必须来自可信执行上下文。

当前主要缺口是完整原始执行观察采集。SOPS、Kyverno/RBAC、Kubescape、Falco 两阶段、Cosign 和 Dojo 的现有成功报告不能直接替代各自 adapter 的原始事实。需要保持原参数、原退出状态、IO/清理结果以及敏感数据仅留内存的采集，再同时迁移真实 Manager/Gate、pre-approval 字段采集、Summary 和两个消费者。不得把成功报告补写成完整事实，也不得以这些单元测试代替生产接线验收。

运行检查：

~~~sh
node --test infra/security/summary-v2/handoff.test.mjs infra/security/summary-v2/compatibility.test.mjs
node --test infra/security/policy/engine.test.mjs
node infra/security/testing/audit-summary-v2.mjs
~~~

原始 Regression 测试中的 HTTP fixture 需要允许本机 127.0.0.1 临时监听；沙箱内的 EPERM 必须保留为真实失败，不能跳过。

V1 快照和逐项报告：evidence/2026-11-02/summary-v2-migration/。回滚试验只在临时目录恢复 V1 完整字节并显式选择 V1 契约；没有切换或重启生产。
