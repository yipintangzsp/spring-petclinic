# Security Manager 架构契约检查 · 2026-11-01

结论：**FAILED，已按“结构性阻塞立即停止”要求停止实施。** 当前不能认定架构收口完成。没有修改实现、业务 Jenkinsfile、生产 Gate 或集群；没有触发 Jenkins、业务 rollout、扫描重跑或新常驻组件。本轮新增内容只有检查报告、矩阵和证据索引。

## 检查范围

实际仓库为 `/Users/zhangsir/code/petclinic-platform-20261011`，当前分支 `fix/security-manager-plugin-switches`，本地 HEAD `741ea2866ea142b24c7838e1ef25c8327c79d279`。已读取 vars、resources/security-manager、infra/security/manager、governance/provenance 实现及历史原始归档。未查询远端最新提交、实时 Jenkins/Dojo/Loki/Grafana，因此以下 VERIFIED 是有时间与场景边界的历史验证，不代表 11 月 1 日实时服务健康。祖先路径和目标子树未找到适用 AGENTS.md。

没有把 10 月初的旧仓库或节点故障记录当成本轮状态。原有五个 tracked 文档修改和其他 untracked 工作保留，没有提交或覆盖。

## 已确认的结构性阻塞

| Blocker | Affected capability | Evidence | Minimal recommended fix |
| --- | --- | --- | --- |
| B1：没有独立分层、版本化 Policy Engine | 默认 standard、low/standard/strict、Profile 策略、Component/Project override、policy version、POLICY_ERROR | `vars/securityManager.groovy` 仅校验 mode/profile 和 switches；三个实现目录内没有 securityLevel/policyVersion/override 处理。`infra/security/manager/tool.mjs` 在扫描分支内给 r.blocking 赋值，末行直接据 blocking/mode 决定 exit10。Trivy 内部写死 C/H、ZAP blocking=0。给 cfg 传 securityLevel 会被存入配置但没有实际策略消费，不能将调用者写了 standard 当作生效 | 新增单独、版本固定的策略解析/评估接口，先冻结并回归旧 Gate 决策，Scanner 只保留原始事实。实现 standard 默认与严格校验、各层来源记录；未知版本/读取失败/错误 override 明确 POLICY_ERROR。不能批量改旧规则或通过 low 兜底 |
| B2：统一注册、默认启用和 capability 契约不完整 | 所有插件默认启用、缺失 capability 状态、独立接入退出、统一状态 | profiles.json 只是工具 ID 数组，没有策略或 capability 描述；两个 provenance 在 profile 外调用，分别需要额外 opt-in；未启用时 skipped 结果被过滤不入 modules。gitleaks/semgrep 无条件被认为 ready。SOPS/Kyverno/Falco 仅生产 adapter 内存在，非 generic registry | 用统一描述表声明插件、适用 Profile、required capabilities、执行/输出类型与缺失状态；统一状态归一化。Provenance 只在能力足够时执行，缺失要可见；生产 adapter 的冻结门禁约束保留，不能为了通用禁用而解除生产保护 |
| B3：Dojo 是顺序依赖的“插件”，还不是 Summary 后的统一 Router | 插件解耦、统一结果出口、单插件/逐步联动、退出稳定性 | tool.mjs defectdojo 分支 current(id) 直接读取其他 enabled scanner 的 `<id>-manager.json`，要求成功/build/source 相同，再读各自私有 native 路径。调用发生在 summary 生成之前；顺序来自 Profile 列表。缺报告或 failed scanner 会抛错。这是显式文件及顺序耦合，不能宣称插件完全解耦 | 在 Manager 收集标准 artifact/result 清单后由 Router 统一导入，scanner 不引用其他插件；保留 DojoClient 原生 parser、同步 reimport 和 Finding ID 稳定检查。不要重写已有 Dojo 数据模型 |
| B4：尚未满足全插件 output/publish verification 契约 | 统一 raw/normalize/summary、required publish、result queryable、完整集成成功定义 | generic summary 对固定 ID 列表读取文件，仍用 success/warn/failed 等内部状态；Cosign 没有独立标准 native artifact，provenance 使用另一套文件。Loki publisher 仅验证 push 204，没有本轮 read-back；summary 没有生效策略/版本/各层来源。已有历史 Grafana 验证不能证明新策略字段可查询 | 定义标准结果/原始报告引用并由 Router 汇总；基于现有 Loki 追加当前 run 关联查询证明和 required sink 状态。非 Finding 证明只进 Summary/Loki/Grafana，不伪造 CVE；保留历史报表 |

这是静态实现与原始归档已能证明的阻塞，不需要运行新的重任务才能发现。按要求没有在发现 B1 后继续实现其他契约，也没有通过修改 Profile、关闭 Gate 或编造数据获得成功结果。以上最小修复是后续分轮范围，不是本轮已执行内容。

## 保留的 VERIFIED 能力

1. **上一轮失败与修复分开记录。** portability-smoke #3 的 Jenkins 结果为 FAILURE。其 security-summary build_result=SUCCESS 是后续断言失败前生成的中间状态，不能替代最终构建结果；旧 matrix 的 overall=BLOCKED 保留。
2. **插件禁用修复已完成，不重做。** 固定 741ea28 的后续 #4 off：扫描0，Build/Test 保留；#5 Semgrep skipped、Gitleaks 正常、没有 Semgrep 扫描报告/日志；#6 Gitleaks skipped、Semgrep Finding 保留；#7 enforce 人工 Java 违规产生 failed，Jenkins FAILURE 符合预期。#7 不是新的普通业务构建故障。证据位于历史 `plugin-switch-fix-20261030/build-{4,5,6,7}/capability-result.json`。
3. **单 Finding 类插件完整历史链。** #6 仅 Semgrep scanner 配置完整，Kubescape not_configured、Gitleaks disabled；Dojo 是结果消费者，不计作第二 scanner。Dojo Test35 查询到 Finding1，同报告 reimport ID 稳定，closeOldFindings=false。不将一个 Semgrep 测试扩大成所有插件已验证。
4. **历史 capability 缺失不伪报 PASS。** #3/#5 的 Kubescape、Dojo 明确 not_configured；这不证明所有插件缺失输入处理都完成。
5. **Provenance / Attestation 历史能力保留。** producer `petclinic-candidate-build #2`、consumer `petclinic-ci #270` 成功，security-validation 与 image-build 两种 predicate 独立。#270 归档中正确签名通过，digest/source或commit/builder/tamper 负例拒绝；临时私钥文件清理记录保留。该能力仍属既有 opt-in，不冒充默认启用契约已完成。
6. **既有治理和观测保留。** #270 中 Kubescape、DefectDojo 均 success；overview-verification status=success，Grafana/Loki/Prometheus 检查及 Falco/Kyverno nativeChecks 有历史响应，Image Build Provenance panel 验证保留。Dojo 总发现6625是历史治理集合，不是当前项目本轮新增漏洞量。没有把签名、Attestation、普通 Falco/Kyverno 事件伪造为 Dojo Finding。
7. **跨项目复用已有有限证明。** iac 独立 fixture 在没有 PetClinic 代码结构的情况下执行了 Gitleaks/Semgrep；未将这点扩展为 Python/Java/container 的所有能力或两个 Profile 策略已验收。

所有历史证据原件仍在 `/Users/zhangsir/Documents/New project/` 的相应日期目录。本轮仅提取必要状态，不复制凭据或漏洞原始内容到报告。17 份核心实现/历史证据文件的路径、大小、SHA256 保存于 evidence-index.json。

## A–L 验收映射

| 项 | 本轮结论 | 说明 |
| --- | --- | --- |
| A 模式 | VERIFIED | 限历史 #4 off/#3 audit Finding/#7 enforce 负例；不表示每个插件所有模式已验收 |
| B 独立禁用 | NOT_TESTED | Semgrep、Gitleaks 两个源码扫描插件已验证；要求的不同类型插件禁用运行验收尚缺，不能视为全部完成 |
| C 缺 capability | VERIFIED | 限 Kubescape/Dojo 历史 not_configured，不扩大范围 |
| D 默认 standard | FAILED | 未实现有效 securityLevel 消费与结果字段 |
| E standard/strict | FAILED | 不存在可独立评估同一 raw finding 的等级策略引擎 |
| F 禁止静默降级 | NOT_TESTED | 没有执行错误策略输入用例；未知 Profile 会失败，但不能据此宣称完整防降级已验收 |
| G Component override | FAILED | 无解析与生效接口 |
| H 两个 Profile 不同策略 | FAILED | profiles 仅选工具，不含默认策略，两个策略 Profile 无从验收 |
| I Project override | FAILED | 不能通过现有 cfg 实现分层策略覆盖 |
| J 单插件完整链 | VERIFIED | 限 #6 Semgrep→native→manager result→固定门禁/summary→Dojo查询；新 Policy Engine 路径仍 FAILED |
| K 逐步联动 | NOT_TESTED | 两 scanner 同时执行已有历史证据，但没有按本轮契约逐步增加并验证 Policy/Router 的完整记录 |
| L Loki/Grafana | VERIFIED | 限既有 #270 历史 pipeline/runtime/supply-chain 展示；securityLevel/新 Policy 字段 NOT_TESTED |

## Capability Matrix 与停止点

完整 14 项能力对象、每项23字段的矩阵见 `evidence/2026-11-01/security-manager-contract/capability-matrix.md` 和同名 JSON。枚举严格限定 VERIFIED、FAILED、NOT_TESTED、NOT_APPLICABLE、NOT_CONFIGURED。矩阵对 adapter 已验证与 generic 未验证分开，不把旧流水线成功推广为新架构契约满足。

最终每行 FAILED 表示完整新架构契约未满足，不表示既有安全工具突然损坏。SOPS/age、Falco、Kyverno 的 generic 插件生命周期尚无对应注册项，相关项保留 NOT_APPLICABLE/NOT_TESTED 并在 notes 解释，不能当作所有插件已覆盖。

**下一步最小建议：先单独收口 B1 的冻结基线和纯策略契约，明确版本与继承行为后，再恢复独立 smoke 的标准/严格/错误配置用例。** 当前遵从停止指令，不自行实施这项结构性调整。没有新 Jenkins 构建号、提交或版本，也不输出全架构成功标记。
