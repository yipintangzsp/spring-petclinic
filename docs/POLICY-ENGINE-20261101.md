# 版本化 Policy Engine：本轮停止记录

最终验收：**FAILED（部分实现完成，未接入生产）**。没有输出成功标记，没有运行 PetClinic 流水线、rollout 或新增常驻组件；DefectDojo、Loki、Provenance 均未修改。没有修改原有 scanner/gate、Security Manager 或公共 Summary。

## 实际新增

- `infra/security/policy/versions/baseline-v1.json`：Git 可追踪版本，low/standard/strict、五个已知 Profile；当前 Profile 策略为空，继承全局，不虚构项目差异。
- `infra/security/policy/engine.mjs`：纯策略核心。默认 standard，版本/等级/Profile/覆盖输入错误明确 POLICY_ERROR；组件覆盖及绑定项目身份的覆盖独立解析，输出 policyVersion/securityLevel/profile/effectivePolicy/appliedOverrides。已知冻结 FAIL 为不可削弱底线。strict 将测试 Medium 从 WARN 加严为 FAIL；low 只能显式选取，目前保守保留旧行为，不降低既有 Gate。
- Scanner 事实输入接口仅支持 Semgrep、Trivy、ZAP；引擎复用原纯分类器，没有改变发现内容或旧分类代码，没有读取业务路径、namespace、Deployment 或环境专有变量。其他组件明确 POLICY_ERROR，而不是假通过。
- `snapshot.mjs`：在实现引擎之前运行，保存74个旧决策样本和修改前源文件摘要。其中20个是原纯分类器直接执行结果；54个是generic exit语义枚举，不能混称74个实际生产Gate样本。快照不是完整生产基线。

## 实测结果与缺口

`node --test infra/security/policy/engine.test.mjs`：5项测试全部通过，覆盖默认/显式等级/错误配置、20个旧分类决策一致、raw input不变、component/project隔离与优先级、不可放宽既有FAIL、策略结果元数据。日志：`evidence/2026-11-01/policy-engine/pure-smoke.log`。

但最终验收不成立：

1. **blocker**：完整生产 Gate Decision Snapshot 尚未建立，各原始执行层不统一：源码逐项误报审查、Python命令分析、Sonar外部质量门、运行时窗口和准入检查等未迁入标准事实适配。此次snapshot不能代表这些输入空间。
2. **evidence**：用真实接口对 gitleaks 空发现事实调用返回 `POLICY_ERROR: frozen evidence adapter not implemented: gitleaks`；`acceptance.json`保存此错误、受影响范围及原gate源码摘要。20个局部决策一致不等于所有生产Gate兼容。
3. **affected capability**：A的全Scanner/Policy分离、D的所有生产Gate standard兼容，以及C的实际统一Summary输出未完成。当前只是evaluate返回元数据，未将其写入现有统一Summary，不声称Summary集成已验证。
4. **minimal fix**：下一轮仅增加冻结Gate事实适配及独立fixture：逐项保留原始输入/审查/身份与原决策，原分类器作为对照；先补源码、命令、签名/准入、质量门、运行时/治理的正反例，完整差分通过后才接Manager和Summary。不得直接用旧decision/exitCode当作scanner事实传回新引擎，也不能把已有业务Gate替换为通用severity规则。

已执行代码止于局部核心与独立测试，按用户“失败即停”要求不继续补接其他Gate或另外三个架构阻塞。没有新Jenkins构建号或生产版本。新增目录和文档可整体移除回滚，不涉及现有配置/数据。
