# Security Manager V2 — Loki / Grafana Candidate acceptance

本轮基线 `3e46208b8db070e291ca94a7150965745f93b7d6`。本地实现与受控验证完成；不激活生产 Manager、不修改生产 Gate、不导入 Dashboard、不向生产 Loki/Dojo 写入、不 push、不发布、不 rollout。最终生产快照已恢复健康，但本轮观察到一次真实中断，不能宣称全程健康或已修复该故障。

## 交付与契约

- `infra/security/manager-v2/consumers/loki.mjs`：受封存输入约束的 allowlist 投影、纳秒字符串时间戳、Push payload 校验、固定目标 HTTP、默认 dry-run、有限重试、独立 hashed Receipt、私有输出目录与既有 payload 复用。
- `loki-event-v1.json`：版本化字段、枚举、160 种 label 组合上界、4 KiB line / 128 KiB batch / 64 events / 32 streams。project/run/digests 在正文；不作为存储 Label。
- `loki-cli.mjs`：默认本地，显式 Mock 开关；禁止 URL/token/header/代理/tenant 注入。
- `router.mjs` 只追加 `routeResultsWithLoki`，委托原 `routeResults` / `routeResultsHttp`，不建设第二个 Router。原同步/HTTP 实现保留字节前缀，默认 registry 未激活 Loki。`source-compatibility.json` 为源码证明。
- 不重新扫描、不调用 Policy Owner，复用同一 sealed Result/fact/resultDigest。一个 Consumer 失败不污染另一个；聚合 delivery 可以阻止 Candidate 投递，不改变 Policy。
- 仅复制受限制状态、身份和数量。原始 Gitleaks Secret、Cosign key、源码片段、环境、原始报告和异常内容不进入 Loki。Credential-shaped 身份拒绝，日志中未发现实际测试凭证明文。这是 schema allowlist 投影，不是通用秘密识别/DLP。
- Gitleaks 原生数量可用，但原生 severity 不足，高危数为 null；Semgrep ERROR/WARNING 保留原分类，不改称 High/Medium；Cosign 不是 CVE scanner。缺证据/未执行不填零，不填 PASS。

## 实际平台只读盘点

Loki buildinfo=3.7.4；Grafana 镜像=13.1.1；Alloy=1.18.1。已有 Loki datasource UID `loki`，URL `http://loki.monitoring:3100`。Loki `auth_enabled=false`，`reject_old_samples_max_age=168h`。未明确配置的 retention、服务端行/批次/Label 限额保持 UNKNOWN；Candidate 上限不冒充服务端真实限制。

原 V1 输出为 `security-summary.mjs` flat schema=1，经 `job=devsecops-security,project=petclinic,pipeline=security-audit` 直接 Push；既有 Dashboard UID `devsecops-control`。V2 独立 selector 为 `service_name=security-manager-v2,environment=validation,schema_version=1,job=devsecops-security-v2`，不读取 V1 冒充 V2。

配置 hash、datasource、Alloy 投影、原 Dashboard 内容，在 before 与 recovery 比较一致。GET /ready、buildinfo、labels 在恢复快照均 200；没有 V2 实际写入或 LogQL 查询。

## HTTP、重试与幂等

真实 Native Node HTTP Mock：仅 `127.0.0.1:32187/loki/api/v1/push`；Dojo Mock 仅 32185；OS 沙箱拒绝其他 loopback、外网和临时树外写入。临时树在测试后删除。无生产目标注册、凭据读取、重定向或代理通道。

204 才记 ACK；200/201/202 是 UNKNOWN，避免把可能的 blocked-ingestion 当成功。401/403/其他非重试响应拒绝。429/5xx/连接拒绝最多三次，退避有限，重试请求字节和 eventIdentity 不变。timeout/lost response 保留 UNKNOWN_REMOTE_STATE，不盲目重试。5xx/重试可以产生重复，`possibleDuplicates` 明示。没有 Loki 远程 exactly-once 证明。

Receipt 独立记录原 Result digests、payload/plan digest、attempt 状态/时间/body SHA、Mock 或 dry-run origin、远程 NOT_TESTED。初始 Push 不可能含自身最终 ACK；仅后续显式投影该 Receipt 才产生 Loki CONSUMER_DELIVERY，不自动递归 Push。Sample `loki-ack-next-explicit-batch` 明示此限制。

## 实测与失败记录

最终 `tests-attempt5.json/.tap`：**299/299 PASS，0 FAIL，0 SKIP**。

| 范围 | 数量 | 性质 |
|---|---:|---|
| 本轮 Loki | 67 | 原生 loopback HTTP + sealed REPLAY / 显式 FIXTURE；不是新的扫描 |
| 本轮 Grafana/LogQL | 20 | 限定模板结构、schema 与 fixture 数据契约；不是 Loki 查询引擎 |
| 原 Manager/插件/Dojo/Policy 回归 | 212 | 原相关测试入口，全部在新临时副本运行 |

27 份最终 HTTP/sample JSON 在 `loki-protocol-samples-attempt5/`，索引 `sample-index.json`。覆盖合法/无效实际 HTTP、204、401、403、429、500、503、连接拒绝、超时、丢响应、重试上限、目标拒绝、跨项目、脱敏、长字段、错误时间戳、重复事件、Label、Consumer OFF、master OFF、plugin disabled/error、Policy FAIL/error。

A–L 对应样本：A `A-three-valid`；B `H-gitleaks-fail`；C `G-semgrep-fail`；D `F-cosign-tampered`；E `D-gitleaks-disabled`；F `I-cosign-timeout`；G `master-off-FIXTURE`；H `policy-error-FIXTURE`；I `dojo-fail-loki-ok` 与 `dojo-http-fail-loki-http-ok`；J `loki-fail-dojo-ok`；K `both-fail`；L `A-three-valid/P-service-project`。G 是真实 Core OFF 路径，零扫描/零求值；H 是明确的 resealed 单元 FIXTURE，不是生产 Policy 事故。其余原生扫描事实来自封存 REPLAY；不将历史运行拼接成新同轮扫描。

保留失败日志：attempt1=63/64（输出 overlap 校验先被 ownership 截获，调整校验顺序）；attempt2=293/296（离线测试将布尔 filter 值误当 JSON 字段、将可重复的 provenance 日志与需去重的指标混比，修正测试范围）；attempt3=87/87（定向）；attempt4=298/299（普通成功 Mock 使用 150ms 测试预算时出现一次 UNKNOWN 超时，Consumer fail-closed 正确；普通成功测试改用默认 1000ms，故障测试仍 30ms）。未放宽生产 Jenkins/Gate 超时。

## Dashboard / LogQL

`infra/security/manager-v2/observability/dashboard.json`：可导入结构的 **DevSecOps Security Manager V2 Overview** Candidate，唯一 UID `security-manager-v2-candidate`，八面板，未导入或渲染生产。`queries.json` 八条实际 LogQL，覆盖执行/Policy/数量/能力/Receipt/project/溯源；面板 8 是版本化 `status-authority.json` 固定权威说明，无假动态 14/16 指标。

所有指标精确限定一个 project/run，先每 plugin 取 max，再聚合，重复投递不作为多次扫描。日志面板可以重复；不宣称 eventIdentity 服务端自动去重。缺数据为 No data，Cosign 数量不显示为 0。run/resultDigest 溯源在 project 范围内，标量 JSON 转义变量，查询行数受限。

没有安全可用的非生产 Loki。验证是 exact restricted-template / 括号引号结构 / 提取字段 / event 数据与重复指标语义；不是完整 LogQL parser。`fixtureView` 不是 Loki evaluator。`GRAFANA_REAL_QUERY=NOT_TESTED`，Grafana 实际 import/render=NOT_TESTED，Loki real remote delivery=NOT_TESTED。

## 证据写保护

13,708 个既有文件内容 SHA、size、mode、uid/gid、mtimeNs/ctimeNs/inode/symlink 及历史清单，在临时树测试前后保持不变。只有 Router/README 为明确许可的既有修改。当前轮 canary 覆盖/删除/chmod 被 OS 拒绝；所有子测试仅能写新临时树，网络仅两个 Mock 端口，外网拒绝。最终独立封存 `code-sha256.json`、`evidence-sha256.json`，由 `verify-seal.py` 验证。Git 本地提交不是 WORM；宿主机特权操作者仍不在此威胁模型内。

**ORIGINAL_EVIDENCE_INTEGRITY=FAILED** 保留，不能由本轮完整性检查改变。

## 生产异常与最终状态

基线北京时间 10:00：#270 SUCCESS、3/3、HTTP200、Argo Synced/Healthy。

本轮中途只读复核观察到：HTTP502；10:27 复核为 HTTP503、0/3 Ready、Argo Unknown/Progressing，ComparisonError 为 repo-server `10.43.95.130:8081 connection refused`；另一次 `kubectl get nodes` 超过25秒。devops load1m=52.96，但这只是现象，不能推断为根因。Ready 条件曾变更，三节点在 followup 已 Ready。

10:30 最终生产快照恢复：#270 SUCCESS / last270 / queue0、V1 Summary 与 Jenkins job hash 不变、3/3、HTTP200、Argo Synced/Healthy、三节点 Ready、socket0660。Deployment UID/generation175/spec/image digest、Docker daemon PID1023/restarts0、Trivy DB metadata 均与基线一致。监控 recovery 快照 Loki Ready/GET200，Alloy/Grafana Ready，配置/datasource/既有 Dashboard 内容不变。

这不是全程可用证明，也不是我们修复了异常。没有重启、apply、发布、Agent、扫描、DB 刷新、生产 Push 或 Grafana 写入。根因 **NOT_DETERMINED**；中途失败证据永久保留。`health-followup-projection.json` 的紧凑序列化 spec hash 与原有默认空格序列化不同，`production-comparison.json` 解释其不可直接对比；按基线算法计算实际 spec 完全一致。

## Verdict 与剩余阻塞

完整逐项 verdict 见 `verdict.json`：本轮 Loki Consumer/Mock HTTP/离线 Grafana contract VERIFIED。真实 Loki delivery/query、Dojo remote delivery/idempotency NOT_TESTED；Production Manager NOT_ACTIVE；Jenkins V2 CI、Trivy/Dojo Canonical Runtime、Summary V2 migration INCOMPLETE；14/16 不变；release=0、rollout=0、push=0。

回滚：本轮只提交本地 Candidate 代码。停用显式 `routeResultsWithLoki` / 不导入新 Dashboard 即停用新增能力；如需撤销代码，审阅后仅 revert 本轮独立提交。没有生产配置需要回滚，不删除任何历史证据。

下一步唯一允许的实际操作：先只读定位/观察这次生产瞬时异常，不能把一次恢复当稳定性通过。后续真实 Loki 最小验证必须另行指定并授权**非生产**实例、固定目标与权限、容量/保留期、隔离项目、少量已脱敏事件和清理责任；随后才能验证 Push、LogQL、重复投递和 Dashboard import/render。当前没有该目标，不执行。Dojo 并发 journal 竞态仍 NOT_TESTED，独立限制真实投递，不阻塞本轮 Loki Candidate。

API 依据：[Loki HTTP API](https://grafana.com/docs/loki/latest/reference/loki-http-api/)、[LogQL](https://grafana.com/docs/loki/latest/query/log_queries/)、[Metric queries](https://grafana.com/docs/loki/latest/query/metric_queries/)、[Grafana variables](https://grafana.com/docs/grafana/latest/visualizations/dashboards/variables/variable-syntax/)。实际版本与现有配置来自本轮只读快照；未将在线文档默认值视为当前配置事实。

**STOP**
