# W12 可观测一致性统一核验 + Web UI/接线整合 — 复现说明（2026-11-13）

## 阶段 1（G-S2）
devops 会话内运行 scripts 同款 grafana-check（sonarqube 证据目录 grafana-check-w12.sh）：凭据仅从 k8s secret monitoring/kube-stack-grafana 会话内取用，对 web-caf26080（clean）与 web-cd9e2513（violating）做 datasource proxy query_range，结果 matched=1 x2；原件在 sonarqube-v2/raw/grafana-loki-{clean,violating}-w12.json（sha256 与 devops 端对验一致），结论 grafana-supplement-w12.json，提交 f9022bc9。

## 阶段 2（逐插件）
- 整合脚本 scripts/w12-integrate.py：对每个插件先做 worktree view 编辑（actions/app/controls），再以 blob 方式把该插件 hunk 逐个写入 index（HEAD 基础上叠加），Codex hunk（withReplayAudit/lokiReplayEvents/canReadRun/trivy counts）从未进入任何提交（每波 git diff --cached 校验计数为 0）。
- 验证 scripts/w12-view-driver.mjs（进程内导入 view/actions）：capability READY -> clean 案 -> finding 案 -> controls 关态 DISABLED 零执行 -> 恢复 READY；每插件结果在 raw/view-driver-<plugin>.json。
- 提交顺序与哈希见 verification.json phase2_UI.commits。
- Falco 未接线（BLOCKED 理由见 per-plugin/falco.md）。

## 阶段 3（13x3 矩阵）
- Loki 直查：scripts/w12-matrix-mac.mjs 经 view/loki-delivery.mjs 的 withExistingLokiChannel（按需 SSH 隧道 127.0.0.1:32189 -> Loki 10.43.7.197:3100）以 LogQL 按 runId 直查，结果 raw/matrix-mac.json。
- Grafana 回查：devops 侧同一 grafana-check 脚本（700h 窗口）逐 runId 回查，原件 raw/w12-grafana-<plugin>.json。
- Web 视图：同一 matrix 脚本以 view/actions 的 recentRuns/getRun 只读路径核查（参考运行本身或 W12 view 运行）。
- 组装：verification.json 由脚本从上述原件机械生成（eventIdentity/resultDigest 跨源比对）。

## 回归
manager-v2 顶层 180/180；manager-v2+view 202/202；infra/security+observability 147/147；consumers 114/162（48 败为既有基线，逐数一致）。

## 红线自查
生产 Manager NOT_ACTIVE（view 服务从未启动，全程进程内导入）；未触发 Jenkins；Harbor 未写；冻结 Policy 未改；未 push；未 reset/clean/stash/git add -A；Grafana 凭据仅 devops 会话内使用未落盘；集群变更仅 kubescape-v2-test 测试命名空间恢复（非生产、可回滚、原件留存）。
