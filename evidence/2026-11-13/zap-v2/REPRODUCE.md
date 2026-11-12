# ZAP V2 真实执行闭环 — 复现说明（evidence/2026-11-13/zap-v2）

## 组成
- `verification.json`：八维结论所依据的全部运行事实（runId、摘要、告警、回执）。
- `raw/core-driver-summary.json` + `raw/driver.log`：Core driver 原始汇总与日志。
- `raw/<caseId>-<level>/`：每案 artifactStore 封存目录原件（candidate-summary、zap.result/facts/runtime-facts/raw、candidate-seal）。
- `raw/disabled-plugin-off/`、`raw/disabled-master-off/`：关态两案封存原件。
- `raw/grafana-loki.json` + `grafana-check.sh`：Grafana 数据源代理回查（devops 会话内执行，凭据不出会话）。
- `run-driver.mjs`：本轮 driver（从仓库根以 node 24 运行）。
- `protected-before/`：改动共享文件前的快照（registry.mjs、core.mjs、consumers/loki.mjs、consumers/loki-event-v1.json；快照时点已含 W3 kubescape 线的未提交增量）。

## 执行面（devops 新建，与 kyverno/sonar 同构）
- 用户 `security-zap`（uid 1004 / gid 981），家目录 `/var/lib/security-zap`（root 拥有）。
- `entry.py`（root 拥有 444）：forced command `scan-v1 <project> <runId> <case>`，经 authorized_keys `restrict,command="/usr/bin/setpriv --no-new-privs /usr/bin/python3 /var/lib/security-zap/entry.py"` 钉死；校验 uid/gid/groups/NoNewPrivs、禁止读生产权威（docker.sock、k3s.yaml、sonar-token）、ZAP jar sha256 钉版、资源预算、flock 串行。
- `fixture.py`（root 拥有 444）：回环靶标。clean 页全量安全响应头（实测零告警）；pii-disclosure 页含 V1 同款测试卡号 4111 1111 1111 1111（pluginid 10062 High）且默认弱响应头。
- `projects.json`（root 拥有 444）：两项目三用例，端口钉死 18113/18115（clean）、18114/18116（pii）、18117/18118（cleanroom）。
- 扫描：ZAP 2.17.0（`/opt/platform-security/zap/2.17.0/zap-2.17.0.jar`，sha256 015dda47…c99c0c，与 tools-lock.json 钉版一致）；plan 固定 requestor GET + passiveScan-wait + traditional-json 报告；无 spider、无主动扫描；报告 site 主机/端口经 wrapper 与 runner 双重校验必须为本案回环地址；靶标进程验后终止且端口关闭才报 cleanup=VERIFIED。
- Mac 侧：专用密钥 `~/.ssh/security-manager-v2-zap`（0600）；武装文件 `.devsecops/security-view-zap-linux-v1.json`（enabled:true, consumed:false，与 kyverno/sonar 既有惯例一致，保持武装）。

## Policy 口径（冻结，未动任何分类器/引擎）
- fact 形状 `{component:'zap', status:'success', raw:{report, context:{targetImage, reportSha256}, approved}}`，approved 为仓库原样 `infra/security/zap-confirmations.json`（schema 1、confirmations 为空）。
- 冻结 classifyZap 语义：无已审 exploit 确认的 High 告警只进 warnings。引擎层级表（baseline-v1）：standard 下 WARN 保持 WARN；strict 下 High/Medium 求值取 effectivePolicy=FAIL。
- 因此负例同一次真实扫描给出双口径证据：standard→WARN（与 V1 zap-gate 对同一靶标的判定一致）、strict→FAIL。runner 的 oldDecision 按用例钉死级别用冻结引擎对同一 fact 求值，Core 单次求值复核一致（四案 oldGate 与 policy 全等）。

## 复现
1. devops wrapper 已就位（见上）；Mac 仓库切到含 zap-real 的工作区状态（见下方接线说明）。
2. `node evidence/2026-11-13/zap-v2/run-driver.mjs`（node v24.14.0）→ 期望输出 4 CASE 全对、2 DISABLED、3 CROSS 拒绝、2 LOKI DELIVERED/VERIFIED、DRIVER_DONE。
3. Grafana：把 `grafana-check.sh` 里的 runId/resultDigest/eventIdentity 换成本轮新值后在 devops 会话内 `bash grafana-check.sh`。

## 接线增量（工作区，未提交——与 W3 kubescape 未提交增量同文件纠缠，按 Falco/Sonar 先例处理）
本线只提交自有新文件（zap-real.mjs、zap-real.test.mjs、zap/projects.json、zap/runner.json）与本证据目录。以下四个共享文件的 zap 增量留在工作区，待 W3 提交后由整合时点统一处理：
- `registry.mjs`：新增 realZap 校验分支（runner zap-real / REAL_VALIDATION / zap-native/v1 / policyAdapter zap / TERMINATE_AND_VERIFY_GROUP）、超时上限链加 `realZap?240000`、新增 `realZapRegistry()`（基于 realManagedRegistry，zap requiredCapabilities=[RUNTIME_TARGET, TRUSTED_EXECUTOR]、timeout 240000、pluginVersion 2.0.0-candidate.7、enabled:false）。
- `core.mjs`：新增 `executeRealZap` import 与 `zap-real` 分发分支。
- `consumers/loki.mjs`：singlePluginId 白名单加 `'zap'`（一行）。
- `consumers/loki-event-v1.json`：plugins 数组加 `"zap"`（加法）。

## 清理
- devops `/var/lib/security-zap/data/` 下全部运行目录（冒烟 3 + driver 4）已删，仅剩 execution.lock；18113–18118 端口复验全空闲；无残留 fixture/ZAP 进程。security-zap 用户与 wrapper 为交付基础设施，保留（如同 security-kyverno/security-sonar）。
- 盘点时误触的 zhang 家目录 `~/.ZAP`（zap --version 探针生成）已删。
- 未扫 petclinic 本体、未扫任何外部站点；未触发 Jenkins；Harbor 未写；生产 Manager NOT_ACTIVE。
