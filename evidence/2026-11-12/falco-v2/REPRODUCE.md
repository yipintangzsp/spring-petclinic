# 复现步骤 · Falco V2 真实执行闭环（条目 1b，2026-11-12）

仓库分支 `fix/security-manager-plugin-switches`；代码提交 `2cdcc95c`（falco-real runner/registry/core/loki schema）。
另有受保护文件 `consumers/loki.mjs` 的未提交最小增量（白名单加 `falco`，见小结增量清单与 `protected/loki.mjs.before`）；
devops 执行副本取自 Mac 工作区（含该增量与并行条目的 trivy/kyverno 工作区改动），`.git-sha` = `2cdcc95c0c74d5c55c67893b400a4216e0b1f9a7`。

## 1. 契约测试（Mac，仓库根目录）

```
node --test infra/security/manager-v2/falco-real.test.mjs infra/security/manager-v2/registry.test.mjs infra/security/manager-v2/core.test.mjs infra/security/manager-v2/runner.test.mjs infra/security/manager-v2/config.test.mjs
```
本轮 falco 相关子集 44/44（见小结回归节的完整套件数字）。

## 2. 执行副本（devops）

- 将 Mac 工作区 `infra/security` 复制到 devops `~/falco-v2-work/repo/infra/security`，仓库根写 `.git-sha`（上值）。
- 驱动脚本 `raw/falco-v2-driver.mjs` 放在副本根目录；运行目录 `~/falco-v2-work/runs/`（0700 子目录）。

## 3. 开关关态（devops 副本目录）

```
node falco-v2-driver.mjs disabled web-falco-off1 ~/falco-v2-work/runs/off1
```
期望：plugin 案 DISABLED/PLUGIN_DISABLED、master 案 DISABLED/MASTER_DISABLED，均 evaluationCount=0、policyEvaluationCounts={}。
原始结果：`raw/disabled-*.result.json` 与 verification.json 的 disabledRuns。

## 4. 受控触发（devops，正例）

```
bash raw/trigger.sh falco-v2-pos-1   # 脚本内含 Pod YAML（devsecops-test、非 root、drop ALL）
```
脚本输出 WINDOW_END_MS（本轮 1794496655180）、传感器身份前后一致（platform-falco-fwwfd / uid db37cfe6… / restarts 17）。
动作：两轮（间隔 17s）`kubectl exec sh -c 'cat /etc/passwd; cat /etc/shadow; …'`，只读测试容器自身文件，内容不记录。

## 5. 正例运行 + Router + Loki（devops 副本目录）

```
node falco-v2-driver.mjs run web-falco-pos1 falco-v2-pos-1 1794496655180 ~/falco-v2-work/runs/pos1
```
期望：COMPLETED、evaluationCount=1、detectedCount=97（其中 sh/cat 目标动作 16 条）、
Router dry-run=DRY_RUN / local-evidence=DELIVERED_LOCAL_ONLY、Loki ACKNOWLEDGED（HTTP 204、1 次请求）、
驱动内 Loki 回查 matched=1（runId/resultDigest 一致）。封存件副本：`raw/pos1-artifact/`、原始 Falco 日志切片：`raw/pos1-falco-log-slice.jsonl`（97 行）。
Grafana 复核：devops 会话内用 Grafana 管理凭据（不落文件）走 Loki 数据源代理 query_range 查同一 runId，
命中同一 eventIdentity `a27129ee…`。

## 6. 负例（devops）

删正例 Pod（命名空间 ResourceQuota pods=1）后建空闲 Pod falco-v2-neg-1（同 YAML、无 exec），等 20s 取 WINDOW_END_MS（本轮 1794496952043）：
```
node falco-v2-driver.mjs run web-falco-neg1 falco-v2-neg-1 1794496952043 ~/falco-v2-work/runs/neg1
```
期望：COMPLETED / PASS / evaluationCount=1；Shell 事件 0、sh/cat 进程事件 0（45 条均为建 Pod 秒的 runc 生命周期事件）。

## 7. 清理

```
sudo kubectl -n devsecops-test delete pod falco-v2-neg-1
sudo kubectl -n devsecops-test get pods        # 应为空
sudo kubectl get pods -n devsecops-system -l app.kubernetes.io/name=falco   # Running、restarts 不变
```

## 边界

- 未改 Falco 生产配置/规则；未动 petclinic 业务负载；未触发 Jenkins；生产 Manager NOT_ACTIVE。
- Policy 决策口径与 FAIL 缺口见 verification.json 的 policyNote 与条目小结。
