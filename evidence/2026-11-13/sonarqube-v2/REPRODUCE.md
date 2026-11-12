# 复现步骤 · SonarQube V2 真实执行闭环（条目 1c，2026-11-13）

仓库分支 `fix/security-manager-plugin-switches`；代码提交见小结（feat 提交 + 本证据提交）。
共享文件 `consumers/loki.mjs` 有一处未提交最小增量（singlePluginId 白名单加 `sonarqube`；同行还含他人 trivy/falco/kyverno 增量，不可分，故不提交，原文快照在 `protected-before/`）。其余共享增量（registry.mjs、core.mjs、consumers/loki-event-v1.json）经核为纯 Sonar 增量，已随 feat 提交。

## 0. 执行面（devops，root-owned）
- 受限用户 `security-sonar`（uid 1003 / gid 982，home `/var/lib/security-sonar`，`restrict,command="setpriv --no-new-privs python3 entry.py"`）。
- `entry.py`（根所有）：只接受 `gate-v1 <projectId> <runId:web-uuid> <caseId>`；项目/用例/工具/服务器版本全钉死在根所有 `projects.json`；令牌只读 `/var/lib/security-sonar/sonar-token`（0600，security-sonar 所有；来源 = Jenkins 凭据 `sonar-token`，经一次性 Jenkins 副本自解密取得，值从未打印/落仓）。
- 工具：sonar-scanner-cli 7.2.0.5079 linux-aarch64（官方 zip sha256 803ca725…，钉死 jar sha256 74cb8498…）；服务器 SonarQube 26.3.0.120487（ns sonarqube，NodePort 30085，wrapper 经 127.0.0.1:30085 访问）。
- Mac 侧：`~/.ssh/security-manager-v2-sonar` 密钥 + `.devsecops/security-view-sonar-linux-v1.json` 武装文件（enabled=true, consumed=false）。

## 1. 契约测试（Mac，仓库根目录）
```
node --test infra/security/manager-v2/sonar-real.test.mjs   # 9/9
node --test infra/security/manager-v2/config.test.mjs infra/security/manager-v2/registry.test.mjs infra/security/manager-v2/core.test.mjs infra/security/manager-v2/runner.test.mjs infra/security/manager-v2/integration.test.mjs infra/security/manager-v2/trivy-real.test.mjs infra/security/manager-v2/falco-real.test.mjs infra/security/manager-v2/kyverno-real.test.mjs infra/security/manager-v2/sonar-real.test.mjs infra/security/manager-v2/view/origins.test.mjs infra/security/manager-v2/view/mac-budget.test.mjs infra/security/manager-v2/view/loki-delivery.test.mjs infra/security/manager-v2/observability/queries.test.mjs
node --test infra/security/*.test.mjs infra/observability/*.test.mjs   # 147/147
```
期望：第一组 108 中 107 过 + 1 个既有 EEXIST（queries 套件与工作树未跟踪目录 logql-contract-samples 碰撞，挪开后 20/20，详见 verification.json）；第二组 147/147。consumers 套件 114/162，48 败为既有基线（对照实验：换回 protected-before 的 loki 两文件结果不变）。

## 2. 全套真实运行（Mac）
```
node evidence/2026-11-13/sonarqube-v2/run-driver.mjs
```
期望（本轮实测，runId 见 core-driver-summary.json）：
- clean-scan（sonarqube-petclinic → smv2-clean 真实扫描）：COMPLETED / PASS，gate=OK，oldGate=PASS。
- violating-scan（每轮全新 componentKey smv2-gatelab-<runId 前 8 位>，先 clean 基线扫、再 violating 扫）：COMPLETED / FAIL，gate=ERROR（new_violations>0），oldGate=FAIL。
- cleanroom-scan（sonarqube-cleanroom → smv2-clean）：COMPLETED / PASS。
- plugin-off / master-off：DISABLED、evaluationCount=0、零 SSH。
- 跨项目：目标错配与用例泄漏各 1 次，均在本地以 SONAR_PROJECT_NOT_AUTHORIZED 拒绝（零 SSH）。
- Router：每轮 dry-run + local-evidence 回执（见 summary 的 router 字段）。
- Loki：clean-scan 与 violating-scan 两轮经 view/loki-delivery 真实投递 DELIVERED + 回查 VERIFIED。

## 3. Grafana 回查（需 Mac GUI 会话）
```
node evidence/2026-11-13/sonarqube-v2/grafana-check.mjs <runId> <resultDigest> <caseId> evidence/2026-11-13/sonarqube-v2/raw/grafana-loki-<caseId>.json
```
本轮在 SSH 会话内因钥匙串 ACL 无法取 Grafana 令牌（exit 36），未验，记 G-S2；Loki 本体已由第 2 步的授权通道回查 VERIFIED（同一数据）。

## 4. 已知设计事实
- petclinic 项目本身：服务器质量门 OK（raw/petclinic-inventory.json），但 Jenkins 令牌用户不管理该项目，CE 端点 403，无法取得 task 绑定，故 runner 用例使用该令牌自建自有的候选项目（smv2-*），petclinic 仅作盘点证据（G-S3）。
- 负例每轮换新 componentKey：Sonar 议题追踪会把同路径同内容的老议题判为非新增（new_violations=0），且令牌无项目删除权（403）；新 key 等效新项目，保证 ERROR 可复现。服务器上会累积每轮一个 smv2-gatelab-* 小项目（1 文件），待有管理权后可清理。
