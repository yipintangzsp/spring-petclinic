# Kubescape V2 真实执行闭环 — 复现与处置说明（2026-11-13，W3）

## 结论形状
- Registry：`realKubescapeRegistry()`（registry.mjs）把 kubescape 切到 `kubescape-real` / REAL_VALIDATION / `kubescape-native/v1` / policyAdapter `kubescape` / timeout 1500000；默认 registry 仍 blocked/PREFLIGHT_ONLY（单测断言）。
- Runner：`kubescape-real.mjs` 经受限 SSH（`security-kubescape@192.168.1.58`，Mac 钥 `~/.ssh/security-manager-v2-kubescape` 0600，武装文件 `.devsecops/security-view-kubescape-linux-v1.json` enabled 未 consumed，与 kyverno/sonar 惯例一致）调用 forced-command 入口 `audit-v1 <project> <runId> <caseId>`。
- 入口（devops，root 所有 0444：`/var/lib/security-kubescape/entry.py` + `entry-projects.json`）：专用用户 security-kubescape（uid/gid 1005，setpriv --no-new-privs）；每轮先验 kubectl/二进制/4 个离线 artifact/治理源码 SHA-256 与资源预算，再以专用 SA（devsecops-system/security-kubescape）取得外层 platform-heavy Lease（data-infra；已存在他人 Lease 时拒绝），在隔离工作目录中以被动观察器 `kubescape-observer.mjs` 原样执行冻结治理脚本 `infra/security/governance/kubescape.mjs`（NSA/CIS × cluster/yaml 共 4 扫描，顺序与冻结基线绑定一致），最后释放 Lease 并核验清理。
- 工具钉死：Kubescape 4.0.17（tools-lock.json kubescape 段）；二进制与 artifact 从 `/var/jenkins_home/platform-security/kubescape/4.0.17/` 逐字节复制到入口目录 `/var/lib/security-kubescape/tools/4.0.17/`（artifacts 目录原权限 0700 zhang 不可直读），每轮按 SHA-256 复验；治理脚本读取的 tools-lock 副本仅 path/artifactRoot 两字段指向该本地副本，version/sha256/artifacts 与仓库锁逐项一致（runner 校验）。
- SA 权限（本轮新建，均为平台安全自有命名空间内的最小授权）：data-infra 内 Lease platform-heavy 的 get/create/delete；devsecops-system 内 get configmap kube-root-ca.crt、create token 仅限 kubescape-readonly；kubescape-v2-test 内 deployments/pods。can-i 实测：list secrets = no；token 创建实测通过（60s 时长被 API 拒绝属时长校验非权限）。
- 令牌处置：治理流程创建的 30 分钟 kubescape-readonly Token 在观察包离开 devops 前由入口替换为其 SHA-256（`REDACTED_SHA256:<hex>`）；冻结 adapter 只校验该命令成功且输出非空，语义不变。任何凭据值未进工件/日志/证据。
- Policy：冻结 `kubescape-parent.mjs` 未动。其 AUDIT 口径：执行完整性全过 → PASS（findings 以 auditDisposition=WARN 呈现）；完整性被篡改 → FAIL（单测以二进制哈希篡改证明）。runner 的 oldDecision 与 Core 单次求值在 3 个真实案全一致。
- 负例口径（缺口 G-K1）：违规 Deployment（特权容器 + 无资源限制，镜像为既有钉死 falco 摘要）在隔离命名空间 kubescape-v2-test 内被真实检出——NSA C-0057（特权，High）、C-0046（资源限制，High）等共 11 条 resource-control findings 落在该 Deployment 上，集群 findings 1274 → 1285；但冻结 AUDIT adapter 不以 findings 判 FAIL，故 Policy 决策仍为 PASS/WARN disposition。要让 findings 判 FAIL 须用户拍板改冻结口径或新增 enforce adapter（与 Falco G-F1 同类），本轮不擅动冻结引擎。

## 运行（Mac 仓库根目录，node v24.14.0）
```
node evidence/2026-11-13/kubescape-v2/run-driver.mjs   # 3 执行案 + 2 关态 + 2 跨项目 + 前 2 案 Loki 投递
```
- 工件：`.devsecops/kubescape-runs/<runId>/artifact`（artifactStore 封存）；证据副本在 `raw/<caseId>-<projectId>/`（result/runtime-facts/summary；raw 原生包体量大，只留在工件目录）。
- Loki：driver 对 cluster-audit 与 violating-workload 两案在完成后立即 `deliverRunToLoki`（view/loki-delivery.mjs 授权通道），均 DELIVERED + query VERIFIED。
- Grafana：`grafana-check.sh`（本目录副本）在 devops 会话内运行：凭据只从 k8s secret `monitoring/kube-stack-grafana` 会话内取用，经 NodePort 30084 的 datasource proxy query_range 回查；两案 matched=1、eventIdentity 与 Loki 投递一致；原件 `raw/grafana-loki-*.json`（两端 sha256 对验一致）。

## 回归（Mac 实树，含他人未提交改动）
- kubescape-real.test.mjs：8/8。
- manager-v2 契约集（顶层 *.test.mjs + view/loki-delivery.test.mjs）：改前 142/142（13 文件，基线时点）→ 改后 157/157（15 文件：新增 kubescape-real 8 + 并行 W4 线 zap 文件 7；基线 13 个文件的计数在改后全部复现），零失败。原件 raw/regression-before.txt / raw/regression-after.txt。
- infra/security + observability 顶层：147/147（与基线逐数一致）。
- consumers：114 过 / 48 败，与基线逐数一致（LOKI_TIMESTAMP_OUTSIDE_WINDOW 夹具老化等既有基线类，零条涉及 kubescape）。

## 共享文件处置
- 已提交（本条目新文件）：kubescape-real.mjs、kubescape-real.test.mjs、kubescape/{projects.json, runner.json, entry.py, entry-projects.json}。
- 未提交（有意，共享行纠缠）：下列共享文件的本轮增量均已实测生效，但与并行 W4（ZAP）线在同一行/同一文件交织，按 Falco/Sonar 先例留工作区，待整合时点名：
  - registry.mjs：本轮增量 = realKubescape 谓词一行、real 成员 `||realKubescape`、超时上限表达式 `realKubescape?1500000` 一段、文件尾 realKubescapeRegistry 函数；W4 的 realZap 谓词/realZapRegistry 与超时段同行相邻。
  - core.mjs：本轮增量 = import 一行 + 分发长行中 `kubescape-real` 一支；W4 的 zap-real import 与分发支在同一长行。
  - consumers/loki-event-v1.json：plugins 一行内本轮 +`"kubescape"` 一个 token（W4 同行 +`"zap"`）。
  - consumers/loki.mjs：singlePluginId 白名单一行内本轮 +`'kubescape'` 一个 token（该行另含他人 falco/kyverno/sonarqube/zap token 与 trivy counts 块）。
  - 改前快照在 protected-before/（core.mjs、registry.mjs、loki.mjs、loki-event-v1.json，均为本轮动手前的工作区状态）。
- view/*：未触碰（Kyverno/Sonar 未提交增量在其中，UI 接线缺口 G-K2：kubescapeUiCase 已备，映射 clean→cluster-audit、controlled-finding→violating-workload，超时需 1500s 级）。

## 清理与现状
- 违规 Deployment：每轮入口内删除并 verifiedGone；kubescape-v2-test 经核为空后于本条目收尾删除（kubectl delete ns --wait=true，复查 NotFound）；platform-heavy Lease 复查不存在；生产 petclinic 4 Pod Running 未动。
- devops 入口基础设施保留待后续轮次复用：用户 security-kubescape、SA 与三处 Role/Binding（Lease 角色、Token 角色；测试命名空间内 Role 随命名空间删除）、工具副本、源码副本、kubeconfig（0600）。临时候选目录 /tmp/kb-install、/tmp/kb-*.sh 已留在 devops /tmp（临时区，可弃）。
- 生产 Manager NOT_ACTIVE；未 push；未触发 Jenkins；Harbor 未写。
