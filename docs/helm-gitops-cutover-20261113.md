# Helm + Argo CD GitOps 切换手册（定稿，2026-11-13）

> 状态：**手册定稿，生产切换未执行（PRODUCTION_SWITCH=NOT_DONE）**。本手册是唯一执行依据；执行生产切换需要用户**单独审批**（见 §6 审批点），任何人不得以本手册本身为由直接切换。
> 范围：把 Argo CD 现有 `petclinic` Application 的源从纯清单目录 `k8s/production` 切换为 Helm Chart `charts/petclinic`（values：`values-prod.yaml`）。切换前后镜像、副本、命名空间、同步策略全部不变。
> 证据基础：W10 非生产真实验证（2026-11-13，`evidence/2026-11-13/helm-gitops/`）：lint 通过、渲染与已部署基线 0 字段差异、非生产命名空间真实部署+HTTP 200、upgrade/rollback 演练通过。非生产 Argo Sync **未验证（缺口 G-H1）**：临时 App 实测报 `charts/petclinic: app path does not exist`——Chart 尚未进入 GitLab `main`（仅在本地开发分支），须先按 §6 审批点 4 把 Chart 合入 GitOps 仓库，之后在非生产侧复验 Sync 成功，才可谈生产切换。

## 0. 现状速览（2026-11-13 实测）

| 项 | 现状 |
|---|---|
| Argo Application | `petclinic`（argocd ns），Synced / Healthy；全集群 14 个 App 全 Synced/Healthy |
| 现源 | GitLab `root/petclinic-platform` `main`，path `k8s/production`，目标 ns `petclinic` |
| 同步策略 | automated，prune=false，selfHeal=true，CreateNamespace=false |
| 同步基线 | GitOps revision `340ef4b8c74e3c2a5820da8d98b0f134283bb8d9`；最近同步修订见 App status |
| 生产镜像 | `core.harbor.domain/petclinic/petclinic@sha256:489cb821573ff1f98edd846d5949d74bf3391b24e2f1fe5bcfb71c6be0793137`（集群实测，与 Chart values 一致） |
| Chart | `charts/petclinic` v0.1.0 / appVersion 0.10.0；模板全 JSON 输出；digest 强制（缺失/非法 digest 直接 fail） |
| Chart 资源 | 11 个：Deployment、Service、Ingress、ConfigMap(petclinic-config)、PDB、Grafana dashboard ConfigMap ×4、ServiceMonitor、PrometheusRule |

## 1. 前置条件（全部满足才可进入切换窗口）

1. **用户单独审批已给出**（§6），且明确了切换窗口与在场验收人。
2. 渲染等价性对**当前** GitOps revision 重新验证（不许沿用旧基线结论）：`helm lint` PASS；`helm template`（生产 values、ns=petclinic）与当前已部署期望状态结构化 diff = 0 真差异（API 默认值类差异除外，逐项记录）。W10 基线结果：vs 基线 fixture（340ef4b8）11/11 资源 **0 字段差异**；渲染 sha256 `750a998e…`，Helm 3.20.0 与钉版 3.22.1 输出一致。
3. 镜像 digest 仍是当前已部署且已批准的 digest（见 §0）。**切换不捎带换镜像**；换 digest 走独立的发布批准流程（签名 approved-release + 晋升合同，见 `docs/helm/PHASE1-SHADOW.md`），且供应链 U1/U2 未决期间不得以切换为由绕过。
4. Chart 外 3 个资源的归属已按 §2 处置并留痕。
5. 生产现状快照已拍：App spec/status、Deployment/Service/Ingress/PDB/ConfigMap 清单、Pod 名/状态/时长、EndpointSlice、HTTP 基线（`/` 与 `/actuator/health`）、Prometheus target 与 Grafana 面板可达。W10 已拍切换前快照样式见证据 `prod-snapshot-before.txt`。
6. 回滚材料就位：现源定义（`k8s/argocd/petclinic-application.yaml` 的 GitLab 实际生效版）与 `k8s/production` 全部清单保持在 Git 中不动（切换不删旧目录，至少保留一个完整发布周期）。
7. 集群健康：3 节点 Ready；devops 磁盘/内存水位正常；无进行中的 Jenkins 发布、无其他线正在动 petclinic/argocd。
8. 密钥前提不变：`petclinic-db`、`petclinic-harbor-pull` Secret 已存在于 petclinic ns（Chart 只引用不渲染，切换不碰 Secret）。

## 2. Chart 外资源处置（切换前必做）

以下 3 个资源由现 `petclinic` App 随 `k8s/production` 目录一并下发，但**不在 Chart 内**：

| 资源 | 处置 |
|---|---|
| Application `platform-alertmanager`（argocd） | 切换前确认其自身 Synced/Healthy；切换后它脱离 petclinic App 的资源树（prune=false，不会被删），改为独立存续，在切换记录中登记为「独立 Application，不再由 petclinic App 托管其定义」 |
| Application `spark-operator`（argocd） | 同上 |
| Ingress `petclinic-harbor-alias`（harbor ns） | 同上；切换后单独验证 `harbor.devops.local` 路由仍通 |

禁止：在未处置/未留痕时切换源；禁止把这 3 个资源塞进 Chart 临时凑数。

## 3. 切换步骤（逐步，每步带验证点）

> 全程只有一个控制器：现有 `petclinic` Application。**严禁** apply `infra/argocd/petclinic-helm-candidate.yaml` 或任何改名副本形成双控制器；严禁用 helm CLI 直接对 petclinic ns 执行 install/upgrade；严禁 kubectl 直接改生产工作负载。

1. **冻结**：通知窗口开始；暂停 Jenkins 对 petclinic 的 Git 晋升（或确认无晋升在途）。验证点：App 仍 Synced/Healthy，GitOps revision 不再变化。
2. **复验渲染**：按 §1.2 重跑 lint/template/diff 并存档。验证点：diff 0 真差异；不一致立即停（§5）。
3. **改源（Git 内）**：在 GitLab `petclinic-platform` 的 Git 管理定义中，把**现有** `petclinic` Application 的 `spec.source` 改为目标形态（工件：证据 `target-petclinic-helm-application.yaml`）：`path: charts/petclinic`，`helm.releaseName: petclinic`，`helm.valueFiles: [values-prod.yaml]`；repoURL/targetRevision/destination/syncPolicy **逐字不变**（prune 保持 false）。以正常提交进入 `main`。验证点：提交 diff 只含 source 段变化。
4. **预检 diff**：在 Argo UI/CLI 对该 App 做一次 refresh + diff 预览（不启用额外自动化）。验证点：预期差异仅两类——(a) Argo 跟踪/渲染元数据；(b) Deployment pod template 上 Jenkins 时代遗留注解（`devops.zhanglab.io/git-commit`、`image-tag`、`jenkins-build`、`kubectl.kubernetes.io/restartedAt`，2026-08 遗留，不在任何 GitOps 源中）被移除。出现其他差异立即停。
5. **放行同步**：让 automated sync 自然收敛（或手动 Sync 一次，prune 关闭）。验证点：同步完成无错误；App 回到 Synced。
6. **工作负载验证**：Deployment 3/3 Ready（遗留注解移除会触发**一次**正常滚动：maxSurge 0 / maxUnavailable 1，PDB minAvailable 2 全程不破）；镜像 digest 与 §0 一致；Pod 名/Ready/重启数记录。验证点：Deployment UID 不变（原地更新而非重建）；Service ClusterIP 不变、EndpointSlice 3 个就绪端点。
7. **业务与可观测验证**：`http://petclinic.devops.local/` 200、`/actuator/health` UP；Prometheus 中 petclinic target UP、ServiceMonitor/PrometheusRule 仍被拾取；4 个 Grafana dashboard ConfigMap 存在且面板可开；Loki 能查到 petclinic 新 Pod 日志；Jaeger/OTel trace 有新样本。逐项记录，不许以「Pod Ready」代替。
8. **Chart 外资源复核**：`platform-alertmanager`、`spark-operator` 两 App 仍 Synced/Healthy；`petclinic-harbor-alias` 路由通。
9. **收尾留痕**：把切换提交哈希、同步 revision、§3/§6 的验证结果写入切换记录（建议 `evidence/<日期>/helm-cutover/`）；旧 `k8s/production` 目录保留不删。

## 4. 回滚步骤

触发：§5 任一停点命中，或切换后 30 分钟内业务/可观测指标劣化。

1. 先在 Argo 中**暂停** `petclinic` App 的 automated sync（防回滚期间来回拉扯）。
2. Git 回滚：对 §3.3 的改源提交做普通 `git revert`，恢复源为 `path: k8s/production`（digest 与其余配置保持回滚前值），提交进 `main`。**Git 回退只是手段，Argo 收敛完成才算回滚完成**；不得用 `helm rollback` 作为生产恢复路径（生产从未由 helm CLI 部署，无 release 记录）。
3. 恢复 automated sync，让 Argo 收敛回纯清单源。
4. 验证回滚完成：App Synced/Healthy；Deployment 3/3 Ready 且镜像/digest 不变；Service/EndpointSlice 正常；`/` 与 `/actuator/health` 200/UP；监控/日志/追踪恢复。逐项留证。
5. 若回滚同步本身失败：保持 automated 关闭，保存 App 与资源现状，升级为人工处置（不得现场改 Chart 或直接 patch 生产工作负载绕过 Git）。

## 5. 风险与停点（命中任一立即停，回到 §4 或保持现状汇报）

- 渲染 diff 出现任何**真差异**（字段增减/取值变化，非 API 默认值类），或参与对比的基线不是当前 GitOps revision。
- digest 与已批准值不一致，或有人试图在同一切换提交里捎带改 digest/副本/资源配额等任何 values。
- selector、Service 名、ConfigMap 名、PDB 等身份字段有任何变化（有 Deployment 重建/流量切换风险）。
- Chart 外 3 资源（§2）未处置，或切换后任一相关 App 不 Healthy、harbor 路由不通。
- 双控制器迹象：出现第二个指向 petclinic ns 的 Application，或有人对生产 ns 执行 helm CLI/kubectl 直接变更。
- 切换滚动期间可用副本低于 2、EndpointSlice 就绪端点少于 2、HTTP 连续失败超过 2 分钟。
- 监控/日志/追踪任一链路在切换后丢失（ServiceMonitor、PrometheusRule、dashboard、OTel 端点）。
- 数据库相关变化：POSTGRES_URL、Secret 引用、启动初始化行为（SPRING_SQL_INIT_MODE）有任何变化。
- 已知预期内现象（不必停，但要记录）：首次同步移除 pod template 遗留注解触发一次滚动；Argo 跟踪注解变化；本地 Mac 检出目录 `k8s/production/petclinic.yaml` 中 digest（`83c2ae78…`）比线上旧——那是本地检出陈旧，不得以它为基线（见 W10 证据 render-diff）。

## 6. 所需用户审批点（缺一不可）

1. **生产切换本身**：单独审批，注明窗口与验收人。本手册与 W10 非生产验证都不构成切换授权。
2. **digest 变更（如有）**：与切换分开审批，走签名 approved-release 晋升流程；供应链 U1（Harbor 签名写路径）/U2（候选 HIGH 处置）未决前不捎带。
3. **Chart 外 3 资源的独立存续登记**：确认 platform-alertmanager、spark-operator、petclinic-harbor-alias 脱离 petclinic App 托管后独立运行的归属安排。
4. **Chart 合入 GitOps 仓库**：把 `charts/petclinic` 推进 GitLab `main` 的提交（当前 Chart 只在本地分支，未入 GitLab，Argo 无从同步——W10 缺口 G-H1，临时 App 实测 ComparisonError `app path does not exist` 已留证）。合入后先在非生产侧重跑临时 App Sync 验证（目标非生产 ns、验后删除）取得 Synced/Healthy + HTTP 200，再申请生产切换。

## 7. W10 非生产验证结论（2026-11-13，证据 `evidence/2026-11-13/helm-gitops/`）

- HELM_LINT=PASS（Mac 钉版 Helm 3.22.1 与 devops Helm 3.20.0 各一次；Chart 自带测试 43/43）。
- HELM_RENDER_EQUIVALENCE=PASS：渲染 11 资源；vs 已部署基线 fixture（GitOps 340ef4b8）0 字段差异；vs 集群 live spec 差异仅 API 默认值 + pod template 遗留注解；渲染 sha256 `750a998e7fc32cb61c11fb2763ad870ee0b9f5c92895b8aae544f1a901c4d3f3` 三方一致（历史影子 / Mac 钉版 / devops 版）。
- HELM_DEPLOY_NONPROD=PASS：新命名空间 `helm-verify` 真实部署 1 副本，Pod Ready，Service ClusterIP 可达，`/` 200（PetClinic 首页）、`/actuator/health` 200 UP。
- HELM_ROLLBACK=PASS：upgrade 副本 1→2（revision 2）→ `helm rollback` 至 revision 1（生成 revision 3），副本恢复 1、HTTP 复检 200。
- ARGO_SYNC_NONPROD=NOT_VERIFIED（缺口 G-H1，见 §6.4）；临时 App 与两个测试命名空间均已删除并复查 NotFound。
- PRODUCTION_SWITCH=NOT_DONE；PRODUCTION_WORKLOAD_CHANGED=NO（切换前后生产 Pod 名/IP/重启数、Deployment 3/3、Service ClusterIP 快照一致；生产 App 源仍为 `k8s/production`）。
