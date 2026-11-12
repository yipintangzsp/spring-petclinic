# W10 盘点（条目 3：Helm + Argo CD GitOps，2026-11-13 实测）

## Chart 结构与 values 分层

- 位置：`charts/petclinic/`（仓库内唯一 Chart）。Chart.yaml：apiVersion v2、name `petclinic`、version 0.1.0、appVersion `0.10.0`，描述自称 “GitOps shadow representation; no production cutover”。
- 模板（7 个，全部用 `toPrettyJson` 输出 JSON 文档）：deployment、service、ingress、configmap、pdb、observability、_helpers.tpl。`_helpers` 强制镜像必须为 `repository@sha256:<64hex>` digest，缺失/非法直接 `fail`——digest 是唯一部署信任输入，tag/appVersion 不是。
- observability 模板：`monitoring.enabled=true` 时把 `files/observability.json`（90 KB，6 个对象）逐个改 ns 后输出：Grafana dashboard ConfigMap ×3＋release-analysis 共 4 个 CM（grafana/metrics/v09/release-analysis）、ServiceMonitor、PrometheusRule。
- values 分层：`values.yaml`（全量默认＝当前 GitOps 快照：3 副本、镜像 digest `489cb821…`、完整 env/探针/资源/安全上下文/nodeSelector=devops/toleration cloud/topologySpread/PDB minAvailable 2/ingress traefik+host petclinic.devops.local/monitoring on）＋ `values-prod.yaml`（SHADOW ONLY，只覆盖同一 digest，注释要求未来更新须有签名 approved-release 证据）＋ `values.schema.json`（JSON Schema：name 恒为 petclinic、digest 正则、serviceAccount.create 恒 false 等）。
- 影子历史：`docs/helm/PHASE1-SHADOW.md`、`docs/helm/FUTURE-CUTOVER.md`、`infra/helm/`（钉版 Helm 3.22.1 工具链、baseline fixture、chart/pipeline 合约测试、direct-deploy guard）。Phase 1 结论：影子校验 PASS、生产仍走纯清单；candidate Application（`infra/argocd/petclinic-helm-candidate.yaml`）标 NOT_ACTIVE/VALIDATION_ONLY，**不得作为第二控制器 apply**。

## 当前生产清单（k8s/production，本地检出）

- 14 个资源：petclinic.yaml（Deployment+Service+Ingress）、petclinic-configmap、petclinic-pdb、ServiceMonitor、PrometheusRule、dashboard CM ×4、petclinic-harbor-alias（Ingress/harbor，JSON 形态）、alertmanager-application 与 spark-operator-application（两个 Application CR，app-of-apps）。
- **本地检出陈旧**：本地 `petclinic.yaml` 镜像 digest 为 `83c2ae78…`，线上与基线均为 `489cb821…`（Phase1 文档已警告本地检出不是基线）。本线 diff 以三方为准：基线 fixture / 集群 live / 本地目录，结论见 verification.json。

## Argo CD 现状（只读入口实测）

- argocd ns 共 **14 个 Application，全 Synced/Healthy**：airflow、cook、devops-tls-lab、hello-app-dev、petclinic、petclinic-gitops-demo、platform-alertmanager、platform-cert-manager、platform-devsecops、platform-messaging、platform-rabbitmq、platform-rollouts、rollouts-lab、spark-operator。
- 生产 `petclinic` App：live spec 源为 GitLab 内网 `http://gitlab-service.ns-devops.svc.cluster.local/root/petclinic-platform.git` `main` + path `k8s/production`（仓库内 GitHub 版定义文件与 live 的 repoURL 不一致，以 live 为准），dest ns `petclinic`，automated prune=false/selfHeal=true，CreateNamespace=false；同步 revision `340ef4b8…`，Healthy。
- Chart 只存在于本地未 push 分支 `fix/security-manager-plugin-switches`（HEAD 48c1a52a）；GitLab `main` 无 `charts/petclinic`——临时非生产 App 实测 ComparisonError 留证（缺口 G-H1）。

## 集群前提（非生产部署用）

- 节点 3 台 Ready（devops 控制面 + aliyun/ucloud worker，k3s v1.36.1）；Chart nodeSelector 把 Pod 钉在 devops（镜像已在该节点缓存、与生产同 digest）。
- petclinic ns 既有 Secret（仅名）：`petclinic-db`、`petclinic-harbor-pull`、`rabbitmq-client`；Chart 只引用前两者，不渲染任何 Secret。
- 非生产命名空间决策：不用既有 `devsecops-test`（有 petclinic-gitops-demo App 在管，避免相互干扰），新建专用 `helm-verify` / `helm-argo-verify`，验后整 ns 删除。
