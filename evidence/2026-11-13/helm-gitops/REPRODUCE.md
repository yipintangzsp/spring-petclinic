# W10 Helm+GitOps 证据复现说明（2026-11-13）

环境：Mac 仓库 `~/code/petclinic-platform-20261011`（分支 fix/security-manager-plugin-switches，HEAD 48c1a52a）；集群在 devops k3s（经 `devssh.sh`/`macssh.sh` 固化通道，批量合并会话）。生产 ns `petclinic` 全程只读；集群写操作仅限新建的 `helm-verify`、`helm-argo-verify` 两个命名空间与临时 App `petclinic-helm-verify`，已全部清理。

## 1. Lint / Template / 等价性

```sh
# Mac（仓库钉版 Helm 3.22.1，.tools/helm/v3.22.1/darwin-arm64/helm）
helm lint charts/petclinic -f charts/petclinic/values-prod.yaml -n petclinic
helm template petclinic charts/petclinic -f charts/petclinic/values-prod.yaml -n petclinic
#   -> rendered-prod.yaml, sha256 750a998e7fc32cb61c11fb2763ad870ee0b9f5c92895b8aae544f1a901c4d3f3
# devops（系统 Helm 3.20.0）同命令同 sha256；且与 Phase1 影子 renderedSha256 三方一致。
# Chart 合约测试（Mac, node v25）：
node --test infra/helm/chart.test.mjs infra/helm/pipeline-contract.test.mjs   # 43/43 pass

# 结构化 diff（本目录 diff_render.py，需 PyYAML）：
python3 diff_render.py
#   rendered vs infra/helm/baseline/current-desired.json : 11 vs 11, 0 字段差异
#   rendered vs k8s/production/*.yaml                    : 11 vs 14, 1 字段差异(本地检出陈旧 digest)
#                                                          + 3 个 chart 外资源(2 Application + harbor alias Ingress)
# live spec 对照：live-vs-rendered.txt（sudo kubectl get -o json 抽 spec 后本地比对，仅默认值/遗留注解差异）
```

## 2. 非生产真实部署（脚本原件：deploy-nonprod.sh / wait-http.sh）

```sh
# devops 上，chart 由 Mac tar 流经本地管道送至 /tmp/w10/charts（验后已删）
kubectl create namespace helm-verify
# petclinic-db / petclinic-harbor-pull 以 kubectl get -o json | jq del(metadata...) | kubectl apply
# 服务端管道复制到 helm-verify（值从未打印/落文件）
helm install petclinic /tmp/w10/charts/petclinic -n helm-verify \
  -f values-prod.yaml -f values-nonprod.yaml --wait --timeout 6m
# values-nonprod.yaml: replicaCount=1, ingress.enabled=false, monitoring.enabled=false, pdb.minAvailable=0
kubectl wait deployment/petclinic -n helm-verify --for=condition=Available --timeout=240s
curl http://<svc ClusterIP>/actuator/health   # 200 UP（从 devops 主机直连 ClusterIP）
curl http://<svc ClusterIP>/                  # 200 PetClinic 首页
```

注：devops helm 3.20.0 的 `--wait` 两次在 Pod 真正 Ready 前返回（G-H3），就绪以 kubectl 状态 + HTTP 重试结果为准（wait-http.log）。

## 3. 回滚演练（upgrade-rollback.sh）

```sh
helm upgrade petclinic <chart> -n helm-verify -f values-prod.yaml -f values-nonprod.yaml --set replicaCount=2   # revision 2
helm rollback petclinic 1 -n helm-verify --wait                                                              # revision 3, replicas 回 1
helm history petclinic -n helm-verify
curl /actuator/health  # 200 UP
```

## 4. 非生产 Argo Sync 尝试（argo-test.sh）

临时 Application `petclinic-helm-verify`（argo-helm-verify-app.yaml）：源 GitLab main `charts/petclinic` + helm 参数（1 副本/关 ingress/关 monitoring/PDB 0），目标 ns `helm-argo-verify`。240s 轮询结果 ComparisonError：`charts/petclinic: app path does not exist`（G-H1：Chart 未入 GitLab main）。验后删除 App 与 ns。

## 5. 清理与生产未动复查（cleanup.sh / prod-snapshot-*.txt）

```sh
kubectl delete application petclinic-helm-verify -n argocd   # 复查 NotFound
helm uninstall petclinic -n helm-verify
kubectl delete namespace helm-verify helm-argo-verify        # 复查 NotFound
kubectl get applications -n argocd                            # 14 个 Synced/Healthy，petclinic 源仍 k8s/production
```

证据文件清单：verification.json、inventory.md、rendered-prod.yaml、render-diff.json、live-vs-rendered.txt、live-{deploy,svc,pdb}-spec.json、lint-template 日志（mac/devops）、mac-chart-tests.txt、deploy-nonprod.log、wait-http.log、upgrade-rollback.log、argo-test.log、argo-helm-verify-app.yaml、target-petclinic-helm-application.yaml（目标生产 App，未 apply）、values-nonprod.yaml、prod-snapshot-before/after.txt、cleanup.log、全部执行脚本原件。任何文件均不含 Secret 值（POSTGRES_URL 为仓库已提交的 JDBC 配置串、密码走 Secret 引用，未出现在证据中）。
