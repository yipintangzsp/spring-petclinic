# PetClinic 故障演练与发布回退

## 安全边界

生产 namespace 为 petclinic；共享 PostgreSQL 在 ns-data。本轮主动注入仅使用新建、无业务数据的 petclinic-drills-20261005 namespace。Pod 不启动应用、不引用数据库 Secret、不创建 Service/Ingress/PVC、不挂载 API token；只复用当前已发布镜像的 shell。配额最多两个 Pod、64Mi memory requests/128Mi memory limits；每次仅一个 Pod。Pending 场景的超大 CPU request 无法调度，不会真正分配 CPU。

执行：`python3 infra/observability/run-isolated-drills.py evidence/2026-10-05/drills.json`。脚本拒绝复用已存在的演练 namespace；真实确认失败状态后修复，再等 Ready，保存状态与事件。finally 只清理脚本创建且 owner label 符合的临时 namespace。不要把这些故障注入步骤改为生产 namespace。

## 本轮四个场景

| 场景 | 现象与根因 | 排查 | 修复 | 验证 |
|---|---|---|---|---|
| ImagePullBackOff | 本地 Registry 中故意使用不存在的 tag | Pod waiting reason；events 的 pull 错误；核对 Registry manifest、平台架构和 tag | JSON patch 仅将 image 恢复为当前生产镜像 | Pod Ready、镜像版本正确 |
| CrashLoopBackOff | shell 主动 exit 42，触发 restart backoff | 核对 lastState.terminated.exitCode、restartCount 和 BackOff 事件；本次摘要长期显示 Error，不能只等待 waiting 字符串；应用事故还需 logs --previous | 删除本轮临时 Pod 后以正常 sleep 命令重建 | Ready，进程保持运行；不是通过放宽探针掩盖崩溃 |
| Readiness failure | exec 探针检查不存在的 /tmp/drill-ready | 必须观察到真实 Unhealthy / Readiness probe failed，不能把刚启动时 Ready=false 当故障 | 在本轮 Pod 创建该文件，保留同一个 Pod 和探针 | 同一 Pod Ready=true，不发生 liveness 重启 |
| Pending | devops 的 CPU request 10000 核超过容量 | PodScheduled=False / Unschedulable，events 中 Insufficient cpu | 仅重建本轮 Pod，将 requests 恢复 10m | 调度到 devops 且 Ready |

这些验证展示 Kubernetes 调度、镜像、容器退出和探针机制，不等于生产应用数据库故障或完整 HTTP 压测。结果以 drills.json 为准；没有证据的场景不标为演练成功。

## 后续场景排障手册（尚未主动注入）

以下命令为只读排查。服务器使用 `sudo -n k3s kubectl`；仅在确认当前 kube context 后使用 kubectl。不要改全局 DNS、删除数据库/PVC，或强制 drain 共享 devops。

| 场景 | 观察与排查 | 根因候选、修复边界 | 验证 |
|---|---|---|---|
| OOMKilled | get pod JSON 的 lastState；logs --previous；top pod；Grafana working set/request/limit、JVM/GC | 区分容器 limit OOM 与节点全局 OOM。检查 JVM heap/native memory/线程/上下文缓存；在独立容器验证后调整该应用预算，不直接扩建全平台 | 无新增 OOM/restart，工作集有余量，延迟恢复 |
| DNS failure | Pod events、现有 Pod 内解析 postgresql.ns-data.svc.cluster.local；CoreDNS logs、Service 和 EndpointSlice | 区分应用名称错误、CoreDNS readiness、云隧道。先修应用地址；共享 DNS 改动进入风险评估 | 应用依赖域名恢复解析与连接；其他业务 DNS 正常 |
| Service 无 Endpoint | get svc petclinic -o yaml；get endpointslice -l kubernetes.io/service-name=petclinic；get pods --show-labels | selector 不匹配或所有 Pod 未就绪；通过 Git 修 PetClinic selector/probe，不靠手填 Endpoint | ready endpoints 存在、Ingress 返回 200 |
| 数据库连接失败 | health、Hikari 日志、postgresql Service/EndpointSlice、数据库 Pod Ready；只核对 Secret key 是否存在 | 地址、认证、连接池、数据库可用性。凭据只能在安全通道校验；不在控制台输出、不重置业务数据 | health UP，业务读回与聚合计数正确，错误日志停止 |
| 节点资源不足 | top nodes/pods、describe node Allocated resources/MemoryPressure、宿主 free/vmstat | requests 低估、构建/DB 容器峰值、CPU/IO/换页争用。先应用预算和构建串行；跨业务变更先分析风险 | 无 Pressure、调度成功、API latency/业务延迟正常 |
| Loki 日志缺失 | Alloy DaemonSet 与 devops 实例日志；Loki readiness；查询 app/namespace stream；检查 namespace/app label | 节点发现、Pod 日志权限、Loki 推送、查询时间范围。只改 PetClinic relabel/查询，保留其他采集链路 | 产生一个无身份字段的正常 GET，Loki 看到该路由的近期记录 |
| Prometheus target down | /api/v1/targets 的 lastError；ServiceMonitor selector/port/path；Service EndpointSlice | 端口、探针、标签、采集权限或网络。保持 /actuator/prometheus，仅修该服务的声明 | 三 target up、最近 scrape 成功，真实指标有样本 |

## 发布失败与 GitOps 回退

Git 是部署权威。先区分镜像构建失败、Git promotion 未发生、Argo ComparisonError、镜像 pull/启动失败、readiness 失败、业务健康失败。构建失败且未晋级时不回滚现有健康生产版本。Argo Synced 只说明声明一致，还必须验证 Healthy、实际 Pod 镜像和 HTTP。

1. 记录当前 main SHA、生产镜像/env、Argo revision 与 conditions、Pod events/logs、数据库只读计数。
2. 查 `git log -- k8s/production/petclinic.yaml`，选择已验收的发布；不要猜 tag，也不要使用 latest。
3. 回退本轮配置可普通 `git revert <配置提交>`。回退应用发行版本则仅从已验收提交恢复 petclinic.yaml，检查 diff 中 image 与 APPLICATION_VERSION/BUILD_GIT_COMMIT/BUILD_NUMBER/BUILD_TIME 同步恢复；确认远端 main 未被并发发布改变后普通提交推送。不使用 force push。
4. 先服务端 dry-run 校验，再经 Argo 同步，运行 watch-release.py <真实目标提交SHA> <证据JSON>；它有 600 秒期限并持续检查 HTTP 200/至少三个 Available 副本。
5. rollout 收敛后运行 audit-production.py 和 verify-production.py，核对健康、日志、监控、版本与业务计数。回退不会删除数据，不修改 schema/PVC。

PDB minAvailable=2 保护 Eviction API 的自愿维护操作，不约束 Deployment 滚动替换。当前全部副本在 devops，完整 drain 会被阻挡，禁止通过删 PDB 来假装完成 HA。

自动回滚尚未实现；本轮也没有主动倒退生产发行版本。需要先验证并发 promotion、源码 freshness、Argo selfHeal 和数据兼容性，再实现有边界的自动 Git 回退。Blue/Green、Canary、HPA 和跨节点硬反亲和留待容量/网络验收，不因组件名称增加而宣称生产成熟。
