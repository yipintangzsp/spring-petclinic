# Terraform 执行隔离验收 · 2026-10-25

> 以下为CI197历史验收。当前安全运行镜像已由完整CI200及独立复验接续，真实漏洞0、误报1、原始1；当前版本、摘要、资源政策及重跑方式见[2026-10-26记录](TERRAFORM-VULNERABILITY-ZERO-20261026.md)。

**完整流水线 #197 SUCCESS，随后独立串行复验通过，执行隔离本轮已完成。** 此结论替代此前“验收中”记录。源码 `30e3b6ce242345246010b37bdb9e31c2fca4ecc3`；GitOps晋升 `acb658cfaf76c2a5b8b1d9669026f80b5cc7e09e`。不是只重跑末尾阶段：GitLab来源、86项Node、16项隔离Python、104项Java、41项消息Python、Sonar、双架构构建、Harbor、Argo、健康、RabbitMQ/Kafka及新增三个Terraform阶段均经过本轮完整流水线。

- [Jenkins #197](http://192.168.64.11:30659/job/petclinic-ci/197/)；在Artifacts查看 `target/platform/terraform-runtime.json`、`terraform-isolated-plan.json`、`terraform-isolated-shared.json`、`terraform-isolated-recovery.json`。
- 应用镜像 `core.harbor.domain/petclinic/petclinic@sha256:78b4f07244b6ccccd44a79c850480e2eb2bb75805e04d5493b397ce40b82ad38`。
- 隔离运行镜像 `127.0.0.1:30050/petclinic/terraform-runner@sha256:9906ee61cad5ffa96532e285b005397d4ad89b2a5e63011f9eebe2ac40ebf28e`，native ARM64、Terraform1.17.0、Kubernetes provider2.38.0，固定摘要、离线provider，不重复安装集群或工具。
- 私有证据目录 `/Users/zhangsir/code/evidence/platform-20261011/terraform-isolation-20261025`；独立复验 `replay-20261025T112852`；最终状态审计 `final-audit.json`。私有完整日志保留在各报告的 `private_logs`，脱敏报告保存日志SHA256。

## 已实际验证的行为

Jenkins只构建、扫描、引导受控配置并通过受限编排身份提交Job。Terraform在 `terraform-execution` 临时Job内执行；旧宿主/Jenkins引擎入口拒绝执行，CI190私有重放入口亦已停用，原脚本及SHA保留。

运行用户65532:65532、只读根、无能力、禁止提权、AppArmor与两层seccomp、Landlock ABI8。没有Jenkins目录、Docker/containerd socket、hostPath、PVC、管理员kubeconfig、默认SA token或服务凭据环境。只读投射身份有效期600秒。网络仅允许API的10.0.0.3:6443，禁止DNS/UDP/raw/vsock/io_uring；22/8080/443/3306实际内核拒绝。访问Jenkins同端口canary需真实ICMP type3/code3拒绝，不能用服务未启动的TCP拒绝充数。读取令牌和启动Terraform前等待CNI拒绝屏障，最多15秒，未就绪则失败。

编排身份不能读状态Secret或exec；运行身份只能管理演示ConfigMap及指定后端命名空间状态/锁，不能创建Pod/Job/Namespace。原运行身份读状态403；越界读真实403。10类非法Job（管理员身份、hostNetwork/hostPath、可写根、可变镜像、入口/lifecycle替换、token终止消息路径、特权、Secret环境）实际server dry-run403，合法请求201；旧RoleBinding恢复被准入拒绝。三组策略fail-closed且编译无警告。

共享状态真实执行A客户端持锁写入、B客户端锁竞争失败exit1、释放后B重试exit0、最终重复计划exit0；只增加/删除虚拟coordination_probe，真实ConfigMap不替换。第二轮重复执行后仍只有一个真实ConfigMap，无重复业务写入。

每轮recovery为受控失败exit42（状态写入前）→真实计划重试exit0→60秒Job期限超时。正常Job180秒、backoffLimit0；外层阶段8分钟。超时必须有实际Failed/DeadlineExceeded和HOLD_READY日志，不伪造退出码；Pod已被期限控制器删除时，只允许此前观察到同Job拥有者、同Pod UID、固定镜像及日志的缓存证据，未知退出码记null。日志接口204/启动暂态有界重试，401/403立即失败，最终缺日志或业务报告仍失败。删除Job带UID前提及Foreground，只清本轮拥有资源。

## 本轮Job及时间记录

|轮次|Job|Job UID|开始 UTC|完成 UTC / 终态|退出码|回收|
|---|---|---|---|---|---|---|
|CI197|tf-197-plan-eda39bda|ee07b79f-9c85-4968-838c-4f82bf1fc71c|2026-10-25T11:25:16Z|2026-10-25T11:25:25Z|0|True|
|CI197|tf-197-shared-1d8dc203|16486b60-6c60-4b68-82fd-5741f8e6d01a|2026-10-25T11:25:33Z|2026-10-25T11:25:58Z|0|True|
|CI197|tf-197-failure-9e02f8af|b98093ee-e07c-4446-ba8b-f76f222ce31d|2026-10-25T11:26:11Z|2026-10-25T11:26:15Z BackoffLimitExceeded|42|True|
|CI197|tf-197-plan-9e02f8af|d11e86d7-5c09-414f-a9e2-de514c2d51af|2026-10-25T11:26:17Z|2026-10-25T11:26:22Z|0|True|
|CI197|tf-197-deadline-9e02f8af|978cef7b-d99d-497f-9c72-10e61a67db62|2026-10-25T11:26:23Z|2026-10-25T11:27:24Z DeadlineExceeded|None|True|
|独立复验|tf-197-plan-7b47078c|319c096a-2e7b-48aa-8aff-57067f8a7c10|2026-10-25T11:29:05Z|2026-10-25T11:29:11Z|0|True|
|独立复验|tf-197-shared-f6ec8e97|cdbdf9ee-9f60-4cac-971b-4ff9a06a02e7|2026-10-25T11:29:19Z|2026-10-25T11:29:42Z|0|True|
|独立复验|tf-197-failure-5d370248|7518f5ec-9135-4021-a2d7-8657be7c6eaf|2026-10-25T11:29:50Z|2026-10-25T11:29:55Z BackoffLimitExceeded|42|True|
|独立复验|tf-197-plan-5d370248|a807ccba-82c5-4803-9e2c-40a6b4ede68e|2026-10-25T11:29:56Z|2026-10-25T11:30:02Z|0|True|
|独立复验|tf-197-deadline-5d370248|a3a24a75-b96e-4b56-ad06-3daeed29d7cb|2026-10-25T11:30:05Z|2026-10-25T11:31:06Z DeadlineExceeded|None|True|

全部Job/Pod已回收；最终审计确认Jenkins恢复非quiet、platform-heavy未持有、后端Lease holder为空。各Job的Pod UID、镜像ID、CPU计数、日志摘要、准入证据在上述JSON报告中。

## 状态与失败保护

状态Secret UID `fb5529e7-ee5b-48ce-a12f-5e54ca5996c6`，lineage `c7319894-9085-a3c1-a6f2-5cc641dfbf2c`；ConfigMap UID `b62c4251-3a1f-4d5f-9b8f-84bc365ecda4` 与原#190相同。最终serial `15`，只保留 `kubernetes_config_map_v1.environment`，原15份历史状态/计划/日志摘要未变。最近成功快照 `terraform-state/tfstate-latest-success-petclinic-remote-v1` 与活动状态一致；独立复验 `failed-batch-preserved-success.json` 核对失败、重试预览及期限超时前后两个Secret的数据摘要均未变。没有迁移旧state或销毁演示ConfigMap。

## 触发、查看与恢复

普通源码提交或Jenkins petclinic-ci的Build Now运行完整发布，末尾串行执行 Isolated Plan → Shared State → Failure Cleanup。文档提交用 `[skip ci] [ci-skip]` 避免重复构建。只重放已验收隔离实验可在Mac执行：

```sh
PETCLINIC_SSH_ADDRESS=192.168.64.11 /opt/homebrew/bin/python3 '/Users/zhangsir/code/evidence/platform-20261011/terraform-isolation-20261025/replay_isolated.py'
```

该入口强制最新成功构建为197、精确源码及受检安全文件一致，否则拒绝，不能用旧配置覆盖后续版本。它沿用资源准入、外层共享锁、Jenkins暂停与恢复，不重建应用镜像；计算内部不重复申请platform-heavy。后续有新版本时，先更新绑定并完成完整验收。

```sh
ssh -o HostName=192.168.64.11 -o HostKeyAlias=192.168.1.58 192.168.1.58 \
  'sudo kubectl -n terraform-execution get jobs,pods; sudo kubectl -n terraform-execution get events --sort-by=.metadata.creationTimestamp'
```

临时Pod运行时可用 `kubectl -n terraform-execution logs <报告中的Pod名>`；结束后Pod被回收，应查Jenkins Artifacts和报告的private_logs，而不是把没有Pod当成没有执行。失败先看阶段报告error、每个Job conditions及私有日志；确认自身Job回收、后端锁无holder后，走受控入口重跑。不要删除他人Job/Lease，不直接force-unlock或手工改state；异常清理保持UID核对。

## 资源与空间

没有新增常驻计算Pod或PVC；仅保留专用Namespace、SA/RBAC/Quota/NetworkPolicy/准入元数据与既有状态Secret/Lease。串行最多1Pod，requests100m/384Mi、limits1CPU/512Mi，临时存储128/384Mi、emptyDir256Mi。已报告任务memory.peak最大 `110.50 MiB`；超时前未报告完整峰值的任务不按0计算。

#197资源采样38份，VM可用内存最低 `7.88 GiB`、根盘最低 `44.81 GiB`。最终根盘 `44.91 GiB`、VM可用内存 `9.13 GiB`；Mac可用盘 `43.86 GiB`。完整原始采样保留，不拿单点作准入。#196曾因Kubelet滞后样本拒绝启动；#197前连续同时核对df、Kubelet nodefs/imagefs均通过才重试。首次构建在原15%+8GiB停止线之上加2048MiB增长预算，扫描库刷新额外4GiB要求保留；未降低原阈值。

获授权清理均先完整归档、blob SHA及实际Docker恢复校验，只删除限定本地副本/非共享缓存。192/193本地副本回收980.56MiB；194副本489.82MiB及192–194剩余非共享缓存497.25MiB。195本地副本另回收649.46MiB，195临时JAR/.deb构建输入119.37MiB、其余未使用非共享BuildKit缓存233.90MiB；197临时JAR/.deb输入另回收119.78MiB；测试/发布报告保留。Registry/Harbor原件、所有Kubernetes镜像/缓存、190/189/183/184、业务库/卷/PVC保留。各archive-verification/result.json记录归档及保护对象核对。两份旧公共漏洞库副本另按单独授权回收2876.48MiB，可从既有Mac官方归档恢复；当前库正常刷新，不伪造NextUpdate。

公开固定工具v20–v23的24个相同文件通过硬链接去重回收1716.82MiB，内容/版本/属主/权限未变。**这些路径现共享inode：升级必须新文件写好后逐路径rename，禁止原地truncate/覆盖共享inode。** 如需拆分，用copy到临时文件再rename并恢复记录的权限；详见identical-public-tools-dedup/result.json。

## 保留的失败与边界

#191启动连接错误、#192磁盘保护ABORTED、#193期限控制器先删Pod导致采证失败、#194日志204误判、#195准入策略传播延迟、#196构建前Kubelet空间样本滞后拒绝均保留，不能写成成功。修复包括DELETE正文长度、provider目录权限、真实ICMP证据、CNI启动屏障、期限前采集、HTTP204暂态处理及合法dry-run的30秒有界生效等待。一项较早工具清理曾记录memory full PSI6.03%越过5%阈值，证据保留；随后重新连续采样才准入后续工作，不能声称整个维护过程无压力。

Harbor扫描Success表示完成扫描，**不代表无漏洞**。本轮Terraform运行镜像扫描：`{"fixable": 110, "summary": {"Critical": 4, "High": 94, "Low": 65, "Medium": 109, "Unknown": 3}, "total": 275}`。仍有漏洞项需另行修复，未篡改质量结论。此处不宣称Harbor全平台High清零。

Jenkins引导/部署身份仍是可信管理员；本隔离不防集群管理员修改策略，也不是对内核漏洞的保证。K3s Secret静态加密仍关闭，示例状态只含公开ConfigMap，不应存放生产敏感状态。未新增跨机高可用/异地备份，其他专题结论沿用各自验收记录。

下一次完整构建启动预算仍差约1728MiB；本轮197本地构建镜像不在192–196清理授权内，因此保留。现有应用与受检隔离重放可运行，后续完整构建须先恢复预算，不能降低停止线。
