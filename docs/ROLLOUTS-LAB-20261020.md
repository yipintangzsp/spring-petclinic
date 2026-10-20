# 灰度与蓝绿发布实验验收 · 2026-10-20

本轮修复并实际完成独立发布实验，未接管 Petclinic 的现有 Deployment。最终成功时间 **2026-10-20 15:19:37 Asia/Shanghai**。这不是把“构建成功”“Pod Ready”作为整体验收。

## 发布来源与实际修复

- 首个修复 `cce131db4acb88b80ad46982b93222703840d60b` 经 Jenkins #158 SUCCESS：删除无 trafficRouting 的副本灰度中非法的 `canary.scaleDownDelaySeconds`；蓝绿保留独立的延迟缩容配置。
- #158 后启动实验时仍 OutOfSync；对比发现 API 给 CRD 内的容器端口补齐了 TCP。第二个修复 `6aa3faf8cef89285f73b4747f8643516fb327fd1` 显式声明协议，经 **Jenkins #159 SUCCESS** 完整发布。
- #159 私有晋升提交 `0e85b45a0bc1ac578bf8344e5146a6d992786139`。测试、SonarQube、私有源码审计、双架构构建/扫描、GitOps、滚动发布、健康验证、Kafka 发布事件阶段均成功。
- 现有 tooling 测试新增灰度语义负例及端口默认值检查；运行器在启动实验计算前，使用已校验 SHA256 的官方 CLI 离线 lint。官方 CLI 对旧非法模板返回1，对修复后的两个模板返回0。

## 现场验收

|项目|实际证据|
|---|---|
|初始服务|v1 服务响应200|
|50%副本灰度|60次请求：v1 31次、v2 29次；这是副本比例分流，非精确流量路由|
|指标晋升|v2 业务探测真实成功，Prometheus AnalysisRun 成功后晋升|
|幂等|重复应用相同v2模板，PodHash及AnalysisRun集合均不变|
|故障回退|bad版本Pod就绪但业务返回500；指标失败自动中止，bad副本归零，正常入口40次均返回v2/200|
|同故障重试|再次执行同一bad模板，新的AnalysisRun再次Failed；未用人工全量晋升跳过门禁|
|恢复|还原v2后Healthy，再停止灰度计算|
|蓝绿|切换前active返回v1、preview返回v2；晋升后active返回v2/200|
|清理|实验web Pod全部回收，两个Rollout均0；保留控制器、分析与失败记录|
|最终状态|rollouts-lab、platform-rollouts、petclinic、spark-operator均Synced/Healthy；Petclinic /owners返回200；共享Lease不存在；Jenkins quietingDown=false|

本轮恢复验收的AnalysisRun：

- `delivery-746cf7967f-4-2`：Successful。
- `delivery-5fcff57b9d-5-2`：Failed，实际HTTP500。
- `delivery-5fcff57b9d-5-2.1`：Failed，同一故障重试。
- 还保留上一轮成功分析 `delivery-746cf7967f-2-2`，不把它当作恢复轮的替代证据。

## 保留的中断与资源记录

首轮 #159 实验被资源保护中止：取构建归档时错误地并行在仅96Mi限额的Jenkins中继容器里运行两个Node读取进程，导致该中继OOM。保护识别到新增OOM后，自动清理实验Pod并恢复Jenkins/Lease；中继恢复Ready。停止并发读取，后续归档请求严格使用现有本地锁串行执行，未扩大中继内存限额，未放宽停止线；用同一个已发布#159重新执行实验并完整通过，未为此重复构建。失败目录和恢复目录均保留。

恢复轮共享保护预算1024Mi加1250Mi储备，14次宿主采样；VM可用最低10961.96Mi、根盘可用最低14584.39Mi、Mac最低freePercent37、Mac swap增量115.87Mi，未触发停止线。45次metrics-server采样中，该命名空间容器合计最高24m CPU、54Mi内存；这是采样最大值，不能称为内核瞬时峰值。

控制器常驻requests100m/128Mi、limits500m/256Mi；每个实验web requests25m/24Mi、limits200m/64Mi。灰度最多2+surge1，蓝绿1+1，串行运行；配额6Pod、CPU requests300m、内存requests512Mi、内存limits768Mi、PVC0。Spark Operator与Webhook保留原运行状态。

## 查询与重跑

```sh
python3 infra/devops-lab/rollouts/run.py --build 159 --revision 6aa3faf8cef89285f73b4747f8643516fb327fd1 --evidence /tmp/petclinic-rollouts-new-run
ssh zhang@192.168.1.58 'sudo kubectl -n rollouts-lab get rollouts,analysisruns,rs,pods'
ssh zhang@192.168.1.58 'sudo kubectl -n rollouts-lab describe analysisrun delivery-5fcff57b9d-5-2.1'
ssh zhang@192.168.1.58 'sudo kubectl -n rollouts-lab logs deploy/argo-rollouts --tail=150'
```

须使用本仓库工作区执行；运行器校验实验源码与已发布SHA一致，拒绝未发布变更。证据目录必须是新的。等待期间Jenkins受控quiet；失败先核对本轮Pod回收与Lease所属，不抢占其他任务锁，不删除namespace/PVC/Secret。正常结束回到Git中的0副本状态并恢复实验自动同步。控制器Dashboard如需查看，可在服务器上运行已固定版本CLI的`dashboard --address 127.0.0.1 --port 3100`，用SSH隧道访问；它是按需进程，本轮未新建常驻Dashboard服务。

## 证据及限制

私有证据根目录：`/Users/zhangsir/code/evidence/platform-20261011/rollouts-fix-20261020`。`ci-158`、`ci-159`保留完整构建、阶段与控制台记录；`acceptance-158`为默认值差异失败；`acceptance-159`为OOM保护中止；`acceptance-159-recovery`为最终完整通过；`final-state.json`为清理后复核。

#159两个运行时架构的Harbor扫描均Success，最高Medium：每个架构176 Medium、15 Low、134可修复项。本轮没有处理这些漏洞，扫描成功不代表无漏洞；也不覆盖Harbor自身其他组件。此前Harbor High逐项修复、Airflow四轮联合分析完整验收等既有遗留，不能因本轮发布实验完成而标为完成。Argo Rollouts为独立学习应用，没有宣称Petclinic本体已改为灰度发布。

官方依据：[Rollout配置](https://argo-rollouts.readthedocs.io/en/stable/features/specification/)、[蓝绿切换](https://argoproj.github.io/argo-rollouts/features/bluegreen/)。
