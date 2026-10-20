# Argo Rollouts 学习实验

此目录是独立灰度与蓝绿应用，不接管现有 Petclinic Deployment。只有精确源码经现有完整 Jenkins 流水线成功后，才由 `run.py` 引导 Application。控制器 namespace-only，固定 v1.10.1 和镜像摘要；CRD来自官方固定tag，原始来源摘要在相邻 upstream-lock.json。官方清单转换为JSON并限制资源；没有宣称验证供应链签名或全镜像无漏洞。

正常 GitOps 状态保留控制器1副本、两个实验 Rollout均0副本。运行时脚本暂时暂停**实验应用**自动同步，串行完成 v1→v2 50%副本灰度、真实 Prometheus/Blackbox HTTP成功率分析、HTTP500候选自动中止、同一错误重试、恢复、同模板重复应用、蓝绿预览及入口切换。结束恢复原始0副本源码与自动同步。失败保留 AnalysisRun、ReplicaSet、事件、日志与证据；不删除namespace/PVC/Secret。

复用既有cook镜像的nginx运行时；响应只标识版本与实验名称，不伪装成Petclinic真实业务统计。`/healthz` 始终200，但bad版本业务URL返回500，因此Pod Ready不能代替业务指标。探测使用既有cook_blackbox模块（实际名cook_http）、既有Prometheus；仅增加命名空间隔离Probe，没有修改既有探测。等待25秒再判定近20秒探测；空/过期指标不会通过。50%按ReplicaSet副本数近似分流，不是精确加权路由，未安装Traefik流量插件。

## 执行

```sh
python3 infra/devops-lab/rollouts/run.py --build <成功构建号> --revision <该构建源码40位SHA> --evidence <新的私有证据目录>
ssh zhang@192.168.1.58 'sudo kubectl -n rollouts-lab get rollouts,analysisruns,rs,pods'
ssh zhang@192.168.1.58 'sudo kubectl -n rollouts-lab describe rollout delivery'
ssh zhang@192.168.1.58 'sudo kubectl -n rollouts-lab logs deploy/argo-rollouts --tail=150'
```

服务器CLI位于 `/opt/petclinic-observability/tools/kubectl-argo-rollouts-v1.10.1`，Linux ARM64 SHA256 `c677dec8cdf124b2ff60f475587ebd4a728015e512a1a1090a8c21b119ebbdf1`，须与官方校验和匹配后准备，脚本拒绝不同CLI。首次安装和重新执行同样受发布门禁、共享重任务Lease和Jenkins quiet状态保护。实验期间用CLI `get rollout delivery` 看树；`promote`继续人工暂停；分析失败后先检查AnalysisRun测量、Probe/Prometheus和HTTP响应，修复模板再重跑。不要使用`promote --full`跳过正在服务的门禁。

控制器 requests100m/128Mi，limits500m/256Mi；每个实验web requests25m/24Mi，limits200m/64Mi。灰度2副本、surge1，蓝绿1+1且串行；namespace硬配额6Pods/CPU requests300m/内存requests512Mi/limits768Mi、PVC0。完整控制过程预算1024Mi+1250Mi安全储备。CLI/宿主开销也需纳入实际观测，样本不等同于瞬时内核峰值。禁止自动清理既有资源；若资源锁/quiet未恢复，先核实本轮Pod确实回收，再按运行手册恢复，不抢占别人的Lease。

控制器安装配置在 `../rollouts-controller`，bootstrap在 `../applications`，故不会被Petclinic父应用提前同步。后续改实验源码前应先暂停对应应用自动同步，CI成功后恢复；不要将未检查配置直接上线。

## 配置语义门禁
副本比例灰度不设置 `canary.scaleDownDelaySeconds`；该字段要求 trafficRouting，蓝绿保留自己的延迟缩容。现有 Jenkins tooling 测试覆盖此约束及错误负例；实验执行前还使用固定摘要的官方CLI逐个离线lint，随后才创建实验计算资源。服务器CLI读取 `/dev/stdin`（其lint不支持`-`文件名）。

CRD中的Pod端口显式使用TCP，避免API默认补全与Argo客户端比较产生永久OutOfSync；不通过忽略整个模板掩盖差异。
