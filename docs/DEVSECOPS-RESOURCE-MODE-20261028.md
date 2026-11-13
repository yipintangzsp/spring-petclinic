# DevSecOps 调试资源模式 · 2026-10-28

本轮用户授权：32 GiB Mac 上的 DevOps VM 从 28 GiB 恢复为 22 GiB，保持 6 CPU；暂时不用的分析业务设为 0 副本，保留部署、数据和恢复配置。只改了 VM 的 System.MemorySize，配置前后结构比较一致；未改主业务磁盘。此前 28 GiB 下 #225 因宿主 swap 比本轮起点增长超过 512 MiB 而 ABORTED，不是客机 full PSI 触发。

## 当前暂停范围

| 命名空间 | 组件 | 原副本 | 当前期望 |
|---|---|---:|---:|
| data-infra | Airflow API / Scheduler / DAG Processor / StatsD | 各 1 | 各 0 |
| data-infra | Superset | 1 | 0 |
| data-infra | Trino Coordinator | 1 | 0 |
| data-infra | Airflow Triggerer / Superset Worker / Trino Worker / MinIO | 各 0 | 各 0 |
| ns-bigdata | Flink JobManager / TaskManager、Kafka UI | 各 0 | 各 0 |

Airflow Application 的 spec.source.kustomize.replicas 与实时副本均设为 0；原自动同步策略保留，防止自愈拉起。原 UID、原副本和 Application 配置保存在 Mac 私有证据目录 devsecops-integration-20261027/analytics-paused-20261028。暂停前未发现 active Kubernetes Job 或运行中的分析/Spark 计算 Pod，未据此声称检查了全部 Airflow 元数据库状态。

Kafka、RabbitMQ、现有数据库、Superset Redis、Spark Operator/Webhook、安全与观测组件保留。Kafka/RabbitMQ 是现有发布/业务验证的依赖；未为了减负停用。未删除 PVC、Topic、镜像或业务数据。暂停期间 Airflow、Trino、Superset 页面不提供原功能，已有存储和分析结果保留，不把预期暂停写成卸载或新故障。

## 实测与验收边界

暂停后 PetClinic 3/3、消息 Worker、GitLab、Jenkins、SonarQube、Falco、Loki、Grafana、Alloy 已恢复；三次连续样本 VM available 6890/6971/6970 MiB，memory full PSI avg10 均 0，Mac swap 均 2478.12 MiB。维护锁按 UID/resourceVersion 前置条件释放，Jenkins 恢复原 quiet=false。以上是恢复时刻观测，不是完整构建峰值，也不保证后续所有负载平稳。

#226 已通过测试、Sonar、私有Harbor解析和现行/214回滚版本签名，并同步了签名策略；随后被旧健康脚本“Falco累计重启必须为0”拦截，未晋升业务。最近Falco退出为Completed/0，时间与本次关机一致；已有累计4次不清零。候选改为CI开始记录Pod/容器/节点bootID基线，本次新增重启、替换、异常退出或driver错误仍阻断，独立只读正例和篡改测试基线的拒绝用例通过。124项回归通过。#227以源码a8393ce04b88f427707f01552224741ef5a10c60复验，已通过124项Node测试、104项Maven测试、SAST/SBOM/Sonar、Falco本轮新增重启0和3个真实Secret对账；当前/214基线签名通过。真实验签准入正例被Harbor认证失败阻断，尚未晋升。有效拉取凭据和精确get RBAC独立验证通过；官方1.19.2 cmd/internal/registry.go显示Secret缓存仅为控制器自身与启动参数声明的命名空间建立，当前策略跨namespace引用未加载。新增专用只读Robot/本命名空间Secret方案已准备，等待超出原3个Secret范围的明确授权。31个样本最小可用5660MiB、最大memory full PSI1.28、Mac swap增长0MiB；当前阻塞并非资源不足，未暂停Spark Operator/Webhook。原15%+8 GiB磁盘停止线、4 GiB构建增长预留、VM 1536 MiB、Mac swap增长512 MiB、memory/IO full PSI5/10和新OOM/Eviction保护均保留。完整发布与新签名/凭据/DAST门禁尚未因此标为完成。

## 恢复分析模式

用户需要分析时，先重新预算、确认没有 DevSecOps 重构建，取得共享维护锁并保存当前状态。只恢复原副本：Airflow Application 仅恢复原 spec.source.kustomize.replicas 数组，不要 apply 整份旧 Application；Superset 与 Trino Coordinator 恢复原1副本。原来为0的组件继续为0。逐项核对UID、Ready、业务与数据可查询后再释放维护锁。不要在CI执行时一次性启动全部分析组件。
