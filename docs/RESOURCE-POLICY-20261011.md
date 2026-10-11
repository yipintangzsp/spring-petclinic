# 实测资源与按需运行策略 · 2026-10-11

## 基线与准入

Mac M1 实测物理内存 32 GiB，保留现有 UTM 配置；不关机扩容。devops 客机约 19.48 GiB，6 CPU，12 GiB swap。基线 11 次、约 324 秒，MemAvailable 最低 2.87 GiB，所有本地业务/数据库健康/API 检查成功；根盘 87%、剩余约 32 GiB。Mac、客机 CPU/内存/Swap/磁盘/inode/I/O/PSI、全部节点 allocatable/Pressure/Pod requests/limits 已单独取证。

Superset worker 初始实测 856 MiB，Celery active/reserved 都为空、队列长度0；无 Argo Application 管理该 Deployment。备份其精确配置后，通过受控按需机制关闭，保留 Superset Web、内部数据库和 Redis。再次实测 MemAvailable 3880 MiB，使用后续实时指标准入，不能固定沿用这个数字。

Jenkins 每次构建先读取新鲜 node-exporter MemAvailable，要求至少 3050 MiB：1250 MiB 系统/k3s/数据库/业务储备 + 1800 MiB 完整构建增量预算，覆盖 Maven、测试 JVM、512 MiB Testcontainers 数据库、Docker/BuildKit、扫描客户端及堆外开销。Maven、镜像构建、扫描在同一个流水线中顺序执行。新增共享 `data-infra/platform-heavy` Lease 阻止本轮管理的重任务重叠；过期或异常任务不得直接抢占，先验证旧任务进程/构建结束。既有 Cook 流水线保留，执行本轮实验前同时检查 Jenkins 队列与运行任务。

停止条件：MemAvailable <1536 MiB、Memory/Disk/PIDPressure、新增 OOM/异常驱逐，或连续三次业务响应明显恶化（Petclinic >2s/Cook >1s）、内存 full PSI avg10 >5% / I/O full PSI avg10 >10%，停止新增任务并正常停止当前实验/构建。数据库/PVC、已有业务、源码及有效镜像不作为资源回收对象。

## 运行策略

|组件/任务|方式|完整计算预算|结束与恢复|
|---|---|---|---|
|Petclinic|devops 常驻3副本；512Mi request/768Mi limit|滚动 maxSurge=0 / maxUnavailable=1，避免第四个 JVM|GitOps 回滚；保留共享 PostgreSQL和分析schema|
|Cook|现有常驻单副本与 blackbox|保持现有小资源请求/限制|独立 Cook GitOps/Pages，代码不随本轮内部改动公开|
|轻量统计|有界 Job，最多5000行、366天；数据库5秒 statement timeout|256Mi request/512Mi limit，100m/500m|Job完成即释放计算；结果留在隔离 schema，事实按主键去重、事务发布|
|Airflow|沿用3.3.0/KubernetesExecutor；核心按需开启，DAG schedule=None|max_active_runs/tasks=1；完整核心/任务预算须实测后准入|不要求每次业务发布启动；状态留在既有元数据库/日志PVC|
|Superset Web/Redis|常驻看板|保留现有配置|同步查询继续；Celery后台worker仅有实际异步任务时启动|
|Superset worker|受控按需|启动前重新核实Celery队列及资源预算|关闭前确认active/reserved/queue为空；`kubectl -n data-infra scale deploy/superset-worker --replicas=1`恢复；不删除数据|
|Spark|既有Operator和原版本引擎，单次有界Job|driver/executor、Operator、堆外全部计入；初拟至少2.5Gi增量+1.25Gi储备，按实际版本修订|完成后正常删除本次计算对象/关闭Operator，保留配置和结果；无需Hadoop|
|Flink|既有2.3.0普通Deployment，单个窗口任务|JobManager、TaskManager、堆/堆外/network/managed全部计入，按实际配置准入|验证checkpoint/savepoint恢复后正常停止，保留状态；不常驻|

## 节点边界

本轮持续采样发现 UCloud 在初次 Ready 后失联，Lease 停在04:58:28 UTC，Trino worker不可查询。不能把初始 Ready 当作长期恢复证据，不能向该节点安排新业务。Petclinic 发布目标在清单中明确固定 devops；preflight 从待发布的真实 YAML 解析 nodeSelector，验证所有目标节点及每个业务 Endpoint 对应节点的 Lease。非目标云节点异常仍归档和报告，但不把它们伪装成该本地发布的必要依赖。原未声明目标时的三节点保护保持默认；没有去除故障 taint或压低 requests。

所有回收步骤限于已确认结束的临时任务或按需计算副本，禁止批量删 Pod、强删失联业务 Pod、删除 PVC、清空表或重装组件。
