# 实测资源与按需运行策略 · 2026-10-11

> 2026-10-25最新：Terraform独立Job执行隔离已通过完整Jenkins #197及独立复验；真实锁竞争、重复执行、受控失败重试、60秒超时回收和状态保护均通过。旧Jenkins内执行入口已停用。当前操作及边界见[执行隔离验收](TERRAFORM-ISOLATION-20261025.md)。

> #190 Terraform远端状态验收通过。Terraform复用原CI重任务锁与Jenkins计算；provider共享缓存避免重复解包，元数据配额禁止Pod/PVC扩张。静态加密及完整管理员隔离未实现。见[记录](TERRAFORM-20261024.md)。

> Terraform接入未新增常驻Pod。Jenkins计划阶段复用原锁和执行容器；受控实验按1024MiB准入，每步768MiB/1CPU/600秒，实际峰值129.89MiB，结束后进程、实验资源和锁均清理。私有plan/state目录保留，不作空间恒定承诺。详见[验收](TERRAFORM-20261024.md)。

> 2026-10-24本轮完成：#188完整发布成功；1202条来源、年度925的Airflow正常/受控失败/自动重试成功/同批重跑四轮通过，Spark→Flink/Kafka→Trino/Superset真实对账。137旧卷已完整备份校验后按授权删除，指定旧镜像本地副本已核验清理。Spark Operator/Webhook保留，计算按需回收；外部通知送达与云Trino根因仍有限制。详见[本轮发布与验收](ANALYTICS-E2E-20261024.md)。

> 2026-10-24较早阶段：#183完整发布成功（0.10.0-ci-183）；RabbitMQ业务、去重、重试/死信、断连及Elasticsearch真实日志复验通过。获授权清理26个≤172旧本地镜像副本，Registry原件保留；CI自动回收仅限构建上下文/JAR缓存。Jenkins与资源锁恢复。新Airflow联合复验仍未完成，不能用旧结果替代。详见[最终交付](RABBITMQ-INTEGRATION-20261023.md)。
> 2026-10-23 RabbitMQ业务接入：#176完整发布通过；就诊回访、后台报表、发布审计均完成真实消费、去重、失败重试/死信、断连恢复与Jenkins恢复验收。新增Worker requests50m/128Mi、limits500m/256Mi；Kafka及既有分析链保留。当前状态和操作见 [业务验收](RABBITMQ-INTEGRATION-20261023.md)。下文较早“尚未接入”为历史阶段。

> 2026-10-23 RabbitMQ：data-infra 单副本持久化工作队列，独立 AMQP 确认/重投/死信、Pod 替换持久化、管理认证及 Prometheus 采集通过；尚未接入 PetClinic 业务。增加 requests100m/256Mi、limits500m/768Mi；入口、账号读取、证据、GitOps关闭方式与限制见 [RabbitMQ 验收及操作](RABBITMQ-20261023.md)。

> 2026-10-23 后续：#167完整发布成功，三个K3s组件采集target及实际指标通过，三条发现缺失Critical告警已在Prometheus/Alertmanager恢复；历史失败Job及容灾容量告警保留。详见[监控修正记录](MONITORING-K3S-20261023.md)。

> 2026-10-23 核对：#165完整发布成功；Airflow四轮联合验收通过，周一02:30上海时间运行。证据、任务ID和操作见[最新验收](ANALYTICS-E2E-20261022.md)。后文较早状态按日期保留为历史。

> 2026-10-22：主盘旧快照经单独授权删除，活动数据全量摘要前后一致，镜像回收约80.3GiB；Harbor控制器原生ARM64恢复、Loki/Grafana缓存重建及健康检查通过。最新完整发布与联合分析状态以 [本轮恢复记录](RECOVERY-20261021.md) 为准；以下较早数字均为历史阶段，不能代替现场。Spark Operator/Webhook常驻保留。


## 2026-10-24 清理后实测与预算

最终VM可用9.93GiB，根盘空闲47.88GiB，Mac数据盘空闲56.22GiB、内存余量42%，当前CPU请求4545m/6000m。此为测量时刻值，不是持续保证；三次空闲记录和完整任务峰值在本轮证据。空闲4545m预算、暂停Sonar后5895m峰值预算、6114MiB剩余内存准入及一次实际swap安全停止详见[验收记录](ANALYTICS-E2E-20261024.md)。阈值不降低，缓存逻辑大小不当作磁盘净回收。

常驻Airflow三核心/statsd、Spark Operator/Webhook、业务/消息/存储/观测依赖；Driver/Executor、Flink JM/TM/客户端、任务执行Pod按需运行并清理，triggerer关闭。完整80项工作负载分类见[组件清单](PLATFORM-INVENTORY-20261011.md)。计划仍为上海时区每周一02:30，单轮串行且不补历史。干净页缓存回收仅为本次大批文件校验后的一次资源恢复，不配置定时清缓存。

## 2026-10-22 当前保护与预算

VM保持原6CPU/约28GiB容量。当前根盘约60GiB空闲，主盘旧恢复点删除后Mac连续采样约90GiB以上空闲，VM可用约12GiB，实际以新鲜记录为准。任务不再沿用固定8GiB根盘门槛：nodefs/imagefs需15%容量加8GiB；Mac>=16GiB且内存余量>=10%，EFI占用有测量且<=128MiB。全程保留swap增长512MiB、内存/IO PSI、OOM/Eviction停止条件，不以关库或调整统计基线换取通过。

Spark Driver与Executor各requests750m、limits1000m（引擎cores仍1），串行Flink；计算requests1500m外另留250m调度储备。Harbor新增明确requests合计100m。当前全恢复常驻CPU请求须重新采样，若联合任务预算不再满足6000m则拒绝，不根据上一次3905m估算硬启动；只在持同一Lease、Jenkins空闲时按既有UID/owner暂停Sonar500m，失败或完成先恢复Ready再释放保护。三次重启采样通过不代替Airflow五次启动前准入。

## 当前等待机制与资源边界

实际运行时Airflow3.3.0，cncf-kubernetes provider10.19.0，未安装apache-flink provider。Spark使用该已装provider的SparkKubernetesSensor，mode=reschedule，本轮真实记录up_for_reschedule；不虚构deferrable/triggerer能力。Flink在唯一KubernetesExecutor任务中进行有界API轮询/消息核对，保留768MiB请求与上限、100m请求/500m上限；已包含在完整预算，最多一项任务、12分钟超时、一次重试。Flink等待仍占用这一个任务Pod，不宣称等待完全无计算占用，也不为此开启新常驻provider服务。

## 2026-10-16 宿主内存回收配置

UTM客机容量维持28672MiB/6CPU，实际Linux约27994MiB；新增virtio-balloon-pci,free-page-reporting=on允许内核向宿主回报空闲页，不设置balloon target，不主动压低客机可用容量，不降低分析requests/limits或停止阈值。配置原件、变更比对、离线磁盘0错误、内核启用日志及冷启动预热采样均在私有balloon-recovery-20261016。实际运行仍需Mac/VM双重连续采样；原VM MemAvailable充足不能替代宿主换页检查。修改后的整轮效果尚在验收。

## 2026-10-16 准入停止与重新评估

保持Mac swap增长512MiB停止线。#147完整发布后，首次新验收在五次启动前采样阶段停止：swap2561.31→3198.38MiB（+637.07MiB），未开启Airflow或新计算。资源观察器保留触发时的真实样本，不能将其写成流程通过。随后七次约两分钟独立评估，swap3198.38→3182.38MiB且稳定，VM可用12090–12233MiB，全部健康/API通过且无新的资源故障，才用全新证据目录重新启动。此为前轮已经退出后的新准入，不是在运行中重设安全基线。

## 2026-10-16 CPU 调度预算与构建服务互斥

首次新联合运行实测暴露 CPU 调度缺口，不能由 MemAvailable 推断可运行：devops allocatable6000m；既有常驻 requests3580m；Airflow核心340m、控制Pod100m、单任务100m，加Spark Driver/Executor各1000m，共6120m，缺120m。计入250m调度储备后总需求6370m，缺370m。Executor真实FailedScheduling证据在私有 airflow-e2e-20261016；该轮已受控中断、计算清理、Jenkins恢复，不计联合通过。

新策略不降低Driver/Executor或业务requests，不停止MySQL、Kafka、Trino、Superset等必要服务。DAG取得同一重任务Lease、确认Jenkins所有Job空闲且quiet后，若CPU不足，只暂停既有SonarQube单副本（释放500m request及至少1GiB内存请求）；保留PVC、原UID/副本数与本轮owner标记。受控Jenkins是现有扫描入口，最近发布已完成质量门，不宣称已取得Sonar全局CE管理员权限。暂停后总请求5620m，保留380m，其中250m为明确调度储备、额外130m余量。准入读取新鲜实际CPU requests，计入init峰值、原生sidecar及overhead；缺口即拒绝提交，不再让Executor无限Pending。

结束/失败先清理本轮计算，再按UID与owner恢复Sonar到原副本并等待Ready，最后恢复Jenkins原quiet状态/释放Lease；控制器受控中断也执行同一恢复。恢复失败保留锁和静默状态以供排查，不能把未知资源批量删除。最终结果仅在业务核对与清理/构建服务恢复成功后转success，失败批次保留最近成功结果。CPU/恢复/提交顺序的新修订正在完整流水线和联合验收中，实际通过结果以本轮执行记录为准。

## 2026-10-15 联合编排分阶段预算

准入使用 Mac 与 VM 连续采样，不能用 Kubernetes allocatable 减 working set 冒充 MemAvailable。启动 Airflow 前要求 VM MemAvailable 至少 10240 MiB。已有业务、PostgreSQL、MySQL、Kafka、Trino 本地协调器、Superset Web、监控和系统的实际占用已体现在采样中；不额外开启云 Trino worker、Superset worker、MinIO 或 Spark/Flink 长期计算。

|增量项目|内存上限预算 MiB|执行方式|
|---|---:|---|
|Airflow API / Scheduler / DAG Processor|2304|每个 768，CPU request 100m / limit 750m|
|两个日志清理容器、StatsD|192|128+64；复用现有日志 PVC|
|单个 KubernetesExecutor task|768|100m / 500m；同一时间最多一个|
|验收控制 Pod|512|仅本轮手工验收，结束即删除|
|Spark 或 Flink 完整计算过程|4096|串行；Flink JM 1024 + TM 1536 + 独立 SQL client 1024，另留 512|
|安全储备|1250|不作为任务可消耗预算|
|合计|9122|启动准入 10240，额外保留 1118 MiB 余量|

Airflow 已启动后，核心占用已扣在 MemAvailable 中，任务准入检查剩余计算 4096 + worker 768 + 安全储备 1250 = 6114 MiB；不能重复计算 Airflow 核心并错误拒绝准入。共享 Lease 记录完整 Airflow 4096 + 计算 4096 = 8192 MiB。验收控制器不获取第二把 Lease，DAG 自己管理锁与 Jenkins 原始 quiet 状态。

轻量 Mac LaunchAgent `local.petclinic.resources` 每 15 秒以上发布真实 Mac/VM 采样到 `data-infra/platform-host-resources`，不启动业务计算。样本超过 90 秒、宿主/VM 磁盘少于 8 GiB、Mac free 低于 10%、swap 增长超过 512 MiB、VM available 低于 1536 MiB、新 OOM/驱逐或既有 PSI/健康阈值触发，任务停止并仅清理本轮资源。等待 Spark 使用已装 provider 支持的 reschedule sensor，等待时任务 Pod 可释放；不额外常驻 triggerer。最终失败由独立失败任务保持 DAG 红色，清理成功不会掩盖失败。

DAG 默认无定时；控制器完成正常、最终失败、重试、同批次复跑四轮后，才可用 `--keep-running` 将 GitOps Application 的核心副本设为 1，并开启 Asia/Shanghai 每周一 02:30，catchup=False、max_active_runs/tasks=1。所有计算仍按需回收。未经整体验收不得将该策略描述为已上线。

## 基线与准入

以下为历史分阶段测量，不能当作当前容量：Mac M1 实测物理内存 32 GiB。2026-10-15 现场 VM 总量27994MiB、6CPU，当前以重新采样为准。初始 devops 客机约 19.48 GiB，6 CPU，12 GiB swap；恢复工作时重新测得24.39 GiB（24976.76MiB），后续按这个实时环境验证。基线 11 次、约 324 秒，MemAvailable 最低 2.87 GiB，所有本地业务/数据库健康/API 检查成功；根盘 87%、剩余约 32 GiB。Mac、客机 CPU/内存/Swap/磁盘/inode/I/O/PSI、全部节点 allocatable/Pressure/Pod requests/limits 已单独取证。

Superset worker 初始实测 856 MiB，Celery active/reserved 都为空、队列长度0；无 Argo Application 管理该 Deployment。备份其精确配置后，通过受控按需机制关闭，保留 Superset Web、内部数据库和 Redis。再次实测 MemAvailable 3880 MiB，使用后续实时指标准入，不能固定沿用这个数字。

Jenkins 每次构建先读取新鲜 node-exporter MemAvailable，要求至少 3050 MiB：1250 MiB 系统/k3s/数据库/业务储备 + 1800 MiB 完整构建增量预算，覆盖 Maven、测试 JVM、512 MiB Testcontainers 数据库、Docker/BuildKit、扫描客户端及堆外开销。Maven、镜像构建、扫描在同一个流水线中顺序执行。新增共享 `data-infra/platform-heavy` Lease 阻止本轮管理的重任务重叠；过期或异常任务不得直接抢占，先验证旧任务进程/构建结束。既有 Cook 流水线保留，执行本轮实验前同时检查 Jenkins 队列与运行任务。

停止条件：MemAvailable <1536 MiB、Memory/Disk/PIDPressure、新增 OOM/异常驱逐，或连续三次业务响应明显恶化（Petclinic >2s/Cook >1s）、内存 full PSI avg10 >5% / I/O full PSI avg10 >10%，停止新增任务并正常停止当前实验/构建。数据库/PVC、已有业务、源码及有效镜像不作为资源回收对象。

## 运行策略

|组件/任务|方式|完整计算预算|结束与恢复|
|---|---|---|---|
|Petclinic|devops 常驻3副本；512Mi request/768Mi limit|滚动 maxSurge=0 / maxUnavailable=1，避免第四个 JVM|GitOps 回滚；保留共享 PostgreSQL和分析schema|
|Cook|现有常驻单副本与 blackbox|保持现有小资源请求/限制|独立 Cook GitOps/Pages，代码不随本轮内部改动公开|
|轻量统计|有界 Job，最多5000行、366天；数据库5秒 statement timeout|256Mi request/512Mi limit，100m/500m|Job完成即释放计算；结果留在隔离 schema，事实按主键去重、事务发布|
|Airflow|沿用3.3.0/KubernetesExecutor；核心当前1副本；源码默认无定时，验收后运行覆盖为周一02:30|max_active_runs/tasks=1；完整核心/任务预算须实测后准入|不要求每次业务发布启动；状态留在既有元数据库/日志PVC|
|Superset Web/Redis|常驻看板|保留现有配置|同步查询继续；Celery后台worker仅有实际异步任务时启动|
|Superset worker|受控按需|启动前重新核实Celery队列及资源预算|关闭前确认active/reserved/queue为空；`kubectl -n data-infra scale deploy/superset-worker --replicas=1`恢复；不删除数据|
|Spark|既有Operator和原版本引擎，单次有界Job|driver/executor、Operator、堆外全部计入；本轮完整准入4096MiB+1250MiB储备；driver/executor各1Gi，controller1Gi/webhook256Mi|完成后正常删除本次 Driver/Executor/SparkApplication；Operator 与 Webhook 各1副本常驻且纳入 GitOps，保留结果；无需Hadoop|
|Flink|既有2.3.0普通Deployment，单个窗口任务|JobManager、TaskManager、堆/堆外/network/managed全部计入，JM1Gi、TM1.5Gi（一slot）、独立SQL客户端1Gi，完整准入4096MiB+1250MiB储备|验证checkpoint/savepoint恢复后正常停止，保留状态；不常驻|

## 节点边界

本轮持续采样发现 UCloud 在初次 Ready 后失联，Lease 停在04:58:28 UTC，Trino worker不可查询。不能把初始 Ready 当作长期恢复证据，不能向该节点安排新业务。Petclinic 发布目标在清单中明确固定 devops；preflight 从待发布的真实 YAML 解析 nodeSelector，验证所有目标节点及每个业务 Endpoint 对应节点的 Lease。非目标云节点异常仍归档和报告，但不把它们伪装成该本地发布的必要依赖。原未声明目标时的三节点保护保持默认；没有去除故障 taint或压低 requests。

所有回收步骤限于已确认结束的临时任务或按需计算副本，禁止批量删 Pod、强删失联业务 Pod、删除 PVC、清空表或重装组件。


## 后续实测与任务峰值

第二段正常基线5次，10月11日10:08–10:10 UTC，VM MemAvailable最低9495.03MiB，memory/io full PSI最高0.28/0.18%，当时Swap0；不把这个旧数字沿用为后续准入。10月12日新构建前实际MemAvailable为8831.77、8648.25、8626.59MiB，VM Swap约924MiB，Mac内存空闲比例48–51%以上。初期CPU/磁盘/inode/各节点allocatable、全部工作负载requests/limits取证保留；两个环境阶段分列，不能把虚拟机物理内存变化解释为本轮代码治理收益。

|实际任务|准入MiB（另加1250储备）|样本数|VM可用内存最低MiB|memory / IO full PSI最高%|
|---|---:|---:|---:|---:|
|Airflow四轮真实DAG|4096|33|7906.56|0.08 / 0.29|
|Trino本地查询|2560|3|8924.47|0.21 / 0.40|
|Superset实际看板|2048|6|8853.95|0.17 / 0.18|
|Spark完整资源探测|4096|4|8340.23|0.17 / 0.14|
|Flink窗口及恢复|4096|12|7888.42|0.18 / 1.52|
|Kafka持久化维护|1536|3|8751.29|0.14 / 0.15|

以上成功任务safetyFailure均为空，计算结束后确认退出。Spark内核memory.peak：driver515.14MiB、覆盖1200行的executor398.38MiB；15s Prometheus采样会漏掉短生命周期峰值，不能把4MiB之类采样低值当作真实executor峰值。Flink实际Pod Prometheus观测峰值：JM335.69MiB、TM415.95MiB、SQL客户端153.36MiB，这是采样观测下界，不是内核真实峰值。

Jenkins #129（测试失败、未部署）13样本，VM可用最低7414.60MiB、memory/io full PSI0.78/1.73%；#130（质量门拦截、未部署）10样本，最低7384.24MiB、PSI0.09/2.24%，两个时段业务/数据库健康及API均正常。最终成功补丁构建的完整窗口会另行记录。Mac连续采样覆盖内存空闲和Swap增长；停止阈值仍为Swap增量512MiB、空闲<10%及数据磁盘<8GiB，不因当前余量较高放宽。

完整联合Airflow4096 + Spark或Flink4096 +1250储备 =9442MiB，高于最近构建前8627–8832MiB；联合按需编排未准入，已分别完成真实验收。未创建长期定时重任务。Trino保持已有协调器本地查询、云worker0；Superset Web完整request=limit768MiB，异步worker0；Kafka完整1Gi；Runner控制器128MiB，轻量audit build/helper各128MiB。Airflow包括API/scheduler/dag processor/StatsD/worker/control与初始化进程的完整预算，全部按需关闭，触发器不作可用性替代。

Trivy数据库大文件缓存准备曾触发memory full PSI12.74%的真实安全停止；停止、重新测量后才继续。失败尝试与原始资源记录保留，不宣称全程没有压力。Harbor现有AMD64 portal/Trivy在ARM节点仿真有额外成本；扫描双架构顺序执行。

当前三个节点有新鲜Ready/Lease；历史UCloud失联记录和Trino云端并发阻塞证据保留，根因未确认。主业务保持经验证本地目标，不将短时Ready宣称为长期跨云高可用。上述预算针对本轮有界任务，历史未限制的支持容器在完整清单中如实记录。

原已成功发布 #127 的精确构建窗口（排除随后中止的#128）：21个样本，可用内存最低8174.53MiB、Swap最高891.93MiB、memory/io full PSI 0.20/2.03%，全部业务/数据库健康与API检查正常。

最终成功 #131 完整窗口32个样本、677.144s，VM可用最低7302.75MiB、Swap最高924.02MiB、memory/io full PSI 0.51/2.10%；Mac空闲最低47%。全部业务/数据库健康与API检查正常，无资源安全停止。

## 2026-10-14 准入复验

最终五样本 VM 可用最低12590MiB，Mac内存空闲40–44%、Swap3705–3713MiB，VM根盘可用约30GiB。Airflow完整4096MiB + 串行Spark或Flink4096MiB + 系统/业务安全储备1250MiB =9442MiB，控制器准入10240MiB。MySQL主/从445/459MiB、Kafka466MiB、Trino864MiB、Superset235MiB、业务约1280MiB及现有系统服务均计入运行基线；不把这些必要服务当作可随意关闭的余量。

Mac数据卷最低5979MiB，低于8192MiB停止线2213MiB。已回收可重建缓存并fstrim；仍拒绝联合编排。后续须先稳定恢复至少12GiB宿主可用空间，为Java漏洞库/镜像/日志增长保留余量。未以降低requests/limits、放宽停止阈值或删除持久业务数据准入。详情及原始资源证据见RECOVERY-20261014.md。

Spark Operator与Webhook按用户要求常驻1副本，已纳入Argo spark-operator应用；driver/executor、Flink及Airflow任务计算仍按需。旧表格中“完成后关闭Operator”的历史策略已被此期望状态替代。


## 2026-10-19 证书学习实验预算

cert-manager三控制器和独立Web常驻requests CPU225m/内存344Mi，内存limits704Mi；临时API-check再加10m/32Mi请求及64Mi内存上限。无新增PVC，生成的证书Secret保留。10月18日恢复验收8个metrics-server样本合计内存最大187.27Mi、CPU最大16.12m；不是内核峰值。结束全机requests3805m/6000m，VM可用11142Mi、根盘20835Mi，Mac swap2550.5→2542.5Mi，无停止阈值触发。原分析预算5620m若加225m及250m储备将为6095m，后续须重新准入并释放足够余量，不降低安全储备或声称联合分析已经完成。不要在保留离线admission webhook时直接将证书控制器缩到0。详见[学习清单](DEVOPS-LEARNING-20261019.md)。


## 2026-10-19 IaC步骤预算

本轮不新增常驻Pod/PVC。Ansible/Terraform每步MemoryMax768MiB、CPUQuota100%、TasksMax128、RuntimeMaxSec600，外层1024MiB预算和原1250MiB储备，沿用原停止阈值及同一共享Lease。26个步骤的cgroup memory.peak采样最大99.22MiB，所有临时进程退出确认后恢复Jenkins/释放Lease；不得将缺失的峰值计数当作0。详见[IaC实操](IAC-LAB-20261019.md)。


## 2026-10-20 发布实验完成

发布实验继续共用platform-heavy Lease，先Jenkins quiet后启动；1024Mi预算加1250Mi储备，灰度/蓝绿串行，结束确认web为0才释放。96Mi的Jenkins中继禁止并行Node exec；读取构建状态/归档同样必须持有petclinic-jenkins-relay.lock串行执行。本轮曾因未遵守串行约束触发OOM保护，已保留失败和恢复证据，未降低阈值或扩大中继限额。[详细资源采样](ROLLOUTS-LAB-20261020.md)。


## 2026-10-25 Terraform执行隔离完成

详见[本轮验收、重跑与资源记录](TERRAFORM-ISOLATION-20261025.md)。计算按需串行1Pod，100m/384Mi请求、1CPU/512Mi上限，结束全部回收；现有状态与锁保留。构建准入保留原停止线加2GiB增长预算，扫描刷新另需4GiB。公开工具去重后路径共享inode，更新必须新文件加rename，禁止原地覆盖。扫描完成不等于零漏洞，K3s静态加密仍关闭。

## Terraform 安全重编译资源约束 · 2026-10-26

主盘获准由250GiB扩至258GiB，保留原15%可用空间加8GiB任务余量的停止规则，Mac仍保留16GiB。新增首次安全构建启动门槛为停止线再加4GiB增长余量；不以临时移除MySQL镜像后的瞬时空间替代预算，集成测试会重新拉取它。

Provider原生编译CPU1、内存/含swap上限1536MiB、pids128、超时900秒、临时目录3GiB；Go并发1、目标堆768MiB，实际进程及cgroup峰值单独记录。源码、SDK只读，编译无网络，第二次编译使用空缓存。新增阶段使用已有Jenkins外层platform-heavy锁，不再申请第二把锁；受控清理成功后才释放。临时任务执行Pod继续按原请求100m/384Mi、限制1CPU/512Mi运行，不新增常驻计算组件。

构建197–205本轮Docker本地副本的备份、逐层校验、实际恢复验证及无容器引用检查后清理已单独获准；不扩大至Kubernetes缓存、Registry/Harbor原件、PVC或其他版本。缓存和误报策略的证据保留参见[TERRAFORM漏洞治理](TERRAFORM-VULNERABILITY-ZERO-20261026.md)。Airflow既有验收结论沿用其独立记录；本轮不重新验收，也不代标完成。

本轮最终实测：根盘可用50.99GiB、VM MemAvailable 9.92GiB、Mac数据盘56.75GiB；临时执行与编译资源均为0。CI199编译临时目录采样峰值2318MiB，3GiB上限已实测通过；CI200完整发布和独立复验通过，原始发现1/误报1/真实0，详见治理记录。
