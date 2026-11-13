# 2026-10-15 分析流程验收记录

本记录按实际运行更新。独立 Spark 已通过，联合 Spark/Flink DAG 仍在验收，不能用组件 Ready 或历史单组件结果替代。

## 已通过的独立 Spark 业务验收

沿用原 Spark 4.0.1、既有启动入口、Operator 2.5.1 和已有业务数据，没有重装 Spark/Hadoop。Operator 与 Webhook 各 1 副本的期望状态已写入 `k8s/production/spark-operator-application.yaml`，现场 Argo Synced/Healthy；Driver/Executor 计算按需创建并回收。

快照原始 1200 条、唯一 visit_id 1200 个，日期 2008-09-04 至 2026-10-01；查询范围 2026-01-01 至 2026-12-31，当前实际计算年度 923 条。年度类型 bird153/cat155/dog154/hamster153/lizard154/snake154。以上是运行结果，代码未硬编码这些计数；源数据标记 demo，不冒称实际临床数据。

|SparkApplication|Application ID|Job ID|业务开始/结束 UTC|Driver / Executor 内核峰值|
|---|---|---|---|---|
|petclinic-spark-233743-1|spark-0ba63f3fbd5d4d2ab8b8cced28d79e9c|0..15|10-14 15:38:08.834220 / 15:38:39.475469|559.1 / 397.5 MiB|
|petclinic-spark-233743-2|spark-54d55569cc874476928d40c0c6638b37|0..15|10-14 15:39:44.862803 / 15:40:11.292830|479.4 / 393.0 MiB|

两次均与 MySQL 独立聚合一致，同批次再次写入仍保持 1200 条/1200 唯一 ID。实时 Driver UI 两次实际验证通过，完整应用、Jobs API、日志和统计证据在私有 `spark-after-disk-repair-20261014`。Driver/Executor/本轮 SparkApplication 已回收，Operator/Webhook 保留。4040 UI 随 Driver 退出而结束，不提供虚假的永久历史地址。

## 联合流程与受控中断

代码实现有界快照→质量与 MySQL 基准→Spark→结果核对→Flink/Kafka 五秒窗口→暂存分析结果→Trino 与真实 Superset 图表查询→事务发布→清理。Spark/Flink 串行，等待 Spark 使用已安装 provider 的 reschedule sensor，不增加常驻 triggerer。

首轮 `manual__orchestration_20261015T123925_1_none` 已运行 acquire/snapshot，但页面取证请求失败导致控制器受控中断，没有完整业务成功。私有目录 `airflow-e2e-20261015` 保留状态、采样、HTML、应用日志和 abort-cleanup 记录。现场确认 Airflow 核心 0、Flink 0、SparkApplication 无残留，Jenkins 恢复。该尝试不算正常或受控 Flink 失败验收通过。

现场重复测量发现 Mac 对 .local 的解析每次约 5 秒；显式解析到既有服务器后 DNS 接近零、页面 HTTP200 约0.12秒。修订保留原域名/入口，减少重复页面取证请求，记录失败 HTTP/退出码/stderr。新修订仍走完整流水线；#143 官方 Ubuntu 安全包下载超时，未晋升，重跑 #144 后才继续验收。

## 数据与资源边界

共享 data-infra/platform-heavy Lease 与 Jenkins quiet 状态由每轮 DAG 自己管理，验收控制器不再次申请同一把锁。启动前连续五次资源准入，预算及停止条件见 [资源政策](RESOURCE-POLICY-20261011.md)。轻量 Mac LaunchAgent local.petclinic.resources 已安装，发布真实 Mac/VM 新鲜样本；过期90秒则停止准入，Mac 休眠或观察器停止时不能伪造健康值。

结果以有界批次和源/业务维度摘要标识。失败批次不替换最近成功结果。DDL 单独由 `migrate_schema.py` 在分析 schema 备份后执行，分析角色未获 CREATE 权限；应用角色仅可读汇总及执行状态。备份/迁移证据位于 analysis-migration-20261015。

Kafka 复用 petclinic-window-092657-input/output，consumer group petclinic-airflow-window-v1。消息为 snapshot_id、visit_id、visit_date；snapshot_id 为有界批次身份，执行身份独立记录。输入限定本次捕获的 partition0 末端 offset，输出只读本次起点后的 read_committed 记录，并核对 checkpoint、已提交位点、窗口唯一键和 MySQL 聚合。没有覆盖 Topic、清空持久状态或把启动日志当业务消息。

## 待验收项

四轮正常、最终失败、重试成功、同批次复跑仍待全部完成。必须保存 DAG Run/Task 尝试、真实 Spark/Flink IDs、Kafka 消费、Trino Query ID、图表响应、页面状态及资源证据后才可开启 Asia/Shanghai 每周一02:30；catchup=False、同一时间一轮。当前不能宣称联合编排完成。

云节点 Alloy Pod 到本地 Trino 协调器 v1/info 实测 HTTP200，仅证明这条 HTTP 链路；云 worker 仍为0，未证明注册/交换链路已修复。Alertmanager 内部触发、接收、namespace 路由和恢复已验收；无获授权外部通知渠道，外部送达仍未验证。

## 2026-10-16 接续恢复

00:57 现场 UTM devops 为 stopped、SSH 不可达；宿主可用约68GiB、EFI变量盘仍约1MiB。启动前对主盘与固件盘分别进行 qemu-img check，两者退出0/check-errors0，未再次修复或更改磁盘内容。正常启动后 SSH、三节点 Ready、systemd失败0恢复，三业务副本、Trino、Superset、Alertmanager随后恢复；新启动内核未见 ext4/I/O/OOM错误。上一启动journal在10月15日22:43附近结束；进一步取得 macOS unified log，22:43:31 UTM 记录 Application Termination commencing/Termination complete，随后 QEMULauncher 退出。证据支持这次 VM 停止伴随 UTM 应用退出，发起退出的来源仍未确认，不能将其归因于磁盘再次损坏。

#144 同一修订因连接Mac代理超时未晋升，生产继续#142。当前Mac与VM经现有代理访问官方Ubuntu包地址均HTTP200。新增构建用户持久SHA256缓存，Maven clean后仍可复用；缓存命中、损坏缓存重下、错误下载拒绝三测试已通过，Node测试合计32通过。10个固定官方包已实际下载并逐一核验，缓存预热不改变镜像内容，CI仍重新核验每包摘要并执行完整构建/扫描/发布。#145发布与新DAG验收结果继续补录。

#145 已完整 SUCCESS，耗时504.681秒，94项Java/32项Node通过；源码092738cb3dacdedd59bce2c1609df91c71af7dfd、晋升06f1e2b45e36b7771ce2e933d2cfaebbdc01819f、镜像sha256:a78288f407c99ebcb7332441501063dc878a41d9390599c673bd864eb49158c5。双架构实际扫描Critical0/High0/Medium169/Low15，Argo、三副本、健康与Kafka发布事件均通过。新的四轮验收证据目录为 airflow-e2e-20261016。

## CPU 阻塞后的修复（正在验收）

新Run manual__orchestration_20261015T171536_1_none 已通过快照与MySQL核对：1200/1200、年度923及六类型一致。SparkApplication petclinic-airflow-66665c79d46a，Application ID spark-bced11df2ec34ec1888fbecf13aa4092，Driver Web UI实际在RUNNING时读取成功；但Executor因CPU requests缺120m Pending，业务Spark Job尚未完成，不能将此UI成功冒称新DAG Spark业务通过。该轮受控中断并确认SparkApplication、计算、Airflow核心和Lease均已回收，原记录保留。

修订加入CPU requests预算及250m调度储备；在Jenkins静默且无构建时，受控暂停空闲SonarQube500m请求，计算回收后先恢复SonarReady、再恢复Jenkins。原副本/UID保存在同一Lease，更新只针对明确资源和owner，新增Sonar命名空间RBAC仅允许get/patch指定StatefulSet。没有新增Sonar管理令牌或扩大原token权限。最终发布步骤移到清理成功之后，避免清理失败时提前替换结果。14项Python测试通过，涵盖CPU单位/向上取整、原生sidecar/init峰值、外来owner拒绝恢复；完整发布为#146，尚待其完成后重跑四轮。

## 10月16日联合计算进展与实际失败

#146完整发布成功，耗时743.948秒；源码4db0e94d260f555c8ce31746f2c4788db8e3e0c8，晋升c0b56fdfbfa250238683b70d4d8ffcdd773ead5e，镜像sha256:4f3ae58eb94e57e38092da97be156fade90a65eaf432603efacdeda7d2dd4eec。双架构Critical0/High0，Java94/Node32、质量门、Argo、业务健康及Kafka发布验收通过。

首次启动Airflow时宿主机swap增量536.19MiB超过512MiB阈值，控制器在触发DAG前停止并回收；未放宽阈值。随后连续六次约110秒重新评估，swap从2969.31降至2905.31MiB且后三次稳定，VM可用11951–12133MiB，才重新准入。原停止证据与重新评估各自保留，没有在运行中重设基线。

Run manual__orchestration_20261016T003932_1_none 实际通过CPU准入：受控暂停Sonar500m后可用2380m，覆盖计算2000m和250m储备。SparkApplication petclinic-airflow-db786d5fb45e 实际完成，Application ID spark-abaeb00038d741ef91bceca726175127，Jobs 0–15，业务计算00:42:06.736911Z至00:42:42.336590Z。原始/唯一1200/1200，2026年度923，与该次MySQL基准一致。Driver峰值582250496字节、Executor423948288字节；运行时UI实际读取成功。

该DAG仍失败：spark_result两次尝试均在读取结果时出现JSONDecodeError Extra data，未进入Flink。修订04f86c9643d1a9aff1b236ef40bb590d002b628e按唯一业务标记解码完整JSON对象，允许随后日志，拒绝重复或截断业务帧，17项Python测试通过。修复走#147完整流水线，结果待补。

该失败轮cleanup成功，确认Sonar原UID/副本恢复且Ready、Jenkins恢复原非静默状态、Lease与计算资源回收；失败状态可在业务页查询。独立Spark和本轮Spark业务完成不能代替联合端到端通过。私有证据：airflow-e2e-20261016-cpu-retry、mac-reassessment-20261016.json。


#147完整流水线SUCCESS（472.903秒），源码04f86c9643d1a9aff1b236ef40bb590d002b628e、晋升c9d4ff6c8f9a170f2b71a5d236c49f76a75cc6ed，镜像sha256:db78a09a6036d9dd2d49002bce90805f0bfd886778eb145fcb636dae3ba473ce；双架构Critical/High0、业务三副本/健康与Kafka发布通过。四轮联合验收重新从新目录airflow-e2e-20261016-framed开始，旧失败目录保留。

#147后首次airflow-e2e-20261016-framed在启动前采样因Mac swap+637.07MiB停止，没有触发DAG。七次连续重新评估通过后，新目录airflow-e2e-20261016-framed-retry开始新准入；前轮未覆盖。

新Run manual__orchestration_20261016T010519_1_none 已通过Spark结果读取：SparkApplication petclinic-airflow-bd0041bab8bc，Application ID spark-890e2c1118bf4d2e8af1d707b59f1409，Jobs0–15，01:08:00.017311Z至01:08:42.660365Z，Driver599580672字节/Executor420454400字节。现场UI已读取、sensor实际up_for_reschedule，读取修复首次真实通过。随后Flink Job29dd05f7afaf6620224293b3003bfa43通过真实消息验收：checkpoint5、输入2400→3600、输出740→1110、已提交消费位置3600/lag0、窗口1200与年度923。此处仅记录已执行阶段；Trino/图表/最终清理及四轮整体验收仍待后续结果。

## 上午完整计算与最终安全停止

manual__orchestration_20261016T010519_1_none 的Spark、Flink、暂存、Trino、Superset图表均实际success。Trino Query ID20261016_011357_00000_5ym5y，原始1200/年度923；Superset chart3实际HTTP200、status success、total_visits923，SQL和响应保存在xcom.verify。最终恢复阶段控制器触发Mac swap+512MiB停止线，故未完成整轮。受控退出已恢复Sonar原UID/副本Ready、恢复Jenkins并回收Lease/计算/Airflow。下午重启后直接数据库复核：execution为failed/controller-abort，airflow批次run仍pending，最近success仍为旧成功结果，没有提前替换。不能将这一轮写成DAG成功或完整端到端通过。

## 宿主机与VM内存回收修复（继续验收）

13:30起取得专用维护Lease并确认Jenkins空闲/静默，正常systemctl poweroff；原UTM config完整备份与SHA256保存在私有balloon-recovery-20261016。发现UTM 4.7.5 BalloonDevice=false且无设备，客机28GiB、宿主32GiB，客机约12GiB MemAvailable而宿主swap持续增长。参考UTM官方Balloon说明及QEMU实现，以受支持UTM update configuration接口仅向AdditionalArguments加入-device virtio-balloon-pci,free-page-reporting=on，原生BalloonDevice仍false以免创建设备两次。原6CPU/28672MiB及Drive/Network完全一致。主盘、EFI只读qemu-img check均退出0/check-errors0，未再次修复元数据。启动内核明确Free page reporting enabled，virtio_balloon绑定virtio6。此设置针对空闲页回报，不强制收缩客机内存，效果须由完整复测确认，不因配置开启宣称换页根因已全部解决。

官方参考：https://docs.getutm.app/settings-qemu/qemu/#balloon-device；https://github.com/qemu/qemu/blob/master/hw/virtio/virtio-balloon.c。旧记录全部保留，后续验收使用新目录airflow-e2e-20261016-balloon。

设备启用后的airflow-e2e-20261016-balloon仍在启动前触发宿主swap增量停止，未生成DAG；不能将该配置单独称为修复成功。随后取得新维护Lease、确认Jenkins空闲静默，正常sync后仅echo 1到drop_caches，释放可丢弃的文件页缓存，不删除持久文件/表/镜像，也未回收应用堆。客机Cached12454684→3492768kB、MemFree278756→9823596kB，MemAvailable仍约13GiB；说明原MemAvailable包括大量可回收页，不能直接等同于已经返还宿主的物理内存。七次后续健康采样全通过，Macswap3455.56→3419.81MiB，memory full PSI最高0.05%、IO最高0.97%。操作证据page-cache-reclaim-20261016，Lease按UID删除、Jenkins恢复；未配置周期性drop_caches。新验收目录airflow-e2e-20261016-reclaim。

## 本轮第一份完整正常验收（已通过）

Run manual__orchestration_20261016T054902_1_none 最终success，12个业务/清理任务全部一次success，failure_status正确skipped。SparkApplication petclinic-airflow-260a437535da，Application ID spark-b9e5e0faf2fe49c1b2346c587117e40e，Jobs0–15；计算05:51:34.528356Z至05:52:15.867215Z，Driver峰值586399744字节，运行UI实证保留。Flink Job57e574cdb0b1b739f29cfe5d3753598a/checkpoint5；输入3600→4800、输出1110→1480，窗口1200/年度923。Trino Query20261016_055722_00000_nkm95，Superset chart3实际HTTP200及923与MySQL一致。

cleanup实证released/sonar_restored/jenkins_resumed均true，Sonar恢复原副本1且Ready后才complete成功。页面HTTP200、analysis-success；运行阶段analysis-running也已捕获。数据库事实1200/唯一1200，daily总行数1918、type总行数42（包括已有版本历史，不是当前年度数量），作为后续重复执行不增长的比较基准。批次airflow:petclinic-2026-01-01-2026-12-31-2210df422082复用上午已暂存的不可变结果，generated_at仍为首次暂存01:13:24.23898Z；本轮实际完成时间以DAG/Task及execution状态记录为准，不能将重跑伪装成新输入或重复改写结果时间。

第一轮完成时，acceptance.json仅有这一轮，控制器随后继续验证最终失败、自动重试及同批次复跑；未提前开启定时。后续第二轮与第三轮的最终状态见下方记录，不能把此处的阶段快照当作当前运行状态。

## Alertmanager 10月16日复验（已通过内部流程）

测试ID20261016T060733，三条Prometheus规则实际health=ok/firing；namespace monitoring/petclinic/ns-bigdata在Alertmanager分别进入platform-local/petclinic-local/analytics-local接收器。将本轮规则改为不满足条件后，Prometheus三条inactive、Alertmanager测试活动告警为空；临时规则按原UID前提删除。接收指纹、分组与Prometheus发现的Alertmanager地址均保留于alertmanager-20261016；完成时刻06:09:33.758187Z。没有创建/使用外部通知渠道，external_delivery_verified=false。原K3s目标Down告警仍保留，未宣称全平台无告警。

## 第二轮最终失败验收（已通过预期失败）

Run manual__orchestration_20261016T060215_2_fail 最终failed。Flink尝试1 Job0791ecfacf1bfaed01682bea0557bd20，输入4800→6000/checkpoint5；尝试2 Jobab30ecbf0b9c80fc0f2041b2b63a4b8c，输入6000→7200/checkpoint5。两次均实际消费/提交窗口1200、年度923后触发controlled_failure=true；没有以模拟启动失败替代业务失败。publish/verify/complete均upstream_failed且未执行，不存在本轮Trino Query ID或图表新响应。cleanup一次success，Sonar/构建调度/Lease均恢复；最终failure_status failed1保持DAG真实failed。

数据库最近成功run_id及generated_at与第一轮完全相同，事实[1200,1200]、daily总行1918、type总行42全部不变；页面HTTP200、analysis-failed。此轮是预期失败验收成功，不应将DAG本身标绿。随后第三轮验证首次失败、第二次成功的自动重试恢复，最终状态如下。


## 第三轮业务通过、构建服务恢复超时（联合编排未完成）

Run manual__orchestration_20261016T061722_3_retry 的Spark结果核对、Flink第二次尝试、暂存与Trino/Superset验证均通过。SparkApplication petclinic-airflow-a766d6fbb2f3、Application ID spark-ad89963970e841868ad0228b6aeb7bca，Jobs0–15；Flink第二次尝试Job243a286fcf1aa57201bea7f65774347a/checkpoint4，输入8400→9600、输出2590→2960，实际窗口1200/年度923。Trino Query ID20261016_062818_00002_nkm95，Superset chart3 HTTP200、年度923，与MySQL基准一致。以上仅说明实际业务阶段通过，不等于本轮DAG成功。

cleanup于2026-10-16 06:28:43.403328Z启动，解析完成后06:28:58.368337Z开始工作；06:32:19.795654Z因内部约200秒的Sonar readiness等待耗尽而失败，错误为Sonar readiness not restored; retain Lease and Jenkins pause，并非触发Airflow任务7分钟超时。状态采样06:29:01.601136Z已见Sonar原StatefulSet副本恢复为1、ready0；06:33:15.622917Z仍ready0，06:33:31.627386Z首次ready1，恢复耗时约257–273秒，超过原等待预算。原始任务日志、build-service-samples.json和abort-sonar-restored.json均保留于airflow-e2e-20261016-reclaim。

complete为upstream_failed，failure_status失败，整轮DAG最终failed；发布保护未因业务查询成功就提前标绿。控制器finally已停止本轮调度、回收本轮计算，按原UID恢复Sonar副本1且Ready，随后清除owner标记并释放Lease；06:34:03.256956Z采样确认owner为空且Lease不存在。Airflow核心随后按需关闭，Jenkins恢复，Spark Operator/Webhook保留。不能把控制器恢复成功改写为DAG cleanup成功。

实际验收窗口内143个控制器资源样本（05:45:46.740790Z–06:32:49.499021Z）中，VM可用内存最低11222.39MiB、Mac空闲最低36%，宿主swap基线及峰值3782.62MiB、末次3271.81MiB；memory/io full PSI最高0.18%/5.58%，API与业务HTTP无失败、无资源安全停止。独立usage观察器同窗162样本记录VM可用最低11129.02MiB、PSI最高0.22%/7.73%，同样未触及停止线。观察器在控制器退出后仍保留过后续采样，不能把后续数小时的swap变化归因于本轮任务峰值，也不能据此断言宿主换页问题彻底解决。

截至这份旧目录的最终记录，acceptance.json仅接受正常成功与预期最终失败两项；第三轮不计通过，第四轮同批次复跑未执行，低频定时未开启，联合编排未完成。恢复等待与各层超时的修订须走完整私有流水线并在全新证据目录重新验收，发布结果和新验收结论另行补录，不覆盖本轮失败现场。
