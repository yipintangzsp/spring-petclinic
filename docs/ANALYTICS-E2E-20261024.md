# 2026-10-24 联合分析发布与四轮验收

本轮主线已完成：Jenkins #188 完整发布成功，实际运行源码0a51371151c57cf40b0389595ced3334e6645aef；当前1202条来源的四轮联合验收通过。流程为有界快照→MySQL核对→Spark→Flink/Kafka→幂等发布→Trino/Superset→资源回收。以下“历史断点”中的未完成状态仅说明当时现场，当前结论以本节及最终审计为准。

## 验收范围与数据

同一批次 `petclinic-2026-01-01-2026-12-31-57eccc81792b`；输入1202、唯一visit_id1202、owners200、pets350、vets20，来源日期2008-09-04至2026-11-01；快照最多5000条，年度核对窗口2026-01-01至2026-12-31。快照SHA256为3146f2ea87775272ab6dee821ec6f504bf4425ffd716aa5c0c73012ae49cc276，创建任务起止时间与每轮快照标识保存在各Run的TI/XCom。来源为既有PostgreSQL演示数据，包括未来登记日期；年度925不能解释为已完成诊疗。MySQL基准是同一受界快照落入既有MySQL基准表后独立SQL核对，并非另一套独立生产MySQL源。

Spark、Flink、MySQL、Trino、Superset年度结果均925；按宠物类型bird153、cat157、dog154、hamster153、lizard154、snake154；年度日统计275行。首次发布实际补入低ID8和11共2条，后续成功运行new_input_rows=0，事实表始终1202行/1202个唯一ID。历史总daily_rows2193、type_rows48包含旧批次，不是本轮年度行数。

## 四轮真实结果

|场景|DAG Run ID（UTC时间编码）|结果|Flink尝试|Trino Query ID / 图表响应|
|---|---|---|---|---|
|正常|`manual__resume_20261024T073835_1_none`|success|1|20261024_074829_00000_c56av / 200|
|受控失败|`manual__resume2_20261024T081236_2_fail`|failed|2|上游失败，禁止发布/查询新结果 / 未执行|
|失败后重试成功|`manual__resume2_20261024T082633_3_retry`|success|2|20261024_083842_00002_c56av / 200|
|同批重跑|`manual__resume2_20261024T084239_4_none`|success|1|20261024_085311_00004_c56av / 200|

受控失败的两次尝试均先实际生成Kafka窗口结果及完成检查点，再主动抛错；publish/verify未执行，失败状态可见，最近成功结果及其时间戳完全未变。重试场景第一次同样真实失败、第二次成功；不是只制造启动错误。各轮cleanup均成功，Sonar恢复1/1后释放共享Lease，Jenkins恢复原非quiet状态。成功页、失败页与运行中页均留有HTML证据；同批重跑没有新增事实或汇总行。

所有Task Instance逐项状态、try_number、start/end位于私有airflow-e2e-r2/acceptance.json；正常轮原始任务日志在airflow-e2e，其余三轮在airflow-e2e-r2的对应Run-task-logs目录。失败轮failure_status为failed以避免all_done清理把整轮误判绿；正常轮该任务skipped。

## Spark真实计算与临时UI

|SparkApplication|Application ID|计算开始/结束（UTC）|Job IDs|Driver / Executor cgroup峰值MiB|
|---|---|---|---|---|
|`petclinic-airflow-7ebd251550b3`|`spark-19988e8a7a71407f930969e60f66a696`|2026-10-24T07:41:55.959694+00:00 / 2026-10-24T07:42:40.766167+00:00|0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15|565.11 / 399.26|
|`petclinic-airflow-671541b3734e`|`spark-7cf660edd7d84dfb9b20edf8651dcfbe`|2026-10-24T08:15:33.730575+00:00 / 2026-10-24T08:16:15.525202+00:00|0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15|558.88 / 396.72|
|`petclinic-airflow-ea7c5cc01b42`|`spark-af0057dfaacc4660ae4cd27489e75fdc`|2026-10-24T08:29:31.430134+00:00 / 2026-10-24T08:30:19.701663+00:00|0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15|472.86 / 391.86|
|`petclinic-airflow-c4eb783c268a`|`spark-3e67261239d344ccbc4629db5f5a93b4`|2026-10-24T08:46:18.111446+00:00 / 2026-10-24T08:47:09.711612+00:00|0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15|480.96 / 388.78|

每轮运行期间Driver UI的HTML及applications/jobs REST已实际读取并留证。Mac本地临时转发127.0.0.1:14040也曾HTTP200；浏览器打开时该Driver已结束，未宣称浏览器打开通过。UI只随Driver存活，结束清理后不可访问，未安装History Server。下一轮运行中获取实际Driver IP后执行：

```sh
ssh -o HostName=192.168.64.11 -o HostKeyAlias=192.168.1.58 -L 4040:<Driver-IP>:4040 zhang@192.168.1.58
```

本机访问localhost:4040。各轮实际命令、IP、应用和作业列表在私有spark-ui目录；运行后查看Airflow spark_result日志、保存的Spark JSON/log与summary.json，不沿用过期Pod IP。

## Flink、Kafka及重复运行语义

复用既有Topic petclinic-window-092657-input / petclinic-window-092657-output，consumer group petclinic-airflow-window-v1；未覆盖或清空Topic。输入结构为snapshot_id、visit_id、visit_date；输出含snapshot_id、visit_date、window_start、window_end、visits。窗口为5秒processing-time重放，保留业务日期用于年度对账，不冒称事件时间水印任务。每次执行重放本批1202条，Kafka日志因此增长；幂等保证指最终业务事实和汇总，不是Kafka消息不再生成。仅从本轮输出起始位点读取read_committed结果，按批次与窗口键核对、拒绝重复最终键；SQL按批次/业务主键写入，失败轮不覆盖最近成功结果。

|DAG Run|尝试|Flink Job ID|checkpoint|输入offset|输出offset|
|---|---|---|---|---|---|
|manual__resume_20261024T073835_1_none|1|`a792da0b2b57695cc2657fe8850da8c5`|6 COMPLETED|22802→24004|7151→7848|
|manual__resume2_20261024T081236_2_fail|1|`4a46417b1c8b5601d99fc6de6d1af0fd`|5 COMPLETED|24004→25206|7848→8219|
|manual__resume2_20261024T081236_2_fail|2|`af550bde593a6e44bdd623624910e317`|6 COMPLETED|25206→26408|8219→8590|
|manual__resume2_20261024T082633_3_retry|1|`0aecd05fe5cbadedf03536db080b2b27`|6 COMPLETED|26408→27610|8590→8961|
|manual__resume2_20261024T082633_3_retry|2|`e6291e51f9af852671b22ae42d16b5d2`|5 COMPLETED|27610→28812|8961→9332|
|manual__resume2_20261024T084239_4_none|1|`9c0927f5bb112e0a4d1787e1fe5a3563`|5 COMPLETED|28812→30014|9332→9703|

六次尝试均真实核对输入1202、输出总1202、年度925及已提交消费位点；消费组lag记录与检查点状态/路径、消息样本保存在summary.json、XCom及CLINIC_FLINK_EVIDENCE任务日志。检查点目录保留在服务器/opt/petclinic-observability/state/flink/petclinic-window-092657；JM/TM在每次尝试finally回收，结束后Flink临时UI不可访问。

## 资源预算、停止与最终状态

Mac物理32GiB，VM原6CPU/28GiB（Linux可用总量约27994MiB）保持不变；预算包含全部常驻服务（MySQL、Kafka、Trino、Superset、业务和系统），不因只测引擎而漏计。空闲CPU请求4545m，持Lease且Jenkins空闲后受控暂停Sonar500m，加执行Pod100m、串行Spark/Flink1500m与储备250m，总5895m≤6000m；剩余105m很小，新增常驻负载必须重新准入。剩余内存预算为引擎4096MiB、执行Pod768MiB和安全储备1250MiB，共6114MiB；Airflow核心已计常驻，不再启动额外512MiB控制Pod。Airflow升级阶段另计3072MiB。

每轮五次准入与运行中采样继续执行Mac余量≥10%、磁盘≥16GiB、swap增长≤512MiB，根盘15%容量+8GiB（本机45667.834MiB），扫描DB刷新另留4GiB。VM MemAvailable运行中≥1536MiB、memory full PSI≤5、IO full PSI≤10、无新增OOM/Eviction；不降低原阈值。Spark和Flink串行，不在内部再次获取外层共享锁，Jenkins重任务与分析互斥。Spark Driver/Executor各requests750m、CPU limits1000m；Flink任务Pod requests100m/768Mi、limits500m/768Mi；DAG max_active_runs=1、max_active_tasks=1、60分钟整轮、一般任务12分钟/一次重试、cleanup15分钟不重试。Spark sensor实际reschedule，已观察up_for_reschedule；Flink由一个受界执行Pod轮询，不宣称零资源等待。

E2三轮资源采样（正常轮另见E1）最小VM可用9831.7MiB、根盘空闲48776.7MiB、Mac内存余量39%；完整Pod CPU/workingSet/RSS峰值见summary.json。最终三次空闲资源采样与80项工作负载状态见final-audit.json、workload-inventory-final.json、idle-kubelet-stats.json。

另有一次实际安全停止manual__resume_20261024T075300_2_fail：Mac swap从Lease基线1620.31增至2247.62MiB，增长627.31MiB超过512，Spark等待阶段失败两次、没有执行预定Flink失败注入；该轮不计入上述四轮。清理恢复后，在无任务/无Lease时sync并仅释放干净page cache，未删除文件或重启业务；VM空闲页约0.8→6.1GiB，QEMU RSS实际约减少944MiB，连续采样后再开始新的三轮。没有重置运行中基线或降低保护。

最终独立核验：无本轮SparkApplication/Driver/Executor/Flink临时Pod，无共享重任务Lease；Flink JM/TM为0；Spark Operator及Webhook各1/1并保留GitOps期望。Airflow API/Scheduler/DAG Processor/statsd各1，triggerer0，Sonar1/1，Jenkins已恢复，当前无活动DAG。新增platform-airflow.json与已验收在线Application spec逐字段一致并通过服务端dry-run；固定受检源码避免下次同步退回旧任务。

## 触发、看结果与故障处理

入口：petclinic.devops.local/insights；airflow.devops.local 的petclinic_insights；superset.devops.local/superset/dashboard/petclinic-analytics-20261011/。Mac实际域名HTTP访问三处均200；Superset图表3每次成功轮强制查询返回HTTP200和925，未只检查health。周一02:30（Asia/Shanghai）低频运行，catchup=False，一轮并发；本轮保留既有计划并完成新源码复验。

命令触发整条默认2026年度流程：

```sh
ssh -o HostName=192.168.64.11 -o HostKeyAlias=192.168.1.58 zhang@192.168.1.58 \
  'sudo kubectl -n data-infra exec deploy/airflow-scheduler -- airflow dags trigger petclinic_insights'
```

也可在Airflow中Trigger DAG，参数from/to为日期、verify_retry=none；retry/fail只用于明确受控演练。查看Graph/Grid逐项TI与尝试日志、snapshot/spark_result/flink/verify/cleanup的XCom；先定位失败阶段，再检查原资源停止原因、Kafka位点和各作业ID。清理完成后以新Run ID重跑整条DAG，避免单独清除已失去Lease/快照的中段任务；不要手工把失败状态标成功。若cleanup未成功，保留现场和owner信息，核对本轮UID/标签后只清本轮计算资源，确认Sonar Ready和Jenkins原quiet状态再释放Lease。

## 发布、安全及仍有限制的事项

#188版本0.10.0-ci-188，晋升678b1116d0b52100445138b10fa1187ef9fb61e8，OCI索引sha256:da217f4de816429c26543588e8047298a84091f299aa2dfe9e587e0f15184dc9。104 Java、58 Node、41 Python测试通过，真实PostgreSQL回归事务已回滚；Sonar新代码覆盖92%、门禁OK，仍有29项既有问题。双架构Harbor当前应用报告均Critical0/High0/Medium53/Low4，不等于平台所有组件无漏洞；原有漏洞说明另保留，不能以扫描成功代替无漏洞。CI临时PostgreSQL容器和本轮新建匿名卷已按精确标签/工作区清理，未改其他卷。

Prometheus Watchdog规则firing、Alertmanager实际接收并匹配platform-local已验证；三个现有receiver无外部渠道配置，外部通知送达未验证。云Trino worker当前按需0，本轮没有该worker运行日志，云端历史阻塞根因仍未确认；所有本轮Trino验收使用已有本地查询模式。其他组件不得因Ready而自动标为已接业务；逐项状态以组件清单本轮表及原独立验收引用为准。

本轮获授权137旧匿名卷已完整备份校验后删除，恢复步骤见[VOLUME-ARCHIVE-RESTORE-20261024](VOLUME-ARCHIVE-RESTORE-20261024.md)；原3卷、全部PVC与业务数据库保留。用户另准许的175/176/177/178/181/185及本轮Peach本地副本均核对Registry完整层摘要后清理，183/184、基础镜像和Registry/Harbor原件保留。详细净回收、备份权限和历史断点如下。

## 历史断点（按当时事实保留）


## 已确认并修复的数据缺陷

第一轮真实执行manual__completion_20261024T011534_1_none中，Spark与Flink均通过，publish因事实表数量不一致失败并回滚。现场来源1202、分析事实1200，最大事实ID1001195，缺失来源ID为8和11。旧逻辑只查询id大于水位，不能识别低ID的新记录。

源码3851c1aefd4a0de8cd26666f33f39f9e9a38364b改为主键及字段差异对账，补入缺失记录、幂等更新日期和宠物关联；不删除来源或事实记录，来源删除仍会导致数量核对失败。真实PostgreSQL临时表覆盖低ID补入、已有日期修正、同一批重复执行，生产SQL被直接提取用于测试，全部事务回滚。41项Python测试中的35项分析检查在#184时已纳入CI（#184总40项）；修复经#184完整发布为0.10.0-ci-184。Airflow已固定该受检源码，实际代码摘要与Git一致。

## 资源缺陷与待发布修复

第二轮manual__completion_20261024T014535_1_none在Flink阶段因根盘低于原停止线而受控停止。现有Flink启动把整套镜像库复制到emptyDir，JobManager、TaskManager和SQL client的临时库造成约1GiB峰值。源码ab949da改为直接复用镜像库，仅将原Kafka connector文件只读挂载到相同类路径；保留检查点/状态目录及原准备步骤。只接受已知模板、两个复制init步骤、指定的File类型connector卷；未知配置拒绝修改；副本必须为0，JSON Patch校验UID、原副本数及完整原模板，避免覆盖并发变更。

36项分析单元测试与5项消息测试在#185均通过，质量门、双架构构建、Harbor扫描与Worker部署通过，但Git Promotion被磁盘检查拦截，整轮#185为FAILURE。应用仍184，Airflow仍3851c1a；不能把新Flink实现写成已通过真实窗口作业。已验证Python Kubernetes客户端序列化与现场模板一致，同一JSON Patch的服务端dry-run通过；没有扩大scheduler账号权限。Flink修改仍待完整发布及真实端到端验收。

## 当前资源处理范围

原nodefs/imagefs的15%容量加8GiB停止线、Mac>=16GiB等保护保持不变。下载缓存检查未发现安装目录指向缓存的符号链接、缓存外链接或运行中缓存进程，使用uv自带cache clean实际回收56.46MiB；保留已安装环境。工具行为参考[官方缓存文档](https://docs.astral.sh/uv/concepts/cache/)。缓存逻辑大小不等于物理净回收量。

Docker现场有137个不被任何运行中或已停止容器引用的匿名卷，分配约6728683520字节（6.27GiB）；3个被容器引用的卷不在范围内。尚不能认定这些匿名卷都可丢弃，未删除任何卷。清单在Mac私有证据volume-archive-20261024/inventory.json。拟先完整备份到同目录archives，逐文件核对SHA256、属主、权限和源内容未变，再确认无引用后删除原卷。自动审批因备份可能将数据库或凭据内容导出到Mac、尚未获得该具体范围授权而拒绝；当前已向用户申请备份及后续删除的明确授权，未执行导出。

## 证据与后续验收

私有证据根为 /Users/zhangsir/code/evidence/platform-20261011：

- airflow-e2e-20261024：第一轮TI/尝试/日志、Spark UI和真实Flink结果、水位缺陷现场及回滚SQL测试。
- airflow-e2e-20261024-r2：第二轮安全停止、资源采样、配置原件及新Flink补丁dry-run；cleanup只处理本轮资源，Jenkins/Sonar恢复，Lease释放。
- airflow-fix-deploy-20261024：已发布增量修复的Airflow GitOps和代码SHA核对。
- messaging-20261023/ci-184、ci-185：完整流水线阶段、质量、测试、扫描和失败原因。

恢复空间后仍需完整发布新Flink实现，再执行正常、终止失败、重试成功、同批复跑四轮，保存新Spark/Flink Job ID、Kafka位点、Trino Query ID、Superset响应、页面状态和清理证据。最近成功分析923仍保留；实时RabbitMQ报表925及独立Spark/Flink成功不能代替完整联合发布和看板验收。

## 2026-10-24 下午恢复主线

源码0a51371修复#186的实际失败：Jenkins没有python3，测试资源清理改用现有Node，保护已有容器/卷、运行容器和其他工作区的回归测试通过。#187在测试前因漏洞库更新额外4GiB空间要求受控停止；#188在空间恢复后执行完整发布，最终结果需以后续记录为准。

137个匿名卷已获用户明确授权：完整压缩备份1114059791字节、逐文件SHA256/属主/模式及源稳定性核对通过，所有137个再次确认无引用后才逐一删除。原3个被容器引用的卷与全部PVC保留；根盘45249.0625→51647.0859375MiB，实测净增加6398.0234375MiB。备份保存在Mac私有volume-archive-20261024/archives，目录0700、归档0600；结果与删除清单分别为backup-complete.json、deleted-volumes.json、cleanup-result.json。旧“未获授权、未导出”段落是此前断点，现已完成此范围。

后续经独立授权，核对完整Registry清单及所有层SHA256后删除PetClinic175/176/177/178/181/185及Peach本地构建副本；184与183、所有基础镜像、Registry/Harbor原件、Kubernetes运行镜像、PVC和卷保留。随后仅沿用原CI的JAR缓存清理与本轮Peach精确缓存ID，解除旧引用后回收缓存；不按逻辑镜像大小估算物理回收。近期清理前47903.5390625、后50296.515625MiB，包含同期系统正常写入影响。完整证据在mainline-resume-20261024/approved-local-images、release-jar-cache、peach-build-cache。

Alertmanager复核：Prometheus Watchdog真实firing，Alertmanager已接收并匹配platform-local。platform-local、petclinic-local、analytics-local目前没有外部通知配置；外部送达未验收。云Trino worker期望副本0，当前没有云worker运行日志，本轮继续本地查询，不能据此写成网络根因已解决。
