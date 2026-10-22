# 2026-10-22 联合分析与发布验收

Jenkins #165 SUCCESS，发布0.10.0-ci-165，源码ecbae16a42c26118630784d14a7031a460bb21cd，晋升cc9adad3fb37c5cbe5fd0def8abf70a190075e97。49项Node、94项Java、Sonar、双架构构建、Harbor扫描、GitOps、Argo及Kafka发布事件均通过。两个架构各Critical0/High0/Medium176/Low15；不代表平台无漏洞。

## 四轮实际结果

|DAG Run ID|状态|Flink尝试|SparkApplication|Application ID|
|---|---|---|---|---|
|manual__orchestration_20261022T090559_1_none|success|1|petclinic-airflow-8c4bfc2c8ae0|spark-7436090b5b834e11bbdc387d973c38f3|
|manual__orchestration_20261022T091823_2_fail|failed|2|petclinic-airflow-d47ceb4db47a|spark-8e03916d54a74813945b2c864c18aedb|
|manual__orchestration_20261022T093140_3_retry|success|2|petclinic-airflow-10c67d039e8e|spark-52f171a38e3e4a748aa1ee113655ece1|
|manual__orchestration_20261022T094620_4_none|success|1|petclinic-airflow-310fb639ca03|spark-c3b42d9b3fae48f0b12344ee921bd13d|

四轮Spark Job IDs均0–15；运行时实际查询Driver UI applications/jobs接口。时间以下均UTC，上海加8小时。

|SparkApplication|开始|结束|Driver峰值bytes|Executor峰值bytes|
|---|---|---|---|---|
|petclinic-airflow-8c4bfc2c8ae0|2026-10-22T09:08:42.511144+00:00|2026-10-22T09:09:19.600605+00:00|589565952|415465472|
|petclinic-airflow-d47ceb4db47a|2026-10-22T09:21:03.911468+00:00|2026-10-22T09:21:41.374564+00:00|574238720|419434496|
|petclinic-airflow-10c67d039e8e|2026-10-22T09:34:16.655321+00:00|2026-10-22T09:34:50.382569+00:00|583159808|415047680|
|petclinic-airflow-310fb639ca03|2026-10-22T09:49:05.465329+00:00|2026-10-22T09:49:47.365022+00:00|594591744|423972864|

## 数据与重复执行

读取既有PostgreSQL演示业务快照，日期2008-09-04至2026-10-01，原始1200条、唯一ID1200。年度窗口2026-01-01至2026-12-31统计923，与MySQL基准一致。该结果由本轮重新计算，不能作为以后硬编码基准。按类型bird153/cat155/dog154/hamster153/lizard154/snake154。

批次petclinic-2026-01-01-2026-12-31-2210df422082；快照SHA256 e25777b6d49d1c0dfe07bb3759f43aaa85023b01964b19c41cd66335a1d687bc。同批复跑事实数/唯一数仍1200/1200，失败不覆盖最近成功。相同内容批次原生成时间2026-10-16保留，10月22日为重新执行核验时间，不伪造新数据更新时间。运行中/成功/失败页面均保存。

|轮次|Flink Job ID|Trino Query ID|Superset chart3|
|---|---|---|---|
|正常|36c1676981691d9277dfff5755ee73db|20261022_091435_00000_tgpyr|HTTP200，923|
|受控失败|两次失败尝试日志保留，未发布成功|未执行|保留最近成功|
|重试成功|81e45f4657cb55ab816f0544864ba2a0|20261022_094244_00002_tgpyr|HTTP200，923|
|同批复跑|ff17c54d5339cb4c5e7fbbcfa4757fc2|20261022_095449_00004_tgpyr|HTTP200，923|

成功Flink作业checkpoint5均COMPLETED，状态7927bytes。沿用Topic petclinic-window-092657-input/output、消费组petclinic-airflow-window-v1；三个成功轮消费位点13200/18000/19200，均lag0，输入1200、年度输出923。消息含snapshot_id、visit_id、visit_date，窗口结果包含visits/window_start/window_end。重试重新发送原始消息，不能宣称Kafka跨尝试exactly-once；结果按批次/主键事务幂等。

## 资源、调度及操作

连续180次采样，VM最低可用10117MiB；Spark/Flink串行。每轮cleanup成功、Sonar原UID/副本恢复Ready、Jenkins恢复非quiet，Lease释放，计算资源回收。Operator/Webhook常驻。10月23日复查三节点Ready、业务3/3，根盘可用53GiB、内存可用10362MiB。旧主盘快照经授权移除，释放86,243,983,360字节（80.3GiB），活动映射/全量摘要一致且磁盘校验无错，旧恢复点永久失去。

四轮通过后启用Asia/Shanghai每周一02:30，catchup=False、max_active_runs=1。启用后Airflow执行最近一期scheduled__2026-10-18T18:30:00+00:00，于10月22日09:59:42–10:11:44 UTC成功；没有批量补跑更早历史期。第五个SparkApplication petclinic-airflow-9fb4e0496d33来自该轮。

- 手动触发（HTTP入口）：airflow.devops.local ，打开petclinic_insights，Trigger DAG，沿用默认有界日期；Grid查看TI状态、attempt和日志。
- 业务统计（HTTP入口）：petclinic.devops.local/insights ；看板（HTTP入口）：superset.devops.local/superset/dashboard/petclinic-analytics-20261011/ 。
- Spark临时UI：`ssh -t -L4040:127.0.0.1:4040 zhang@192.168.1.58 "sudo kubectl -n default port-forward pod/<本轮driver-pod> 4040:4040"`，浏览器访问http://127.0.0.1:4040。Driver回收后失效，日志/Job ID/峰值保留在私有证据。Flink临时REST UI同样随计算回收关闭。
- 失败先看失败Task日志及尝试次数，核对资源准入、Lease、Jenkins/Sonar恢复，修复原因后重触发同批次；保留失败Run，不删除锁或降低门槛。

## 证据与限制

完整证据目录：`/Users/zhangsir/code/evidence/platform-20261011/airflow-e2e-20261022`。acceptance.json含每轮TI状态/尝试/起止、XCom及数据库不变量；resource-samples.json为连续采样；各轮task-logs含失败尝试。发布与Driver UI证据位于同级analytics-release-20261022/ci-165和spark-ui；磁盘证据位于recovery-20261022/main-snapshot。

Trino采用本地查询模式，云worker阻塞根因未解决。Alertmanager规则触发、内部接收/三个路由及恢复通过，外部通知送达未验证。平台其他镜像漏洞按HARBOR-HIGH逐项保留处理状态。Superset worker、云Trino worker继续按需关闭；Airflow核心常驻，任务计算按需。
