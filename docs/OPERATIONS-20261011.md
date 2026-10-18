# Petclinic 发布与按需分析操作

> 2026-10-14 当前状态以 [恢复与发布验收](RECOVERY-20261014.md) 为准：生产 #134；#135 受控停止；联合编排未完成（宿主磁盘不足、Java DB 更新网络受阻）。以下旧数字与验收属于历史记录。Spark Operator/Webhook 当前常驻保留。

本轮内部源码仅推送私有 GitLab `root/petclinic-platform`。公开 GitHub 原仓库和 Cook 的审查后公开导出流程保留；内部配置、网络、数据库备份、原始日志不得直接公开同步。详细组件、资源和发布结果分别见本目录 inventory、RESOURCE-POLICY 和 UPGRADE 文件。

## 业务与发布入口

- 业务统计：`http://petclinic.devops.local/insights`。输入日期为登记就诊日期，2026 年窗口923条；页面明确标记演示业务数据。总记录1200并非本年数量，未来预约不能当作已完成诊疗。
- Jenkins：`http://jenkins.devops.local/job/petclinic-ci/`，Petclinic视图可查看阶段、控制台、测试和归档。失败构建保留；测试/质量门失败时不会开始部署。
- Harbor：`http://core.harbor.domain/harbor/projects`；真实扫描通过指扫描执行成功，漏洞数另查归档。
- Argo：`http://argocd.devops.local/` 中 Petclinic Application。
- Superset：`http://superset.devops.local/superset/dashboard/petclinic-analytics-20261011/`，使用现有账号登录。
- Grafana：`http://grafana.devops.local/d/petclinic-release-analysis/`；既有应用看板 `petclinic-app-metrics`、平台看板 `petclinic-v09` 保留。
- Kibana 保存搜索：`petclinic-upgrade-20261011-logs`，按 `service.version`、`kubernetes.pod.name`、时间和 `trace.id` 查询。
- Jaeger：`http://jaeger.devops.local/`，service=petclinic。

这些主机名使用现有本地 DNS/hosts。端点未经本轮公开发布。原始验收证据在 Mac 私有目录 `/Users/zhangsir/code/evidence/platform-20261011`；主机一致性备份位于 `/opt/petclinic-observability/backups/platform-20261011`。

## 正常发布、回滚与恢复

审查代码后在私有 GitLab main 普通推送，由实际 Push Webhook 触发 Jenkins。Runner 只执行有界源码审计，不重复部署；Jenkins 顺序执行资源准入、94项 Java/29项 Node 测试、Sonar、双架构镜像、Harbor扫描、私有GitOps晋升、Argo/Endpoint/业务健康验收及Kafka发布事件。独立分析计算不在业务发布的同步等待链。

每次晋升提交同时使用 `[skip ci] [ci-skip]`，分别兼容 GitLab 和现有 Jenkins GitLab 插件；缺少第二个标记曾产生重复构建。本轮已实际阻止后续晋升再次构建。

从归档的 `promotion.json` 找出精确晋升提交，在私有源正常 `git revert <晋升提交>` 并推送。等待 Argo sync revision 与回滚提交一致、镜像digest正确、三副本及业务健康后，再 revert 该回滚提交并推送以恢复目标版本。GitOps-only 提交携带两种skip标记。不要使用强推或直接 `kubectl rollout undo` 绕过源记录。

本轮已实际执行的回滚/恢复修订分别是 `9a2f7dee2ce091c6961fd51f4c673786e5a4a6ec`、`cc19a4b628e20dc9dfca64333821586d0082d46b`。新增分析schema与旧应用兼容；应用回滚保留schema、事实、状态、备份和原业务数据。数据库恢复是单独批准的灾难恢复操作，不能作为发布回滚默认步骤。

## 分批分析

从隔离工作树运行 Python 控制器，始终使用一份新的私有 evidence 子目录。控制器每次读取实时容量/健康，获取共享 `data-infra/platform-heavy` Lease，暂停 Jenkins 新调度并检查已有构建，启动一个有界任务；正常结束后确认计算退出，再按UID/holder释放Lease和自己设置的quiet模式。资源不足会拒绝准入。不要绕过Lease或将过期Lease直接删除。

```bash
python3 infra/analytics/run_airflow.py \
  --revision 77c676e32f0d81aa150ee18455ad99b724e6d44f \
  --evidence /Users/zhangsir/code/evidence/platform-20261011/airflow-new-run

# 上一个控制器完全退出后，才执行下一个。
python3 infra/analytics/run_spark.py \
  --from 2026-01-01 --to 2026-12-31 --repeats 2 \
  --evidence /Users/zhangsir/code/evidence/platform-20261011/spark-new-run

python3 infra/analytics/run_flink.py \
  --evidence /Users/zhangsir/code/evidence/platform-20261011/flink-new-run
```

Airflow固定审查修订，DAG schedule=None，实际测试正常、重试、超时和重复执行。结果在隔离schema事务发布，访问超时3–5秒、有界5000行/366天；原事实按visit_id去重。当前源为append-only VisitController契约，不能将此增量方式冒称处理任意删除/更新的CDC。

Spark读取只有visit_id/date的1200行快照，输出真实Job IDs、年度923和driver/executor内核峰值。Flink读取明确标记demo的快照重放，Kafka replay scope隔离；验证exactly-once最终窗口、消费位置、实际checkpoint/savepoint恢复。Flink SQL connector 5.0.0-2.2与2.3.0的本轮有界测试通过，仍需后续兼容性审查后才可扩为长期流任务。

当前 Airflow联合Spark/Flink完整准入需9442MiB，最近正常构建前可用内存8627–8832MiB，联合编排未准入。保留分批已验收方式，不创建长期重任务定时器。

## 存储、日志及关闭后的证据

Kafka数据现位于已有VM磁盘hostPath `/opt/petclinic-observability/state/kafka-20261012T010132/data`，保留原Topic及168h策略。验收时应核对 broker Ready、`kafka-topics.sh --version` 为4.3.1、关键Topic末端位置，并实际消费最新发布事件；VM重启恢复后的最终基线是 `jenkins-logs:0=2189`、`petclinic-release-v09:0=2`，且后者包含 `0.10.0-ci-131`。Flink状态位于 `/opt/petclinic-observability/state/flink/petclinic-window-092657`；两次savepoint和Topic保留。本地单节点磁盘不是跨节点高可用。

业务 Filebeat→ES 提供版本/Pod/时间/trace检索；Alloy→Loki用于Grafana运维关联，因此业务日志有重复采集与存储成本。Kafka Filebeat只采集Flink文件路径，Jenkins另有日志采集器；本轮有界消费者证明实际流入及消费，未宣称存在长期Kafka→ES消费者。正常关闭Flink后，该路径无新消息是预期状态。

Filebeat数据流实际ILM为hot rollover 30d/50GB及delete min_age30d；旧filebeat-7.17.10索引未管理。Loki未配置自动retention，本轮未改变既有持久日志删除政策，后续清理需具体审查。分析告警只在期望副本大于0时评估计算不可用；快照7天时效仅info提示。告警规则已验证，通知送达未验证。

Harbor的135字节AOF修复、Kafka数据迁移、Runner helper和Hello路由修复脚本属于一次性迁移记录；已保留原件/UID/备份，不应在正常发布时重复运行。


## 2026-10-19 新增证书学习入口

独立入口为`https://tls-lab.devops.local`，使用内部学习CA；浏览器默认不信任，使用[学习手册](DEVOPS-LEARNING-20261019.md)中的显式CA校验命令。Argo应用为`platform-cert-manager`与`devops-tls-lab`。证书状态在devops-lab，控制器日志在cert-manager；可用服务器cmctl对tls-lab进行非删除式换发。#153完整成功后，10月18日验收通过；自动续期预定10月24日20:56:55上海时间，尚未观察到该时刻执行，公网ACME未验证。资源锁已释放、Jenkins恢复；现有业务入口和Spark Operator/Webhook保留。
