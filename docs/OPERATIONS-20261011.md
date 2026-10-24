# Petclinic 发布与按需分析操作

> Terraform接入：#189完整发布成功，新增Terraform Plan门禁，归档target/platform/terraform.json。CI只预览隔离实验；实际创建/漂移修复/清理已由受控入口通过，触发、状态与故障处理见[Terraform记录](TERRAFORM-20261024.md)。

> 2026-10-24本轮完成：#188完整发布成功；1202条来源、年度925的Airflow正常/受控失败/自动重试成功/同批重跑四轮通过，Spark→Flink/Kafka→Trino/Superset真实对账。137旧卷已完整备份校验后按授权删除，指定旧镜像本地副本已核验清理。Spark Operator/Webhook保留，计算按需回收；外部通知送达与云Trino根因仍有限制。详见[本轮发布与验收](ANALYTICS-E2E-20261024.md)。

> 2026-10-24较早阶段：#183完整发布成功（0.10.0-ci-183）；RabbitMQ业务、去重、重试/死信、断连及Elasticsearch真实日志复验通过。获授权清理26个≤172旧本地镜像副本，Registry原件保留；CI自动回收仅限构建上下文/JAR缓存。Jenkins与资源锁恢复。新Airflow联合复验仍未完成，不能用旧结果替代。详见[最终交付](RABBITMQ-INTEGRATION-20261023.md)。
> 2026-10-23 RabbitMQ业务接入：#176完整发布通过；就诊回访、后台报表、发布审计均完成真实消费、去重、失败重试/死信、断连恢复与Jenkins恢复验收。新增Worker requests50m/128Mi、limits500m/256Mi；Kafka及既有分析链保留。当前状态和操作见 [业务验收](RABBITMQ-INTEGRATION-20261023.md)。下文较早“尚未接入”为历史阶段。

> 2026-10-23 RabbitMQ：data-infra 单副本持久化工作队列，独立 AMQP 确认/重投/死信、Pod 替换持久化、管理认证及 Prometheus 采集通过；尚未接入 PetClinic 业务。增加 requests100m/256Mi、limits500m/768Mi；入口、账号读取、证据、GitOps关闭方式与限制见 [RabbitMQ 验收及操作](RABBITMQ-20261023.md)。

> 2026-10-23 后续：#167完整发布成功，三个K3s组件采集target及实际指标通过，三条发现缺失Critical告警已在Prometheus/Alertmanager恢复；历史失败Job及容灾容量告警保留。详见[监控修正记录](MONITORING-K3S-20261023.md)。

> 云端Trino后续：原worker短时注册及两节点业务查询923已通过，随后恢复0；历史阻塞根因未定、日常仍本地模式。见[云端复验](TRINO-CLOUD-20261023.md)。

> 2026-10-23 核对：#165完整发布成功；Airflow四轮联合验收通过，周一02:30上海时间运行。证据、任务ID和操作见[最新验收](ANALYTICS-E2E-20261022.md)。后文较早状态按日期保留为历史。

> 2026-10-22：主盘旧快照经单独授权删除，活动数据全量摘要前后一致，镜像回收约80.3GiB；Harbor控制器原生ARM64恢复、Loki/Grafana缓存重建及健康检查通过。最新完整发布与联合分析状态以 [本轮恢复记录](RECOVERY-20261021.md) 为准；以下较早数字均为历史阶段，不能代替现场。Spark Operator/Webhook常驻保留。

本轮内部源码仅推送私有 GitLab `root/petclinic-platform`。公开 GitHub 原仓库和 Cook 的审查后公开导出流程保留；内部配置、网络、数据库备份、原始日志不得直接公开同步。详细组件、资源和发布结果分别见本目录 inventory、RESOURCE-POLICY 和 UPGRADE 文件。

## 业务与发布入口

- 业务统计：`http://petclinic.devops.local/insights`。输入日期为登记就诊日期，2026 年窗口925条（2026-10-24复验）；页面明确标记演示业务数据。本轮总记录1202并非本年数量，未来预约不能当作已完成诊疗。
- Jenkins：`http://jenkins.devops.local/job/petclinic-ci/`，Petclinic视图可查看阶段、控制台、测试和归档。失败构建保留；测试/质量门失败时不会开始部署。
- Harbor：`http://core.harbor.domain/harbor/projects`；真实扫描通过指扫描执行成功，漏洞数另查归档。
- Argo：`http://argocd.devops.local/` 中 Petclinic Application。
- Superset：`http://superset.devops.local/superset/dashboard/petclinic-analytics-20261011/`，使用现有账号登录。
- Grafana：`http://grafana.devops.local/d/petclinic-release-analysis/`；既有应用看板 `petclinic-app-metrics`、平台看板 `petclinic-v09` 保留。
- Kibana 保存搜索：`petclinic-upgrade-20261011-logs`，按 `service.version`、`kubernetes.pod.name`、时间和 `trace.id` 查询。
- Jaeger：`http://jaeger.devops.local/`，service=petclinic。

这些主机名使用现有本地 DNS/hosts。端点未经本轮公开发布。原始验收证据在 Mac 私有目录 `/Users/zhangsir/code/evidence/platform-20261011`；主机一致性备份位于 `/opt/petclinic-observability/backups/platform-20261011`。

## 正常发布、回滚与恢复

审查代码后在私有 GitLab main 普通推送，由实际 Push Webhook 触发 Jenkins。Runner 只执行有界源码审计，不重复部署；Jenkins 顺序执行资源准入、104项 Java/58项 Node/41项 Python 测试、Sonar、双架构镜像、Harbor扫描、私有GitOps晋升、Argo/Endpoint/业务健康验收及Kafka发布事件。独立分析计算不在业务发布的同步等待链。

每次晋升提交同时使用 `[skip ci] [ci-skip]`，分别兼容 GitLab 和现有 Jenkins GitLab 插件；缺少第二个标记曾产生重复构建。本轮已实际阻止后续晋升再次构建。

从归档的 `promotion.json` 找出精确晋升提交，在私有源正常 `git revert <晋升提交>` 并推送。等待 Argo sync revision 与回滚提交一致、镜像digest正确、三副本及业务健康后，再 revert 该回滚提交并推送以恢复目标版本。GitOps-only 提交携带两种skip标记。不要使用强推或直接 `kubectl rollout undo` 绕过源记录。

本轮已实际执行的回滚/恢复修订分别是 `9a2f7dee2ce091c6961fd51f4c673786e5a4a6ec`、`cc19a4b628e20dc9dfca64333821586d0082d46b`。新增分析schema与旧应用兼容；应用回滚保留schema、事实、状态、备份和原业务数据。数据库恢复是单独批准的灾难恢复操作，不能作为发布回滚默认步骤。

## 分批分析

从隔离工作树运行 Python 控制器，始终使用一份新的私有 evidence 子目录。独立Spark/Flink控制器读取实时容量/健康并管理共享 `data-infra/platform-heavy` Lease及自己设置的Jenkins quiet状态。联合Airflow验收则由每轮DAG独占申请同一把Lease、确认Jenkins空闲并受控暂停新重任务；宿主run_airflow控制器不重复申请这把锁，避免等待自己。宿主控制器启动Airflow前的临时静默会在触发DAG前恢复。正常结束先确认本轮计算退出、Sonar原UID/副本恢复Ready，再恢复Jenkins原状态并释放Lease；恢复失败保留保护并保存证据。资源不足会拒绝准入，不要绕过Lease或将过期Lease直接删除。

历史#147验收曾固定源码04f86c9643d1a9aff1b236ef40bb590d002b628e，其中Sonar恢复等待仅约200秒；该修订只供追溯，不应在本轮修复发布后重新用作触发目标。下方变量必须设置为本轮完整私有流水线成功发布且已审查的源码SHA；本轮已发布源码为ecbae16a42c26118630784d14a7031a460bb21cd（#165 SUCCESS）。

```bash
: "${PETCLINIC_ANALYTICS_RELEASED_REVISION:?请先设置本轮完整流水线已发布源码SHA}"
python3 infra/analytics/run_airflow.py \
  --revision "$PETCLINIC_ANALYTICS_RELEASED_REVISION" \
  --evidence /Users/zhangsir/code/evidence/platform-20261011/airflow-new-run

# 上一个控制器完全退出后，才执行下一个。
python3 infra/analytics/run_spark.py \
  --from 2026-01-01 --to 2026-12-31 --repeats 2 \
  --evidence /Users/zhangsir/code/evidence/platform-20261011/spark-new-run

python3 infra/analytics/run_flink.py \
  --evidence /Users/zhangsir/code/evidence/platform-20261011/flink-new-run
```

Airflow固定已发布且审查过的修订；DAG默认schedule=None，run_airflow控制器验证正常、最终失败、失败后重试和同批次重跑四轮，全部通过后才允许--keep-running开启低频定时。结果在隔离schema事务发布，访问超时3–5秒、有界5000行/366天；原事实按visit_id去重。当前源为append-only VisitController契约，不能将此增量方式冒称处理任意删除/更新的CDC。

历史独立Spark快照为1200行、年度923，记录含真实Job IDs和driver/executor内核峰值；新批次必须重新生成快照与MySQL基准，不可把这两个历史数字写入判断条件。Flink读取明确标记demo的快照重放，Kafka replay scope隔离；验证本轮提交消息对应的已提交窗口、消费位置和实际checkpoint；旧独立验收还验证了savepoint恢复。每次尝试都会向既有Topic重新发送本批消息，不能宣称原始Topic跨尝试exactly-once；分析结果通过批次/主键与事务发布保证重复执行安全。Flink SQL connector 5.0.0-2.2与2.3.0的本轮有界测试通过，仍需后续兼容性审查后才可扩为长期流任务。

2026-10-16 当前采用启动前10240MiB内存准入、CPU计算2000m+250m储备；必要时仅在持有同一Lease且Jenkins空闲静默时暂停Sonar500m。结束或失败先回收本轮计算，恢复Sonar原UID/副本并等Ready，再恢复Jenkins。历史Spark结果读取失败尝试的清理和恢复已通过。后续reclaim目录第一轮完整正常DAG成功，第二轮完成预期最终失败验收；第三轮业务查询通过但cleanup因Sonar原200秒等待超时失败，宿主控制器finally已恢复Sonar/Jenkins并回收本轮资源。第四轮未执行，四轮联合验收未完成，定时尚未开启；不能将异常恢复成功代替该轮DAG成功。旧内存8627–8832MiB仅为10月12日历史测量，不能作当前拒绝依据。

## 存储、日志及关闭后的证据

Kafka数据现位于已有VM磁盘hostPath `/opt/petclinic-observability/state/kafka-20261012T010132/data`，保留原Topic及168h策略。验收时应核对 broker Ready、`kafka-topics.sh --version` 为4.3.1、关键Topic末端位置，并实际消费最新发布事件；VM重启恢复后的最终基线是 `jenkins-logs:0=2189`、`petclinic-release-v09:0=2`，且后者包含 `0.10.0-ci-131`。Flink状态位于 `/opt/petclinic-observability/state/flink/petclinic-window-092657`；两次savepoint和Topic保留。本地单节点磁盘不是跨节点高可用。

业务 Filebeat→ES 提供版本/Pod/时间/trace检索；Alloy→Loki用于Grafana运维关联，因此业务日志有重复采集与存储成本。Kafka Filebeat只采集Flink文件路径，Jenkins另有日志采集器；本轮有界消费者证明实际流入及消费，未宣称存在长期Kafka→ES消费者。正常关闭Flink后，该路径无新消息是预期状态。

Filebeat9.4.4已按单独授权删除两份旧日志索引并采用专用策略：每日或主分片1GB滚动、滚动后7天删除（文档时间约7–8天）；其他旧版本沿用原配置。历史策略为30d/50GB滚动及30d删除；旧filebeat-7.17.10索引未管理。Loki未配置自动retention，本轮未改变既有持久日志删除政策，后续清理需具体审查。分析告警只在期望副本大于0时评估计算不可用；快照7天时效仅info提示。2026-10-16复验三条真实Prometheus规则firing/health=ok，Alertmanager分别接收并按namespace路由至platform-local/petclinic-local/analytics-local，显式恢复后均inactive且Alertmanager不再有测试活动告警；临时规则按UID删除。证据alertmanager-20261016。外部通知送达未验证，未配置新外部接收器；既有K3s控制面目标Down噪声仍须单独治理，不能将测试通过写成所有告警清零。

Harbor的135字节AOF修复、Kafka数据迁移、Runner helper和Hello路由修复脚本属于一次性迁移记录；已保留原件/UID/备份，不应在正常发布时重复运行。

## Alertmanager 查看与告警验收

Alertmanager沿用现有0.31.1原生ARM部署与1GiB PVC，常驻1个Pod、两个容器；不要再重复安装另一套。若本地未解析其主机名，可建立端口转发后在浏览器打开本机9093：

```bash
ssh -t -L9093:127.0.0.1:9093 192.168.1.58 'sudo kubectl -n monitoring port-forward svc/alertmanager-platform 9093:9093'
```

本轮内部测试ID为20261016T060733，保留了Prometheus规则健康/触发、Alertmanager指纹/路由/分组、规则恢复及UID清理记录。没有已获授权的外部通知渠道，本轮没有测试外发，故外部送达仍未完成。


## 2026-10-19 新增证书学习入口

独立入口为`https://tls-lab.devops.local`，使用内部学习CA；浏览器默认不信任，使用[学习手册](DEVOPS-LEARNING-20261019.md)中的显式CA校验命令。Argo应用为`platform-cert-manager`与`devops-tls-lab`。证书状态在devops-lab，控制器日志在cert-manager；可用服务器cmctl对tls-lab进行非删除式换发。#153完整成功后，10月18日验收通过；自动续期预定10月24日20:56:55上海时间，尚未观察到该时刻执行，公网ACME未验证。资源锁已释放、Jenkins恢复；现有业务入口和Spark Operator/Webhook保留。


## 2026-10-19 Terraform/Ansible学习实验

Jenkins #154完整成功后，已通过配置预览、两工具幂等、非法参数拒绝、ConfigMap漂移检测/原地修复及3个隔离对象回收。入口和重跑命令见[IaC实操](IAC-LAB-20261019.md)。状态及日志保留，无新增常驻Pod/PVC；证书实验保持独立。


## 2026-10-20 发布实验完成

Jenkins #159及独立灰度/蓝绿完整验收已于2026-10-20 15:19通过。两个实验Rollout回到0、副本清理确认、自动同步恢复、共享Lease释放、Jenkins非quiet；Spark Operator/Webhook保留。重跑、AnalysisRun ID、失败证据和资源记录见[本轮发布实验](ROLLOUTS-LAB-20261020.md)。此处不改变既有Airflow四轮联合验收未完成结论。

## 2026-10-22 新准入与扫描数据库维护

发布前要求Mac新鲜采样可用空间>=16GiB，nodefs/imagefs保留15%容量加8GiB，Harbor注册表和控制器均须有ready端点。两类Trivy库的版本/NextUpdate/DownloadedAt必须有效，否则先维护库再构建。维护采用infra/harbor/warm_trivy_db.py，--database db或java-db，输入官方OCI清单与按其层摘要校验的归档，脚本沿用重任务Lease和Jenkins恢复保护，经本地OCI调用正常Trivy下载。不可跳过扫描、伪造元数据或使用未经官方摘要核对的镜像站标签。
