# RabbitMQ 真实业务接入与验收 · 2026-10-23

## 已完成的流程

私有 GitLab 源码 `a27bb5f` 经 Jenkins #176 的测试、Sonar 质量门、双架构构建、Harbor 扫描、GitOps、Argo 同步、业务健康及 RabbitMQ/Kafka 发布事件阶段完成发布。新应用 `0.10.0-ci-176`；Worker 的 Argo Application `platform-messaging` 固定受检源码，不跟随未验证的 main。此前 #173/#174 在质量门被拦截；#175发布后端到端验收发现ORM先插入、后关联宠物导致漏发，#176修复并加入事务回滚回归验证。6条新增规范问题已修正，未放宽门槛。

|真实场景|输入、处理与结果|
|---|---|
|就诊异步业务|新增就诊（含ORM后续宠物关联更新）与 PostgreSQL outbox 同事务提交；RabbitMQ 消费生成内部人工回访待办；页面标记完成。不会发送短信/邮件，也不会把历史1200条重新回放|
|后台任务|页面提交最多366个自然日的报表，Worker 查询真实 PostgreSQL 并保存结果；请求键保证重复提交不重复执行|
|发布事件|Jenkins 在实际健康发布后生成稳定事件ID，经 RabbitMQ 消费写入 release_audit；保留 Kafka 原发布阶段|
|可观测性|原生 RabbitMQ Prometheus 采集、应用任务状态/待发outbox指标、Worker event_id结构化日志、页面状态和更新时间|

Kafka、Airflow、Spark、Flink、Trino、Superset沿用原职责；GitLab/Sonar/Harbor/Argo服务通过真实发布流程产生事件，不将所有系统日志或数据库复制流硬改为RabbitMQ。详细接入矩阵与故障语义见 [实现说明](../infra/messaging/README.md)。

## 如何使用

- 业务入口：`http://petclinic.devops.local/jobs?lang=zh`，导航“异步任务”。选择日期提交后台报表；刷新后查看 queued/running/retrying/success/failed、尝试次数、UTC更新时间和持久结果。
- 在原宠物页面登记一条未来就诊记录，提交成功后生成“人工回访”；检查后点击完成。只是内部待办，未来预约不代表已经完成诊疗。
- Jenkins普通发布会自动产生RabbitMQ发布审计；不需手动重跑流水线来造事件。
- 管理入口：`http://rabbitmq.devops.local`，使用现有管理员账号；vhost `petclinic`。应用使用独立 `petclinic-app` 用户，不使用管理员账号；随机密码在 `petclinic/rabbitmq-client` Secret，未入Git。

可重复的API示例；同一key与同一日期只生成一个任务，不同日期复用key返回409：

```sh
curl --noproxy '*' --resolve petclinic.devops.local:80:192.168.1.58 \
  -X POST 'http://petclinic.devops.local/api/messaging/reports' \
  --data-urlencode 'key=my-2026-report-001' \
  --data-urlencode 'from=2026-01-01' --data-urlencode 'to=2026-12-31'
# 用响应中的 id 查询，直至 success；每次运行新报表请换key。
curl --noproxy '*' --resolve petclinic.devops.local:80:192.168.1.58 \
  'http://petclinic.devops.local/api/messaging/jobs/<id>'
```

## 本轮真实验收

批次 `mq-20261023T234811`；原始证据保存在 Mac 私有目录 `/Users/zhangsir/code/evidence/platform-20261011/messaging-20261023/e2e-final`。以下计数是本轮现场查询，不是历史常量。

|验收|结果与证据|
|---|---|
|正常报表|`report-fcd246ea-6268-3115-b573-e279da575295`，success，attempts=1；结果 `{"from": "2026-01-01", "to": "2026-12-31", "owners": 200, "pets": 350, "vets": 20, "visits": 924}`，与SQL基准一致|
|同批次重复|相同key返回同一ID；另发2条重复AMQP消息；jobs=1、report_results=1、attempts=1，冲突参数409|
|受控失败后自动重试|`check-e02161db-029a-4f74-869a-4e9ffb6e40c5`，记录retrying后第2次success；重试等待由数据库调度，不占睡眠任务Pod|
|三次失败和死信|`check-56c28254-761c-440e-a062-456e6e41d4ce`，3次失败、failed；死信队列实际检查到原event_id和持久消息；检查后全部NACK/requeue保留证据|
|人工重试|只移除本轮测试任务的注入故障后，页面POST retry；总attempts=4、success；成功任务再次retry为409|
|失败隔离|失败批次无report_results，原正常任务结果仍存在，不覆盖最近成功结果|
|断连恢复|只暂时阻断本Worker的AMQP出口并重建Worker，任务queued、confirmedVersion=0；恢复原策略/GitOps后 `report-189482b2-8e5b-354a-a745-42a5b3fd2112` 第1次成功|
|实际就诊|保留一条明确标记的学习记录 id=11，pet=1；新outbox消费成功，回访从todo到done，重复完成无重复待办|
|现场计数|原始记录1201→1202；2026年924→925；event_id重复数0。新增记录为未来预约，不能当作已完成诊疗|
|清理和恢复|仅本轮Worker策略/同步状态临时改变，已恢复；Jenkins原quiet状态恢复，platform-heavy Lease释放，无临时计算Job残留；Broker/PVC/Operator保留|

`states.json` 保存状态轮询；`failed-page.html`/`success-page.html`保存页面；`outage-evidence.json`保存断连与待发证据；`worker-logs.json`保存消费日志；`acceptance.json`含SQL、死信与发布审计。数据库迁移前的完整备份、摘要和回滚验证见同级 `backup-before.json`、`schema-rollback-check.log`；未删除既有业务行；首轮漏发的本轮测试记录8只按ID及精确验收标记重写相同pet_id，恢复唯一outbox并完成人工回访，未批量回放历史记录。

## 指标与集中日志

Prometheus查询 `max by(status) (petclinic_messaging_jobs)`、`max(petclinic_messaging_outbox_pending)` 与 `min(petclinic_messaging_storage_available)`。三个Web副本读取同一份数据库状态，不能直接sum这组状态Gauge，否则会把同一任务重复计算三次。RabbitMQ原生投递/确认指标与这些持久业务状态分开看。

Grafana Explore选现有Loki数据源，查询 `{namespace="petclinic",app="clinic-message-worker"} | json`，再按event_id筛选。Worker日志由新增独立Alloy链采集，原PetClinic/Cook采集保留；Filebeat保持原日志链和原解析方式。原始采集响应、队列消费者/积压、内核memory.peak及资源记录在同级 `observability/`。

## 排查、重跑与回滚

```sh
ssh zhang@192.168.1.58 'sudo kubectl -n petclinic logs deploy/clinic-message-worker --tail=200'
ssh zhang@192.168.1.58 'sudo kubectl -n petclinic get pod -l app=clinic-message-worker; sudo kubectl -n argocd get app platform-messaging'
ssh zhang@192.168.1.58 'sudo kubectl -n data-infra exec rabbitmq-0 -- rabbitmqctl list_queues -p petclinic name messages_ready messages_unacknowledged consumers'
```

先用event_id对应页面/日志，再检查数据库与RabbitMQ连接。queued且confirmed_version落后表示待发；retrying表示业务失败已排下一版本；failed须确认死信投递完成，修复原因后用页面“重试”。不要清空队列、删除PVC或复制未知消息来恢复。正常重复提交原key不会重算；需要新时间批次使用新key。历史成功结果按独立event_id保留。

Worker单副本，代码和镜像固定摘要；回滚应将platform-messaging固定到已验证的兼容源码，通过原检查流程发布。新增schema、outbox、死信和结果保留；应用回滚不默认恢复数据库。暂停Worker应通过该Application的GitOps期望副本数，不应只手工scale后被selfHeal恢复。

## 资源和边界

Worker requests50m/128Mi，limits500m/256Mi，一个实际串行回调；prefetch=1按每个consumer生效，3个队列最多3条未确认，但一次只执行1个处理器。复用原固定摘要Python运行时，不另启Airflow实例。网络仅DNS、PostgreSQL、RabbitMQ；不挂载Kubernetes API token。管理账号不变。

Broker仍单副本，不宣称高可用；本轮断连恢复验证不等同于主机掉电或独立备份恢复。每队列10000条/64MiB拒绝发布上限沿用；死信不自动清空，需监控积压。新状态指标是持久状态快照，不是每次状态迁移都必然被Prometheus短周期采样捕获。日志/链路可观测性各以最终取证记录为准，不把Pod Ready当作业务验收。历史云Trino根因及AMD64冷构建限制仍单列，未因本次接入宣称解决。


## 2026-10-24 换网后的恢复与安全停止

Mac 的局域网地址已变为 10.90.114.22，原桥接地址192.168.1.58不能从Mac直连；VM专用网卡192.168.64.11已通过原SSH主机密钥核验。未修改系统代理、默认路由或全局hosts。当前网络可使用临时本地转发：

```sh
ssh -o HostName=192.168.64.11 -o HostKeyAlias=192.168.1.58 \
  -o ExitOnForwardFailure=yes -N \
  -L 127.0.0.1:18080:10.43.39.130:80 \
  -L 127.0.0.1:15672:10.43.176.108:15672 192.168.1.58
# 保持该SSH运行；关闭后上述临时入口失效。ClusterIP变化时先重新查询Service。
# http://127.0.0.1:18080/jobs?lang=zh
# http://127.0.0.1:15672
```

资源采样LaunchAgent继续运行，通过`PETCLINIC_SSH_ADDRESS=192.168.64.11`连接；原SSH身份及主机密钥校验保留。原先采样过期使#179/#180在部署前被准入检查拦截，未降低90秒时效要求。CoreDNS另修复了无效cluster.local与Tailnet搜索后缀拼接请求，在本地返回NXDOMAIN，合法内部、Tailnet和外部域名仍由原处理器处理；规则、恢复步骤和官方依据见[DNS配置](../infra/observability/coredns/README.md)。修复后已验证绝对域名、错误扩展名及libc实际解析。

仅清理APT/Helm/pip及Docker buildx的source.local可再生缓存，实际净回收约675MiB；保留全部常规构建层、镜像、卷、业务数据及备份。当前磁盘门槛仍为节点容量15%+8GiB，本机约45667.83MiB；下次扫描数据库刷新还须额外预留4GiB。

**联合编排复验未完成**：新DAG `manual__rabbitmq_preserved_20261023T155303` 的Spark真实完成，Application `petclinic-airflow-1de3bbf335fd`、AppID `spark-e69e17ac87fe4056911fa18d91df3920`、Job IDs 0–15，输入1202、唯一1202、年度925，与本轮SQL快照一致；耗时39.215秒，Driver峰值561541120字节。之后Flink阶段根盘可用空间从46665.93MiB降至45483.80MiB，低于停止线约184.03MiB，被安全停止；这只是已观察到的约1182.13MiB写入，不能视为完整Flink磁盘预算。新批次未发布Trino/Superset结果。

本轮Spark临时UI随Driver清理关闭；运行记录在私有证据`airflow-preserved`。本轮Flink计算资源归零、Spark临时资源已移除，Sonar与Jenkins恢复，Lease释放。失败批次状态已按本轮dag_run_id标记resource-safety-stop；最近成功分析结果仍保留，`/insights`和Superset的历史923不等同于`/jobs`实时PG报表925。历史完整联合验收并未被重新标为失败，但不能代替本次复验。

再次联合运行应至少在停止线上额外预留2GiB写入空间（仍需连续监测完整Flink峰值）；若当前约46521MiB可用，则至少缺约1195MiB，发布后须重测。可行减负方向是迁移已核验的旧备份到外盘、证明旧临时卷无业务引用后另行授权清理，或扩容根盘；不要盲删匿名卷、日志、PVC或调低保护线。


## 2026-10-24 最新现场结论（应用晋升尚未完成）

最新Jenkins #181源码`bfd2d8c8f04646d4e15528c570ed247a4e17ba9f`：104项Java、56项Node、5项Python通过；Sonar质量门OK（新增覆盖92%、新增重复0%、新增问题0）；双架构构建、Harbor扫描、Worker部署成功。两架构均0 Critical/0 High、53 Medium/4 Low、fixable=0；仅适用于PetClinic应用镜像，不代表平台所有镜像无漏洞。固定SHA的Pika缓存命中，未依赖外部重复下载。

**#181整轮FAILURE**，原因是Git Promotion前磁盘不足：47610605568字节可用，门槛47886194893字节，差约263MiB；因此没有晋升应用、没有本轮RabbitMQ/Kafka发布事件。应用仍为最后成功版本`0.10.0-ci-176`，Worker代码已由#181前置部署至固定源码bfd2d8c，完成本节业务复验后bootstrap配置与现场固定源码保持一致。不能将Worker部署成功写成#181完整发布成功。

定向清理JAR构建缓存和source.local又回收640.57MiB（APT安装缓存保留）。后续自动清理这些构建缓存的Jenkinsfile变更及只包含实际Docker COPY输入的.dockerignore已准备，尚待完整CI验证。未自动删除旧镜像：删除旧本地副本的动作被自动审批因先前“保留镜像”的范围限制拒绝，单独授权仍待处理；拟执行范围仅构建号≤172、无容器引用且原Registry摘要逐一校验一致的本地副本，保留175之后、基础镜像、Registry/Harbor原件及所有业务卷。

当前真实Worker复验批次`mq-20261024T020439`（Web176+Worker181），正常报表`report-91e13709-de5d-30cd-b2c8-5d11c196070e`结果925，与SQL一致；2条重复AMQP消息之后jobs=1、results=1、attempts=1；自动重试第2次成功；`check-39d3e48c-c610-4696-a08c-30c1531d744c`第3次失败、实际死信持久化，修复本轮注入原因后人工第4次成功；阻断后恢复任务`report-d08ada13-e7ff-328c-9478-042b22b91dbe`第1次成功。复用已验收visit11检查回访完成幂等，未新增业务行，原始1202/年度925/event_id重复0。Jenkins原状态恢复、Lease释放、临时计算资源0，原网络策略和GitOps自动同步已恢复。证据位于`e2e-ecs/acceptance.json`。

Elasticsearch已实际检索到该正常报表的publisher_confirmed、running、success及duplicate_or_obsolete_acked日志，共5份文档，service.name=clinic-message-worker，证据`observability/elasticsearch-ecs-acceptance.json`。之前错误service字符串被拒的历史日志没有宣称已补写。Loki实际Worker流、RabbitMQ确认/ACK计数和3个Web副本业务Gauge均已查到。Worker内核峰值25153536字节、上限268435456字节；采样VM可用内存9600.5MiB、根盘可用45918.2MiB、CPU requests 4495m/6000m，Mac内存可用比例40%。这些为现场采样，非保证常数。
