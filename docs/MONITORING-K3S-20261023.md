# K3s 控制面采集修正 · 2026-10-23

## 原因和修改

三条Critical告警KubeControllerManagerDown/KubeSchedulerDown/KubeProxyDown并非本轮证实的组件退出。现场10257/10259/10249均由k3s-server监听127.0.0.1，默认kube-prometheus-stack Service的EndpointSlice为空，因而没有发现采集目标。K3s把组件集成到同一进程；现场经认证API /metrics已包含scheduler_、kubeproxy_及controller/workqueue指标。

依据[K3s官方指标说明](https://docs.k3s.io/reference/metrics)，新增三个ServiceMonitor，通过现有default/kubernetes Service的TLS和Prometheus既有ServiceAccount读取/metrics，分别保留对应组件指标并设置job标签。未开放端口、未重启K3s、未禁用告警、未添加silence、未修改历史失败Job。此方式监控本地K3s server共享进程的组件指标，不代表对两个云agent的kube-proxy逐一探活；up表示共享入口可采集，不是独立组件健康检查。

配置位于infra/observability/alertmanager/k3s-component-monitors.json，纳入既有platform-alertmanager Argo Application，目标main。提交7d4ef23；服务端dry-run通过后正常推送私有GitLab。Argo自动同步、Prometheus config-reloader热加载，无业务或监控Pod重启。

## 实际验收

- 三个target scrapeUrl均为现有TLS API /metrics，health=up、lastError为空，up各1。
- scheduler_pending_pods、kubeproxy_sync_proxy_rules_last_timestamp_seconds及controller job的workqueue_depth均有真实样本；完整响应保留在metrics-verified.json。
- 三条原Critical告警已不在Prometheus活动告警及Alertmanager活动告警中，实际恢复而非静默。
- #166的49项Node通过，但Maven NoHttp检查发现上轮新增验收文档三处内部HTTP URL，构建在测试阶段失败、没有部署。修正为明确HTTP入口的主机名写法，未改检查规则，提交15f24f2，#167重新执行完整流水线；最终#167完整SUCCESS，发布0.10.0-ci-167。

## 保留的告警与限制

五条KubeJobFailed对应airflow-db-upgrade-v2、petclinic-analysis-baseline-20261011、petclinic-analysis-verified-20261011、harbor-aof-check-20261011、harbor-aof-rehearsal-20261011。它们是仍保留的历史失败Job；目前Airflow四轮及Harbor恢复的成功证据不能把这些旧Job改成成功。保留现场，不通过删除对象清零。

KubeCPUOvercommit/KubeMemoryOvercommit衡量最大节点故障后的请求资源容纳能力。本集群CPU为本地6、两云各2；内存主节点约28GiB、云节点约1.57/3.78GiB，无法把主节点全部负载迁往云节点。保留真实容量/容灾限制，不靠下调requests消警。Watchdog与InfoInhibitor是告警链路/抑制辅助信号，不等同业务故障。构建期间可能出现CPUThrottlingHigh pending，应按实际state区分，不能将所有返回条目都算firing。

外部通知送达仍未验证。当前无新的获授权外部接收渠道，不发送外部消息。

私有完整证据：/Users/zhangsir/code/evidence/platform-20261011/monitoring-release-20261023，包含逐次targets/指标查询、metrics-verified.json、alerts-after.json及ci-166/ci-167归档。资源门槛、共享Lease和原有业务健康保护继续生效。

## 最终发布记录

Jenkins #167完整SUCCESS；源码15f24f29ee4ffcdc4ab15708178bba5a5b739925，晋升a7fd905902ab4def7028b4a89030a012b08d3e11，OCI index sha256:1f976f86442ca8f6d7c2b99d36f0681321e7fa7b57a8bf9054491eacdffb6d7c。双架构扫描各Critical0/High0/Medium176/Low15，仍有191项漏洞，不是零漏洞。94项Java/49项Node、Sonar、GitLab源码审计、双架构、Registry、Harbor、Git晋升、Argo、滚动/业务健康、Kafka发布事件全部通过。

最终三副本更新且可用3/3，共享Lease释放，Jenkins非quiet且无构建。根盘可用约52GiB。发布和连续资源记录见ci-167，失败#166保留。既有Airflow周调度和本地Trino模式不变，Spark Operator/Webhook保留；本轮没有重新执行Airflow四轮，之前#165联合验收仍为独立证据。
