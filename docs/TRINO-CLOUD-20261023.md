# 云端 Trino 有界复验 · 2026-10-23

本轮未改网络、镜像、权限或生产查询模式。使用既有HeavyRun准入、共享platform-heavy Lease与Jenkins受控静默，短时启用原trino-worker Deployment，完成后恢复0副本。原始历史阻塞根因仍未确定，不能将当前成功写成已证明修复网络根因。

## 真实业务证据

- 节点查询20261022_193012_00012_tgpyr：本地协调器及ucloud-worker上的trino-worker-76655f7bd5-fzvjt均active、版本483。
- 统计查询20261022_193013_00013_tgpyr：对既有只读汇总daily_visits按最近成功run_id求和，加入非确定性过滤以避免直接聚合下推；结果923，与此前MySQL/Superset验收一致。
- 完成状态FINISHED，nodes=2、total/completedSplits=11/11、failedTasks=0、elapsed5322ms、spilledBytes=0、internalNetworkInputBytes=241。结合当时仅两个active Trino节点，证明云worker参与了本次查询。
- VM到云worker /v1/info实测ACTIVE；历史只做云Pod到协调器的单向探针，不能代替上述注册及查询证据。

## 失败取证及范围

最初尝试访问visit_facts被报表账号拒绝；这是既有最小权限设计，不扩权，后续改查正式看板使用的汇总表。另一次业务查询完成后，取详细query接口遭401，导致探针未保存结果；最终修正取证步骤后完整保存nodes/business响应。这些尝试分别保留在trino-cloud-query-20261023和trino-cloud-summary-20261023目录，不能冒称每次都完成了完整验收。

本轮没有强制worker独占，也没有长期稳定性或断网恢复测试。日常Airflow继续使用本地Trino模式，云worker按需关闭，不增加常驻资源。不能将该一次查询成功等同跨云高可用。

## 资源和恢复

worker沿用requests250m/2Gi、limits1CPU/2Gi，云ucloud-worker运行，原副本0。最终有效轮VM最低可用10179MiB，safetyFailure=null。结束确认worker0、无worker Pod、共享Lease不存在、PetClinic3/3及readiness UP；Jenkins状态另存jenkins-after.json。未修改数据库、PVC、Kafka Topic、主机密钥或防火墙。

最终证据：私有/Users/zhangsir/code/evidence/platform-20261011/trino-cloud-verified-20261023，含queries.json、pods.json、原资源/副本、事件、运行日志、资源采样及Jenkins恢复记录。Query ID中的时间为UTC，上海时间加8小时。

Alertmanager本轮状态API可读，当前11条活动告警：KubeJobFailed5、KubeControllerManagerDown1、KubeProxyDown1、KubeCPUOvercommit1、KubeSchedulerDown1、KubeMemoryOvercommit1、Watchdog1；内部接收器analytics-local3/platform-local8。保留真实失败与默认控制面目标告警，不将其写为已全部恢复；外部通知送达仍未验收。
