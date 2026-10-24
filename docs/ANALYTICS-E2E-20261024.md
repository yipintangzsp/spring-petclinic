# 2026-10-24 联合分析恢复记录（尚未完成）

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
