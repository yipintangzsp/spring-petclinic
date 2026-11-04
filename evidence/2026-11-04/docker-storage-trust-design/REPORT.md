# Docker storage and trusted-executor design — 2026-11-04

本轮仅取证/设计，无执行器、无容器创建、无daemon/Jenkins配置变更。结论 NO_SAFE_EXISTING_EXECUTOR，保持NOT_READY。

## Storage evidence

Docker29.6.2，overlayfs / io.containerd.snapshotter.v1，rootful，systemd/cgroupv2；/var/lib/docker与/var/lib/containerd映射guest /dev/vda2 ext4，rw,relatime。tune2fs只读元数据未列出quota/project，mount未启用配额。不能把Docker接受size参数当作执行证据。
Docker官方[run reference](https://docs.docker.com/reference/cli/docker/container/run/)将经典overlay2 size支持限定为XFS+pquota；此环境是containerd snapshotter，不能把经典driver说明直接当作当前driver支持或拒绝的证明。因此Docker层继续UNKNOWN，当前目录保护方案无强制配额则UNAVAILABLE。
官方[containerd store](https://docs.docker.com/engine/storage/containerd/)解释该存储后端；未切换driver，未调整filesystem。

| Option | Status | Evidence | Cost / permission / impact |
|---|---|---|---|
| Native writable-layer quota | UNKNOWN | Docker overlayfs/containerd != classic overlay2; size accepted historically but not enforcement proof; existing ext4 no quota/project feature | cannot implement without further supported mechanism; no config changes |
| Bounded tmpfs small scratch | SUPPORTED | historical4MiB native fixture; RAM available5348777984 bytes, swap in use2011754496 bytes | memory+swap+metadata accounting required; full DB UNSUPPORTED without peak proof |
| Controlled directory on existing guest disk | UNSUPPORTED | ext4 lacks quota/project flags and quota mount option; directory0700 is ownership, not capacity | enabling quota/remount/storage changes is outside scope and not proposed as an action |
| Monitoring-only fallback | UNSUPPORTED | no forced capacity bound; STORAGE_QUOTA_ENFORCEMENT=UNAVAILABLE for this directory-only fallback | not admissible as hard-quota replacement |

tmpfs不可默认承载完整DB；当前guest约21.45GiB RAM，available约4.98GiB，swap约1.87GiB正在使用。官方[tmpfs说明](https://docs.docker.com/engine/storage/tmpfs)指出其数据可能进入swap，因此也不能直接声称完全不消耗磁盘。未执行RAM压力或容量实验。

## Complete mapping / known gaps

各路径见 storage-map.json，包括层、tmpfs、volume、bind、Jenkins workspace、UTM guest、Mac COW；未配置的未来路径明确NOT_CONFIGURED/UNKNOWN，不伪造成已部署。
Mac只读stat发现devops命名qcow2候选：logical约340.69GiB、allocated约207.05GiB、host available约21.63GiB；这些不是COW峰值证明，VM归属尚未做设备链核验。guest可用空间不是host物理余量，不能相加。旧fixture的mountinfo/16KiB写入仅HISTORICAL_ARCHIVE复用，本轮没有运行容器。

## Jenkins trust boundary

实际#270 WorkspaceAction node空字符串，built-in节点唯一executor=1；路径/var/jenkins_home/workspace/petclinic-ci。Jenkins内UID1000，通过挂载socket连接与host相同daemonID4616ba22-4e70-4b96-8e66-6a3a4d756cb2。host socket uid0/gid988、mode0666，已有任意项目代码可绕过CLI wrapper直接使用raw API的权限风险。没有实际执行危险Docker API。
授权策略FullControlOnceLoggedInAuthorizationStrategy；admin真实ACL可Build/Configure，anonymousBuild=false。历史用户部分无法映射登录身份，明确UNKNOWN，未读取密码或创建身份。GitLab提交者/保护分支写ACL未取得，UNKNOWN；不能由gitlab-creds存在推断所有仓库权限。
本地冻结源码静态分析：agent any；withCredentials为sh/module提供Sonar/Harbor/Git/age文件凭据，masked日志不是对执行代码的隔离；未读取任何credential value。源码归属与SHA绑定在baseline，不把当前本地源码当成逐行在线构建重放。
权限边界FAILED，换Job名称、参数wrapper或同UID Agent不足以隔离；现有Jenkins任务与可信执行器不能共享可写工作树/凭据/进程身份和socket权限。

## Candidate comparison / unique recommendation

| Candidate | Feasibility | Blocker |
|---|---|---|
| A 独立可信Job/Agent | NOT_READY | 当前只有built-in executor；新增Job仍共享身份与socket；需真实身份/权限拆分及仓库审核边界 |
| B API代理 | DESIGN_ONLY | 只过滤HTTP方法不足；必须解析完整create spec、限制exec/image/volume/daemon API和对象归属；本轮不部署 |
| C 现有隔离Agent | NOT_FOUND | 本轮Jenkins节点列表只有built-in；不重新打开systemd/unshare/rootless路径 |
| D 保持阻塞 | SELECTED | NO_SAFE_EXISTING_EXECUTOR，不扩大生产权限 |

唯一推荐：保持阻塞（NONE）。未来唯一设计方向为受保护固定操作的可信执行入口，与普通仓库执行身份及raw socket可达性真正分离；现环境无法在本轮约束内完成。不是已批准的实施方案。
未来拟新增文件与字段见trusted-executor-contract.design.json，均未创建到实现目录；统一Security Manager→Trivy Plugin→Capability Check→Trusted Executor→Restricted Docker→Raw Report→Normalize→Policy，插件显式独立启停，production Gate不变。
新增身份、收回普通构建socket或部署代理/Agent都会触及平台权限和现有构建，必须另行批准具体变更；当前没有满足条件的低风险直接实施项。

## Daemon failure / cleanup contract

live-restore实际false，daemon.json未显式设置；不能据此认定异常崩溃时所有shim/container已停止。官方[live restore](https://docs.docker.com/engine/daemon/live-restore/)说明该选项与daemon生命周期有关，生产故障行为仍NOT_TESTED。
客户端API失败与daemon故障严格区分：create超时可能创建了容器；不能盲重试。执行前落盘受保护intent（daemonID/runNonce/owner/specHash）；响应后登记全ID/Created/image/mount/cgroup。label/name只能发现候选，不能单独授权删除。
断连进入UNCERTAIN_BLOCKED，禁止成功、禁止下一轮、禁止清理不明对象；有限退避重连，不假装client watchdog或TTL label可在daemon不可达时杀死容器。
恢复时验证同daemonID及完整归属链，再按已登记ID stop→必要时kill→核实cgroup为空/消失→rm→inspect not found。没有ID的create竞态、ledger缺失、身份改变、mount不符、归属不唯一、长期不可达必须人工介入；不采用host全局kill、prune或生产daemon重启。
真实daemon中断不实施；DOCKER_FAILURE_CLEANUP维持INCOMPLETE。未来需要单独授权的非生产故障环境，不用本轮静态契约冒充验收。

## Guard responsibilities / independent gates

Docker提供已验证配置的PID/mount边界；可信执行器必须强制固定配置与授权；Guard保留实际域/容量/新鲜度检查、固定hard floor和fail-closed；Policy只消费真实事实，无新PASS。
DOCKER_EXECUTOR_SECURITY_READY=NO；TRIVY_DISK_BUDGET_READY=NO；TRIVY_DB_FRESHNESS_READY=NO；总readiness=NOT_READY。现有DB stale为历史只读证据复用，本轮不打开/刷新DB；刷新/扫描峰值、瞬时写入、失败清理及MacCOW均未证明。

## Scope / validation / rollback

本轮REAL_READ_ONLY：Docker选定配置、findmnt/statvfs/inode、tune2fs metadata、socket mode、RAM/swap、PV路径、Jenkins ACL/#270执行绑定、Mac文件stat、生产健康。STATIC_ANALYSIS：源码凭据作用域、可信执行/清理契约、方案比较。HISTORICAL_ARCHIVE：9组Docker隔离、190/190/184差分与以往回归；未重跑、不计入本轮执行数。
checks.json只做设计字段与source/hash preservation检查，不叫原生隔离测试。保持2187个旧文件SHA不变，原历史完整性FAILED不修复。
首轮Linux脚本在解析前截断JSON导致失败，保留stderr并修正仅读取内存上限；Jenkins查询遇到无法映射身份，按用户返回UNKNOWN后成功。未绕过认证、没有权限扩展。
本轮只新增证据/设计文件；生产不需回滚。未来回滚先禁用validation入口、撤销仅新增能力、保留ledger直至归属清理完成；禁止用恢复普通构建raw socket作回滚捷径。未来任何权限变更都需独立评审，现阶段不实施。

## Production / next step

本轮Jenkins#270 SUCCESS，V1 Summary SHA ec9ee51a06d4b9f61c6c0eaf50b374d1e25e6d3ca687908b7596d3a2c794f5d8未变；ArgoSynced/Healthy、三节点Ready、PetClinic3/3、3Endpoints、HTTP200、生产digest489cb821573ff1f98edd846d5949d74bf3391b24e2f1fe5bcfb71c6be0793137不变。时间见JSON；一次采样不代表SLA。
唯一下一步允许操作：为“普通构建与可信执行身份真正分离 + 可强制限额存储”形成单独变更评审材料，补齐GitLab写ACL与底层配额机制证据；仅只读/设计，不实施或接线。STOP。

```text
DOCKER_STORAGE_DOMAIN_MAPPING = INCOMPLETE
DOCKER_STORAGE_QUOTA_ENFORCEMENT = UNKNOWN
DOCKER_JENKINS_PERMISSION_BOUNDARY = FAILED
TRUSTED_EXECUTOR_DESIGN = NOT_READY
SELECTED_EXECUTOR_ARCHITECTURE = NONE
DOCKER_FAILURE_CLEANUP = INCOMPLETE
DOCKER_EXECUTOR_SECURITY_READY = NO
TRIVY_DISK_BUDGET_READY = NO
TRIVY_DB_FRESHNESS_READY = NO
TRIVY_VALIDATION_EXECUTION_READINESS = NOT_READY
VALIDATION_EXECUTION_ADAPTER = NOT_IMPLEMENTED
TRIVY_RUNTIME_FACT_CAPTURE = INCOMPLETE
DEFECTDOJO_RUNTIME_FACT_CAPTURE = INCOMPLETE
FINAL_WIRED_CAPABILITY = 14/16
ORIGINAL_EVIDENCE_INTEGRITY = FAILED
REAL_RUNTIME_FACT_CAPTURE = INCOMPLETE
REAL_POLICY_OWNER = INCOMPLETE
IMMUTABLE_ARTIFACT_RUNTIME = INCOMPLETE
SUMMARY_V2_MIGRATION = INCOMPLETE
RELEASE_COUNT = 0
ROLLOUT_COUNT = 0
```
