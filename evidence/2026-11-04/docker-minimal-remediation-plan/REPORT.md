# Docker socket minimal remediation — 2026-11-04

本轮方案已形成，未执行。选择D：Trivy真实执行继续暂停；socket0666持久化来源已找到，单独提交维护变更。socket方案READY表示可审阅，不是获准执行或完整权限边界通过。身份拆分NOT_READY。

直接来源：/etc/systemd/system/docker.service.d/override.conf 中 ExecStartPost=/bin/chmod 666 /var/run/docker.sock，systemd显示该post命令执行成功；vendor docker.socket原为0660。来源文件SHA256 ab806ac13ce92bcc87c29d57befe985ff826c35db7fffa96b71277c3c740c8b3。

受影响对象：Jenkins UID1000/GID1000/no988，Portainer默认root，docker组成员zhang/gitlab-runner。当前未观测TCP Docker listener；未知代理/短时连接不由快照排除。直接chmod会让Jenkins失去新连接能力，因此需维护窗口先保留现有Jenkins兼容访问，再精确持久化与收紧inode；残余root等效权限明确保留为过渡风险，不叫身份隔离。

详细执行顺序、备份、准确文件diff、检查条件、只重载不重启daemon/socket、失败分阶段回滚、维护批准范围及四架构比较见 [CHANGE-PLAN.md](CHANGE-PLAN.md)。所有命令为提案，本轮未执行。

ext4 quota在线改造涉及共享根文件系统且缺可靠恢复前提，NOT_FEASIBLE_NOW；不提供生产根盘改造动作。小tmpfs不能默认为完整DB执行存储。没有已验证的现成远程扫描/DB替代服务，不重复七候选审计。

本轮REAL_READ_ONLY：systemd socket/service属性与drop-in来源、已知配置位置扫描、所有Kubernetes/Docker socket挂载消费者、ss/lsof快照、相关用户组、Jenkins实时组、生产健康。rg返回2是/etc/rc.local不存在，其他位置取得唯一chmod666命中；不声称扫描所有未知目录。lsof无连接不代表无人依赖。
OFFLINE：权限mode模型/精确文本替换与回滚/源hash核对，见offline-plan-checks.json。额外ACL未采集，计划必须实施前核对。没有新增容器、服务或Agent，没有重新执行原生Docker/190差分；历史VERIFIED只是封存复用。

本轮生产只读取样：Jenkins#270 SUCCESS、V1 Summary hash ec9ee51a06d4b9f61c6c0eaf50b374d1e25e6d3ca687908b7596d3a2c794f5d8未变；ArgoSynced/Healthy、三节点Ready、PetClinic3/3、HTTP200、3Endpoints、生产digest489cb821573ff1f98edd846d5949d74bf3391b24e2f1fe5bcfb71c6be0793137不变。无发布/rollout/push。

尚未解决：普通项目raw socket权限、独立可信执行身份/授权治理、强制存储预算与配额、DB freshness、daemon失联清理及MacCOW上界。临时收敛world-write不消除这些阻塞。

唯一下一步：审阅并明确批准或拒绝单独socket维护变更（含Jenkins短时重启、补充组兼容及限时应急回滚风险）；未批准前不执行任何生产动作。STOP。

```text
DOCKER_SOCKET_RISK = CONFIRMED
DOCKER_SOCKET_REMEDIATION_PLAN = READY
JENKINS_IDENTITY_SEPARATION_PLAN = NOT_READY
STORAGE_QUOTA_CHANGE_FEASIBILITY = NOT_FEASIBLE_NOW
PREFERRED_EXECUTION_ARCHITECTURE = D
PRODUCTION_CHANGE_REQUIRED = YES
MAINTENANCE_WINDOW_REQUIRED = YES
TRIVY_VALIDATION_EXECUTION_READINESS = NOT_READY
TRIVY_RUNTIME_FACT_CAPTURE = INCOMPLETE
DEFECTDOJO_RUNTIME_FACT_CAPTURE = INCOMPLETE
FINAL_WIRED_CAPABILITY = 14/16
ORIGINAL_EVIDENCE_INTEGRITY = FAILED
SUMMARY_V2_MIGRATION = INCOMPLETE
RELEASE_COUNT = 0
ROLLOUT_COUNT = 0
```
