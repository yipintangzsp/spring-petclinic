# Linux isolation feasibility — 2026-11-04

现有原生能力 AVAILABLE，但没有后端通过本轮完整准入；SELECTED_ISOLATION_BACKEND=NONE。候选 Docker，Guard 执行适配器 NOT_IMPLEMENTED。仅新增独立测试脚本与证据，未修改 Guard/Gate/生产文件。

| Capability | Status | Evidence / limit |
|---|---|---|
| kernel | AVAILABLE | 7.0.0-38-generic ARM64 |
| cgroup v2 | AVAILABLE | controllers and actual Docker cgroup observed |
| direct cgroup delegation | UNAVAILABLE | UID1000 session directory and cgroup.kill not writable |
| systemd user manager | AVAILABLE | transient unit true exited0; collected |
| systemd filesystem sandbox | UNAVAILABLE | same host mount namespace; outside disposable sentinel write ALLOWED despite ProtectSystem/PrivateTmp |
| direct user/mount/PID unshare | UNAVAILABLE | uid_map EPERM; no sysctl changes |
| systemd PrivateUsers | AVAILABLE | distinct user namespace observed, insufficient filesystem boundary |
| rootless container | UNAVAILABLE | no podman/nerdctl; Docker info not rootless |
| Docker controlled execution | AVAILABLE | cached immutable image, nonprivileged no host mounts, UID65534 |
| containerd direct socket | UNAVAILABLE | UID1000 cannot read/write k3s socket |
| seccomp support | AVAILABLE | Docker builtin configured; actual filtering details UNKNOWN |
| Jenkins executor | UNKNOWN | Jenkins deployment UID1000 CapEff0, cgroup readonly, Docker socket writable; exact #270 executor binding not re-queried |
| existing approved Linux sandbox | UNKNOWN | no separately authenticated sandbox identified |

## Native controlled execution

- `native-verification.json`：unshare 实际 EPERM；systemd true 成功，不能据此宣称隔离。
- `sandbox-check.json`：systemd unit 的 PrivateUsers 创建了 user namespace，但 mount namespace 与宿主相同；写入自建边界外 sentinel 成功。这是候选失败证据，文件和 unit 已清理，未接触生产路径。
- `container-confirm-final.json`：现有 python 镜像固定 SHA256，pull=never；网络 none、无端口、无 hostPID/hostPath/绑定卷、只读根、cap-drop ALL、no-new-privileges、UID65534、pids12、内存48MiB、临时 tmpfs4MiB、log-driver none。根及 symlink 越界写入得到 EROFS。
- 宿主 cgroup.procs 观察到父/子两进程；setsid 子进程测试和忽略 SIGTERM 的主进程受 docker stop --time=1 控制，退出137，之后 cgroup不存在。没有仅根据父PID宣称完整清理；仅此单次受控域通过。容器最终 inspect not found。
- Docker 首轮因未等待子进程就绪，只保留启动/停止证据；补证脚本一次遗漏 pathlib import，finally 执行定向容器删除，错误 stderr 原样保留；修正后取得完整事实。没有 mock 替代原生测试。

## 未通过与设计阻塞

- 多级后代、孤儿父退出、主动移出 cgroup、非授权执行拒绝、存储域变化、清理失败和不误杀外部哨兵的完整原生矩阵：SKIPPED / INCOMPLETE。当前没有经过认证的执行适配器来强制执行这些拒绝与清理策略，不能据一次 docker stop 外推全部通过。
- Docker 有 /dev、/dev/shm、/proc 特殊可写挂载；当前 Guard 的六目录维护未映射容器挂载/运行时元数据/日志传输到已核实存储预算，无法注册全部写入域。当前路径 API 不能冒充容器 filesystem execution isolation 已收口。
- 不将 Docker socket 权限继续交给扫描容器。当前 Jenkins 已可访问 rootful socket 是已有风险事实，本轮未扩大/修改该权限；rootless 未证明。
- 最小设计：独立 opt-in broker/CLI 构造固定受限 spec、拒绝任意 volume/privileged/host namespace/socket、固定镜像与真实挂载清单、认证运行归属、独占容器ID、停止后验证 cgroup populated=0或域消失，再允许UID绑定清理与结果返回；失败保留明确 receipt。此为设计，不是已实现功能。
- 因完整原生负例与全写域边界未通过，不实现 Guard 适配器。磁盘预算继续独立：约42.54GiB可用低于45.78GiB floor，峰值、扫描、COW及失败清理未证明。

## Regression

| Log | Total | PASS | FAIL | SKIP |
|---|---:|---:|---:|---:|
| evidence-darwin.log | 15 | 15 | 0 | 0 |
| evidence-protection-linux.log | 15 | 15 | 0 | 0 |
| guard-darwin.log | 110 | 106 | 0 | 4 |
| guard-linux.log | 110 | 106 | 0 | 4 |
| helm-shadow/tests.log | 43 | 43 | 0 | 0 |
| helm-versioned/tests.log | 190 | 190 | 0 | 0 |
| legacy-guard-linux.log | 80 | 80 | 0 | 0 |
| original-v1/tests.log | 190 | 190 | 0 | 0 |
| path-darwin.log | 9 | 9 | 0 | 0 |
| path-races-linux.log | 9 | 9 | 0 | 0 |
| policy-core/tests.log | 5 | 5 | 0 | 0 |
| regression/tests.log | 147 | 147 | 0 | 0 |
| runtime/tests.log | 143 | 143 | 0 | 0 |
| source-lock/tests.log | 54 | 54 | 0 | 0 |

Contract另10项通过；实际命令和平台见各execution.json（本地macOS ARM64，远端Linux ARM64 UID1000）。各平台Guard4项跳过不能计为通过。旧版/新版190各通过，184差分一致。
Regression首轮因当前沙箱禁止127.0.0.1 listen而失败，保留regression-sandbox-denied；按原测试在允许loopback的环境重跑147/147。非本轮源码缺陷。
Linux guard/路径/防覆盖再次执行，远端fixture目录删除，未扩大权限。1317个此前保护文件SHA256保持不变，旧manifest未修改。原历史完整性继续FAILED。

## Production / rollback / next step

Jenkins #270 SUCCESS、V1 Summary SHA256 ec9ee51a06d4b9f61c6c0eaf50b374d1e25e6d3ca687908b7596d3a2c794f5d8 未变。ArgoSynced/Healthy；3节点Ready；PetClinic3/3、3Endpoints、HTTP200；生产digest保持489cb821573ff1f98edd846d5949d74bf3391b24e2f1fe5bcfb71c6be0793137。只读取样，非持续SLA。没有重启生产服务。
未创建常驻组件、未更改配置。transient unit collect完成；临时容器定向删除，临时sentinel目录删除。回滚无需恢复生产；本轮证据保留，不覆盖历史。
下一步唯一允许操作：独立补齐 Docker 候选的完整原生隔离/拒绝/清理失败矩阵及挂载域契约设计审查；未验收前不接适配器、不刷新、不扫描。STOP。

```text
LINUX_ISOLATION_CAPABILITY = AVAILABLE
SELECTED_ISOLATION_BACKEND = NONE
PROCESS_LIFECYCLE_ISOLATION = INCOMPLETE
DESCENDANT_TERMINATION = INCOMPLETE
FILESYSTEM_EXECUTION_ISOLATION = INCOMPLETE
STORAGE_DOMAIN_ENFORCEMENT = INCOMPLETE
VALIDATION_EXECUTION_ADAPTER = NOT_IMPLEMENTED
TRIVY_GUARD_PRODUCTION_COMPATIBILITY = VERIFIED
TRIVY_VERSIONED_COMPATIBILITY = VERIFIED
ORIGINAL_EVIDENCE_INTEGRITY = FAILED
TRIVY_VALIDATION_EXECUTION_READINESS = NOT_READY
TRIVY_RUNTIME_FACT_CAPTURE = INCOMPLETE
DEFECTDOJO_RUNTIME_FACT_CAPTURE = INCOMPLETE
FINAL_WIRED_CAPABILITY = 14/16
REAL_RUNTIME_FACT_CAPTURE = INCOMPLETE
IMMUTABLE_ARTIFACT_RUNTIME = INCOMPLETE
SUMMARY_V2_MIGRATION = INCOMPLETE
RELEASE_COUNT = 0
ROLLOUT_COUNT = 0
```
