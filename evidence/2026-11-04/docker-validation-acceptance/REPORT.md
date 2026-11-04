# Docker native validation acceptance — 2026-11-04

结论：Docker 原生进程和受限文件系统测试通过；后端 NOT_READY。存储配额未证明、daemon不可响应时完整清理未实测、Jenkins现有rootful socket最小权限边界不成立。不实现适配器。

## 执行域与安全基线

主机 devops / 192.168.64.11，Linux ARM64；普通 SSH UID1000，严格 host key；Docker Engine 29.6.2。daemonID 4616ba22-4e70-4b96-8e66-6a3a4d756cb2；root=/var/lib/docker，driver=overlayfs（io.containerd.snapshotter.v1），cgroup driver=systemd/v2。SecurityOptions有AppArmor/seccomp/private cgroupns，没有rootless/userns-remap证据。

镜像固定 sha256:fbecd461fc72d21b2143c6eaba25143738079154a6d0ea3da3aec724f50eed4a，pull=never。非root65534，read-only root，cap-drop ALL，no-new-privileges，无网络/端口，无privileged/hostPID/hostIPC/hostPath/生产Secret/registry credential，CPU0.5、memory48MiB、swap48MiB、pids24，专用tmpfs4MiB+/tmp1MiB、shm1MiB、log-driver none。仅启动测试Python，不执行Trivy。完整命令见native-results-final.json。

## 实际原生测试

| Case | Classification | Result |
|---|---|---|
| single-normal | REAL_CONTROLLED_EXECUTION | PASS |
| nonzero-exit | REAL_CONTROLLED_EXECUTION | PASS |
| parent-child-normal | REAL_CONTROLLED_EXECUTION | PASS |
| multilevel-setsid-sigterm-kill-escalation | REAL_CONTROLLED_EXECUTION | PASS |
| parent-exit-orphan-descendant | REAL_CONTROLLED_EXECUTION | PASS |
| docker-kill | REAL_CONTROLLED_EXECUTION | PASS |
| watchdog-timeout | REAL_CONTROLLED_EXECUTION | PASS |
| cleanup-running-container-denied | REAL_CONTROLLED_EXECUTION | PASS |
| filesystem-and-bounded-storage | REAL_CONTROLLED_EXECUTION | PASS |
| daemon-unreachable-client | SIMULATED_TRANSPORT_UNAVAILABLE_NOT_NATIVE_DAEMON_FAILURE | INCOMPLETE |

single正常退出0，非零退出7，普通父子完成；多级树4个宿主PID，setsid脱离原进程组，忽略SIGTERM后stop超时升级并退出137；孤儿测试父退出0，后代随PID namespace/cgroup域停止；docker kill和watchdog timeout均终止完整隔离域。实际cgroup.procs、docker top PID/PPID/SID、state和after域消失证据保留。外部宿主探针进程仍存在，未使用全局kill。
孤儿首轮触发器docker exec随PID1退出得到137，测试误当失败；首轮原样保留。修正为允许触发器0/137，且必须容器父ExitCode=0+完整cgroup消失，再重跑全部9例通过。不是放宽生产Gate。
运行中docker rm真实拒绝；记录wouldPermitNextStep=false，然后仅定向stop/rm已登记ID。整个测试finally按本轮ID回收；最终无专用label容器，临时宿主sentinel目录已删除。
daemon不可响应只使用不存在的临时unix socket模拟客户端不可达，不停止生产daemon；不算原生daemon故障通过。真实daemon失联后的清理策略仍INCOMPLETE。测试流程异常的finally已在首轮实际触发并成功删除该ID。

## 文件系统边界

真实执行根目录、../、宿主临时哨兵绝对路径、symlink→/、目录移除后替换symlink→/均拒绝写入；/validation四目录各4KiB写入成功，共16384 bytes。主机侧sentinel保持不变；无宿主绑定卷，kernel mount/PID隔离而非路径字符串检查。
FILESYSTEM VERIFIED仅适用于本次固定镜像/参数、无host bind的受限执行配置；不代表未来自定义镜像、额外挂载或任意Docker CLI参数。目录替换为实际顺序替换负例，没有声称并发host bind TOCTOU测试。
读取实际statvfs字节/inode与mountinfo，/validation为4MiB专用tmpfs，其余write domains见storage-map.json。没有填盘测试、没有制造inode耗尽。

## 存储域与配额

| Region | Container path | Host/backing | Filesystem | Limit |
|---|---|---|---|---|
| root overlay | / | containerd snapshotter overlay lower/upper; readonly container mount | host /dev/vda2 ext4 253:2 | shared production backing; no proven per-container quota |
| cache/temp/report/metadata | /validation/{cache,temp,report,metadata} | dedicated tmpfs | container private mount/device in filesystem-facts.json | 4MiB tmpfs total; only16KiB test writes |
| temporary | /tmp | dedicated tmpfs | container private mount | 1MiB configured |
| IPC/dev | /dev/shm; /dev | private tmpfs/dev mounts | container private IPC/device mounts | shm1MiB configured; dev mount available per mountinfo, no host devices added |
| Docker metadata | n/a | /var/lib/docker | /dev/vda2 ext4 253:2 | shared; available45617647616 bytes; free inodes15324262; no proven quota |
| snapshot runtime | overlay backing | /var/lib/containerd | /dev/vda2 ext4 253:2 | same shared disk; full COW/metadata upper bound unknown |
| generated config | /etc/hosts /etc/hostname /etc/resolv.conf | Docker-managed per-container config files | observed mounts in filesystem-facts.json | not user bind mounts; UID65534 cannot modify root-owned files; cleanup owned container only |

`docker create --storage-opt size=4m`返回成功，临时对象未启动且已删除；接受参数不等于执行磁盘配额。未运行写满测试，也没有充分driver配额证据，因此UNKNOWN，不能报VERIFIED或凭猜测报UNAVAILABLE。tmpfs上限只能约束其自身，不能约束daemon metadata/snapshotter/COW。
存储域映射保留INCOMPLETE：共享ext4主机域已定位、容器mount已采集，但运行时overlay全部物理分配/COW/daemon新增元数据上界及强制限额未证明。监控失败时的真实adapter拒绝策略NOT_TESTED；没有适配器，不能用mock替代。

## Jenkins权限

jenkins-mounts.json记录生产Jenkins已挂载Docker socket、CLI及docker.original，UID1000；storage-permissions.json中Jenkins执行docker info返回与主机完全相同daemon ID。socket可访问rootful daemon，等效宿主root管理权限。仅Docker wrapper不能防止仓库代码直接调用socket/raw API。
当前权限边界FAILED：不能把此权限当成正式validation最小权限入口。不可信构建代码与容器创建权限必须由可信执行器隔离；固定镜像digest、entrypoint、argv及挂载白名单，拒绝socket/host namespaces/privileged/额外挂载，且构建代码不能访问创建端。仅评估，未改Jenkins/RBAC/daemon权限。Jenkins #270精确历史agent placement未重新取证，不从controller容器身份推断所有agent。
只读Deployment初次jsonpath格式错误已保留，后用JSON提取mount元数据成功；未读取或输出Secret值。

## Regression

| Log | Total | PASS | FAIL | SKIP |
|---|---:|---:|---:|---:|
| evidence-protection.log | 15 | 15 | 0 | 0 |
| guard.log | 110 | 106 | 0 | 4 |
| helm-shadow/tests.log | 43 | 43 | 0 | 0 |
| helm-versioned/tests.log | 190 | 190 | 0 | 0 |
| original-v1/tests.log | 190 | 190 | 0 | 0 |
| paths.log | 9 | 9 | 0 | 0 |
| policy-core/tests.log | 5 | 5 | 0 | 0 |
| regression/tests.log | 147 | 147 | 0 | 0 |
| runtime/tests.log | 143 | 143 | 0 | 0 |
| source-lock/tests.log | 54 | 54 | 0 | 0 |

Contract另10项通过。旧/新版各190/190、184 frozen差分一致且原始事实保留；Guard106PASS/4SKIP，路径9、防覆盖15通过。命令/平台见对应execution.json（本地macOS ARM64）。4个Guard进程沙箱测试SKIP不能算通过；原生Docker进程证明单独记录，不偷换旧Guard状态。
此前1759个保护文件SHA256不变，原历史完整性继续FAILED。所有日志/fixture输出仅在新证据目录/私有临时树，没有重写旧manifest。

## Production / rollback / next step

Jenkins#270 SUCCESS；V1 SHA256 ec9ee51a06d4b9f61c6c0eaf50b374d1e25e6d3ca687908b7596d3a2c794f5d8 不变；Argo Synced/Healthy，3节点Ready，PetClinic3/3、3Endpoints、HTTP200；生产digest 489cb821573ff1f98edd846d5949d74bf3391b24e2f1fe5bcfb71c6be0793137 未变。read-only取样不代表持续SLA。无DB刷新、scan、Dojo、release、rollout、push。
代码变更仅本轮独立测试/证据/报告；Guard/Gate/生产文件未改，不需要生产配置回滚。临时容器、配额probe对象和目录已删除，不执行prune或清理未知资源。
Backend NOT_READY：强制条件5（完整存储容量边界）、6（可信最小权限执行路径）、7（真实daemon失联清理）未成立；不得接正式适配器。
唯一下一步允许操作：对存储限额与可信执行器的阻塞做只读设计/能力补证，形成有界清理与传输契约；保持不实现、不刷新、不扫描。STOP。

```text
DOCKER_ISOLATION_BACKEND = AVAILABLE
DOCKER_PROCESS_LIFECYCLE = VERIFIED
DOCKER_DESCENDANT_TERMINATION = VERIFIED
DOCKER_FILESYSTEM_ISOLATION = VERIFIED
DOCKER_STORAGE_DOMAIN_MAPPING = INCOMPLETE
DOCKER_STORAGE_QUOTA_ENFORCEMENT = UNKNOWN
DOCKER_FAILURE_CLEANUP = INCOMPLETE
DOCKER_JENKINS_PERMISSION_BOUNDARY = FAILED
DOCKER_VALIDATION_BACKEND_READINESS = NOT_READY
VALIDATION_EXECUTION_ADAPTER = NOT_IMPLEMENTED
TRIVY_VALIDATION_EXECUTION_READINESS = NOT_READY
TRIVY_RUNTIME_FACT_CAPTURE = INCOMPLETE
DEFECTDOJO_RUNTIME_FACT_CAPTURE = INCOMPLETE
FINAL_WIRED_CAPABILITY = 14/16
ORIGINAL_EVIDENCE_INTEGRITY = FAILED
REAL_RUNTIME_FACT_CAPTURE = INCOMPLETE
IMMUTABLE_ARTIFACT_RUNTIME = INCOMPLETE
SUMMARY_V2_MIGRATION = INCOMPLETE
RELEASE_COUNT = 0
ROLLOUT_COUNT = 0
```
