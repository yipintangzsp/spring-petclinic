# PetClinic 生产瞬时故障联合取证 — 只读 RCA

基线 `9ebe70a82c2aea23ed6315a92d4b4cf60fe2eb64`。本轮只有只读取证、离线分析和本地报告提交。**故障确认；直接失效链路已有证据，最初触发源仍 UNDETERMINED。决策为 C：当前恢复，不做推测性生产修改。**

已确认：devops 的容器运行时/API 响应异常、PLEG 超时和 Node NotReady；同节点三个 PetClinic JVM 被既有 liveness 策略终止，随后重建受 cache 超时影响；Service 一度无 Ready 后端；Argo repo-server 同期退出，controller 无法生成目标状态。没有发生 PetClinic 新版本 rollout。

没有证据把触发源归到 Loki Candidate 测试。运行时和探针异常早于首次 Node 测试派发。不过测试运行的 Mac 与 devops QEMU VM 确实共享宿主机；历史逐进程 CPU/内存/IO 未记录，不能排除所有间接资源影响。

## 1. 时间与查询边界

只查询 **2026-11-05T02:05:00Z–02:45:00Z**（北京时间 **10:05–10:45，UTC+08:00**）。没有扩大窗口或扫描无界历史。故障前/恢复快照及既有测试证据仅用于关联。

本次“已取得证据包络”为 **02:13:15.085838Z–02:30:04.125459Z**。前者是窗口内首次取得的本地 API 超时日志，后者是确认 HTTP200/3 Ready 的快照完成时刻。**这不是精确 HTTP 不可用区间，也不是已确定的最初根因时刻。**

- 首次 502：命令派发 **02:21:31.756Z** 后、工具观察到异常 **02:22:56.013Z** 前。原请求无独立时间戳。以前手工记录错误的 02:23:50 不是 502 发生时间。
- 首次 503：旧主机程序开始 **02:27:18.975195Z** 后、结果文件写完 **02:27:35.066186Z** 前；GET 本身未打点，保留区间。
- 首次已取得的 Deployment available=0/三个 Pod Ready=0 历史观测：**02:26:30Z**，这是 Prometheus evaluation time，不是精确 kubelet/控制器转换时间。
- Kubernetes Event 的 firstTimestamp/lastTimestamp 与 metadata.creationTimestamp 分开。大量事件延迟写入。例如 liveness Killing 的 **firstTimestamp=02:18:03Z**，creationTimestamp 却是 **02:27:51–52Z**；不能用后者判断何时杀容器。
- Prometheus 查询步长30秒，有 lookback/陈旧状态和采集中断。原始抓取时间另以 `timestamp(...)` 查询保存在 focused-metrics-attempt2.json。没有把 evaluation time 当作精确事件时刻。
- 各原始 source timestamp、collection timestamp、tool observation、file write timestamp 均保留。完整44项时间线见 `timeline.json`，源日志含原 UTC 或 +08:00 时间。

## 2. 主要时间线

下表时间均为 **2026-11-05，北京时间 UTC+08:00**，UTC 原值保留在原始文件和 timeline.json。

| 时间 | 事件与组件 | 原始证据 | 影响 / 确认程度 |
|---|---|---|---|
| 10:00:30.404904 | 故障前 3/3、HTTP200、Argo Synced/Healthy | 前轮 production-before.json | 快照 CONFIRMED |
| 10:13:15.085838 | devops 本地 API `/metrics` timeout/abort | journal.json | 响应延迟 CONFIRMED，业务起点未知 |
| 10:13:16.164476 | containerd ExecSync 超时 | containerd.json，原时间 +08:00 | 运行时调用异常 CONFIRMED |
| 10:15:05–10:15:09 | 三 Pod liveness HTTP 请求超时 | inventory.json events firstTimestamp | 探针异常 CONFIRMED，早于测试 |
| 10:16:28.500 | 首轮 Loki 测试工具派发 | local-execution.json 当前聊天工具记录 | 派发时刻 CONFIRMED，非进程精确开始 |
| 约10:16:53.940 | 首轮 Node 测试约开始；10:16:54.690 有真实 Mock Receipt | TAP duration/mtime、native Receipt | 估算开始 PROBABLE；Receipt 时刻 CONFIRMED |
| 10:18:03 | 三 Pod `failed liveness probe, will be restarted` | inventory.json events | kubelet 终止原因 CONFIRMED |
| 10:18:29 | 三旧 JVM 均 exit143，previous 日志显示 graceful/Hikari shutdown | Pod lastState、runtime-logs.json | 有序 SIGTERM 路径，非 OOMKilled；CONFIRMED |
| 10:18:36 | Argo repo-server 旧容器完成退出 | inventory.json / previous repo log | 8081 服务不在运行；CONFIRMED |
| 10:20:30（观测） | 6 vCPU devops node_load1=98.38 | prometheus.json node-load | 高负载 CONFIRMED，不是已知真正峰值 |
| 10:20:34.447898 | kubelet Node Ready=false；PLEG 3m18s>3m | journal.json | Node 本地 runtime/PLEG 失效 CONFIRMED |
| 10:21:31.756–10:22:56.013 | HTTP502 发生于该观察区间 | http502-tool-observation.json | 状态 CONFIRMED，代理具体原因 PROBABLE |
| 10:23:16；10:23:21.160989 | ComparisonError；PetClinic Synced→Unknown | 前轮 health-followup.json；本轮 controller log | repo-server 连接拒绝 CONFIRMED |
| 10:23:24.481091 | PetClinic Healthy→Progressing | controller log | 不是 OutOfSync 或 Degraded；CONFIRMED |
| 10:25:01.391735 | 第二次 PLEG 超阈值、Node not ready | journal.json | 异常不是单个瞬间；CONFIRMED |
| 10:25:42–10:26:08 | 同 UID 的三个新容器启动 | Pod state / containerd log | 容器重启，非 rollout；CONFIRMED |
| 10:26:00.193795 | repo-server 启动监听8081 | current repo log | 服务自动重建已确认 |
| 10:26:30（观测） | EndpointSlice 三个地址均 ready=false | prometheus-followup.json | 无 Ready 后端；地址未删除；CONFIRMED |
| 10:27:18.975195–10:27:35.066186 | HTTP503 与 API 0/3 被观察 | 前轮 health-followup.json | 状态 CONFIRMED，请求精确时间未知 |
| 10:28:02 / 03 / 13 | 各 Pod Ready 恢复；Deployment Available 于10:28:13 | inventory.json conditions | 探针恢复 CONFIRMED |
| 10:28:20.908211 / .980000 | Argo Unknown→Synced、Progressing→Healthy | controller log | reconciliation 恢复，无新同步发布 |
| 10:29:00（观测） | Pod/Deployment/Endpoint 三 Ready | Prometheus 历史 | 恢复观测 CONFIRMED |
| 10:30:04.125459 | HTTP200、3/3、Argo正常复核 | 前轮 production-final.json | 恢复快照 CONFIRMED，精确首次200未知 |

## 3. 0/3 到底代表什么

`0/3` 是 Deployment/Pod **Ready 数量**，不能直接等同“三容器同时崩溃”。本轮另有证据证明三个旧容器确实退出，但原因是 liveness 触发的既有重启行为。

| Pod 后缀 | Pod UID | 节点 | restartCount 前→后 | 旧容器退出 | 新容器启动 | Ready 恢复 |
|---|---|---|---:|---|---|---|
| 7gqqx | 32543aa9-4b6f-418f-be1b-3795796f37b6 | devops | 5→6 | 10:18:29，143/Error | 10:25:55 | 10:28:03 |
| v7pbv | d82f840e-aaea-40f9-b877-4628dcc2522f | devops | 7→8 | 10:18:29，143/Error | 10:25:42 | 10:28:02 |
| z9q2p | 3134d6ae-f33d-4a8e-9d61-ea9fae117db6 | devops | 5→6 | 10:18:29，143/Error | 10:26:08 | 10:28:13 |

三 Pod 创建于10月29日，UID 保持不变，无 deletionTimestamp；没有新建/重新调度/Pending 的证据。旧进程 previous 日志有 Spring graceful shutdown 与 Hikari shutdown completed。最后终止 reason=Error/exit143，不是 OOMKilled。不能把143单独当原因；这里用 Killing 事件与 previous 日志共同验证。

启动延迟有直接 k3s/event 证据：10:18:47–48 `failed to sync configmap cache`，10:23:29 `failed to sync secret cache`、CreateContainerConfigError；PLEG 不健康时 kubelet 跳过 Pod synchronization。探针 `connection refused` 与新容器 startup probe 失败也保留在 events。它们是恢复过程中的状态，不代表有人改了 Secret 或重新发布。

现有 terminationGracePeriodSeconds=45，preStop=`sleep 5`；本轮未改。容器退出有完整收尾日志，不支持本轮由 termination budget/SIGKILL 或新镜像架构错误引发。

## 4. Traefik / Service / HTTP

链路配置为 PetClinic Ingress→Service→EndpointSlice→Pod；当前配置在 inventory.json 中。Traefik 在00:10:23已启动，本窗口没有其容器重启，当前旧 termination 不属于本事故。

EndpointSlice `petclinic-8lj9d` 创建时间仍为8月9日。三个地址 10.42.0.46/.44/.57 保留；历史条件为 10:22 时2 Ready+1 NotReady，10:26 时1 Ready+2 NotReady，10:26:30 三 NotReady，10:28:30 一个Ready，10:29 三Ready。这里说的是**可用 Endpoint 消失，不是地址或资源被删**。

**HTTP_502_503_CAUSE=PROBABLE**：502 与旧容器已退出但状态/Endpoint 更新延迟相容；503 与全部后端 NotReady 相容。没有当次请求 ID/访问日志/上游错误对应，不能仅凭状态码宣布具体连接拒绝/超时原因 CONFIRMED。

实际缺口已验证：Traefik flags 只有 `--log.level=INFO` 与 Prometheus，没有 accesslog；native Traefik log 中没有可对应本次 PetClinic 请求的错误。现有 `traefik_service_requests_total` 只有 cook 的标签，不能把 cook 的502计数归给 PetClinic。未发现的 entrypoint/旧 endpoint 指标查询无结果，不解释为0错误。没有修改 Traefik 或采集配置补造历史证据。与本事故无关的既有 minio service-port 报错不归为根因。

## 5. 节点 / 资源 / 运行时

直接故障节点是 **devops（ARM64、6 vCPU）**，三个副本全在它上面。主要证据是它的本地 kubelet/containerd 与127.0.0.1 API 日志，不是以前 ucloud 隧道问题的推断。

- `journal.json`：40分钟内筛选取得3892条 k3s记录（cap4000未触达）、1条kernel匹配；k3s PID1043、同 boot ID；服务无重启证据。两次明确 PLEG 超3分钟、最长取得4m12s，跳过 Pod 同步，本地API、ConfigMap/Secret cache 超时。
- K3s 使用嵌入式 containerd，独立 containerd unit 没日志不是“无运行时问题”。补读实际 `/var/lib/rancher/k3s/agent/containerd/containerd.log` 尾部最多2MiB，首时间早于本窗口；取得1100条窗口内日志。早在10:13:16已有 ExecSync DeadlineExceeded。
- `node_load1` devops 可见峰值 **98.38**；CPU PSI waiting rate 可见峰值 **0.9620 s/s**，表示CPU争用等待时间比例，不是CPU利用率96%。资源争用关联 **CONFIRMED**；是否最初触发 PLEG/API 延迟为 **PROBABLE**。
- 可见 MemAvailable 最低约 **5.92GiB**，根文件系统可用最低约 **42.56GiB**；可见 MemoryPressure/DiskPressure/PIDPressure 样本未置真。kernel窗口无OOM记录，三JVM lastState也非OOMKilled。关键缺口内不能宣称从未出现任何压力。
- Prometheus node-exporter gauge 在 **10:14:30–10:20:30** 缺测，KSM在 **10:14:30–10:21:30** 缺测；不能用前后样本填补、插值成正常或用30秒step冒充每30秒真实采集。
- CPU topk(8) 查询已基于真实 `node="devops"` label。可见单Pod最大约0.61核（GitLab），但不覆盖关键缺口，不能指定它为触发源或把load98归给某一个Pod。宿主k3s等进程的历史CPU/调度堆栈未记录。
- node exporter mapping 10.0.0.3=devops 由 kube_node_info 核对。两个 worker 的可见 Ready 样本没有同类变化，但采集端同在devops且存在缺口，不构成连续健康证明。未取得worker宿主机journal；没有证据支持把历史SSH tunnel故障套用为本次根因。
- 当前路由/接口/TCP统计为 current-only，不作为事故时的丢包/MTU/隧道证据。没有抓包、注入故障、改网络或扩大权限。

## 6. Argo CD

**ARGOCD_ABNORMALITY_CAUSE=CONFIRMED（直接原因）**：repo-server在10:18:36退出，10:26重新启动；旧Application ComparisonError明确 `10.43.95.130:8081 connect: connection refused`。应用controller进程本窗口未重启，日志按 `application==petclinic` 精确过滤，没有把同namespace的 platform-messaging 变化混入。

变化是 **Synced→Unknown、Healthy→Progressing**，不是已证实 OutOfSync、Degraded、Git漂移或新发布。controller多次 `Skipping auto-sync`；10:28:20重新生成/比较后恢复Synced/Healthy。repo-server退出的更深触发原因仍归入节点资源/运行时链路待定，不能由 connection refused 单独反推。

Deployment generation175、revision164、活动RS `petclinic-7b9fc47976`、Pod UID、spec hash、image不变；所有归属PetClinic Deployment的RS都早于本窗口创建。前后 Git revision未变化，原Argo last successful sync不是本窗口新发布。**实际 PetClinic rollout=0，容器重启=3。**

## 7. Prometheus / Loki 的覆盖和缺口

Prometheus 原查询、标签、series矩阵、HTTP结果保存在 prometheus*.json、focused-metrics-attempt2.json；没有借空查询编造指标。未采集 `argocd_app_info`，Argo历史用native controller/repo日志替代。实际EndpointSlice指标是 `kube_endpointslice_endpoints`，没有沿用不存在的旧 endpoint gauge。

Loki 对 PetClinic 的真实 query_range 返回 **341条**，含旧进程收尾与新进程启动。Argo/Traefik查询200但0条，不等于它们没有错误：Alloy现有keep规则仅包含 petclinic、cook、devsecops-system/falco，未覆盖它们；CM hash与前轮一致。其native Kubernetes日志有实际内容。未修改采集、Retention或Dashboard。Loki查询是生产既有日志的只读RCA，不是 V2 Candidate 的真实投递验证。

## 8. 测试时间与因果关系

原测试为 **Darwin ARM64** 原生 Node/Python临时副本，非guest Linux/K3s上的测试进程。原runner执行git archive、复制fixture、sandbox-exec；允许网络仅loopback32185/32187，真实外网拒绝预检已封存。没有生产 Loki/Dojo目标、Docker构建、Jenkins触发、kubectl mutation、Argo同步或扫描调用。本轮没有重新执行测试或扫描。

| attempt | Node约开始（北京时间） | TAP写完 | 原生耗时 | 性质 |
|---:|---|---|---:|---|
| 1 | 10:16:53.940 | 10:16:58.963 | 5.023s | Loki定向 |
| 2 | 10:19:14.394 | 10:19:51.927 | 37.533s | 相关完整回归 |
| 3 | 10:21:16.233 | 10:21:22.520 | 6.287s | Loki/Grafana定向 |
| 4 | 10:24:31.286 | 10:25:11.238 | 39.951s | 相关完整回归 |
| 5 | 10:27:44.052 | 10:28:07.285 | 23.232s | 299/299通过 |

约开始=Node native duration与TAP写入mtime推导，不是精确process start。派发、真实Receipt的首末时刻另外保存。完整测试前的hash/copy准备不在Node耗时中；没有历史CPU、内存、磁盘峰值可补测，保持 UNKNOWN。

共享物理宿主已证实：Mac QEMULauncher UUID **4C8DEDBC-D2FB-43F6-99EC-C2C6F9C1FF46** 与 devops kube_node_info system_uuid相同，6vCPU、memoryArgument22528。不能只因Mock在loopback就排除宿主资源争用。当前ps没有匹配测试残留，原临时树均已清理。

同40分钟Mac unified log读取621条匹配，主要为普通 memorystatus idle-exit/non-fatal记录；未见可证明QEMU OOM/测试诱发压力的记录。QEMU/UTM的两条XPC记录在10:41，不能归因于10:15–28事故。当前进程RSS/CPU不代表历史。CPU steal可见样本为0，也不能填补缺口证明宿主完全无影响。

结论分层：**时间重合 CONFIRMED；共享宿主 CONFIRMED；测试直接修改生产/把测试作为异常最初触发者 NOT_SUPPORTED；间接宿主CPU/内存/IO贡献 UNKNOWN。整体 LOKI_CANDIDATE_TEST_CAUSALITY=UNKNOWN。**

## 9. 根因、恢复和风险

- **ROOT_CAUSE=UNDETERMINED / UNKNOWN**：未识别最初造成CPU/运行时阻塞的进程或事件。不能把“Node NotReady”“PLEG不健康”再次作为未解释的最终根因，也不能仅按时间重合归罪测试。
- **直接失效机制 CONFIRMED**：本地runtime/API迟滞→探针失败/既有liveness终止→同节点3 JVM退出；cache/PLEG阻止及时重建/状态传播；无Ready后端；repo-server退出导致Argo ComparisonError。
- **CONTRIBUTING_FACTORS**：3副本同devops是CONFIRMED放大因素；CPU争用的存在CONFIRMED，其对延迟的贡献PROBABLE；具体触发源UNKNOWN。
- **RECOVERY_MECHANISM=CONFIRMED**：kubelet既有策略重建同UID容器；Spring/Hikari启动、探针恢复；Endpoint条件恢复；repo-server启动，controller重新比较恢复。导致底层阻塞消退的原因仍 UNKNOWN。不是本轮重启/修复。
- **RECURRENCE_RISK=POSSIBLE**：相同单节点故障域与未知触发源仍在；当前健康不是稳定性/复发概率保证。本轮证据不支持宣布永久修复。

决策 **C**。`PRODUCTION_FIX_REQUIRED=UNDETERMINED`；没有提出或执行基于猜测的探针、资源、网络、Jenkins、Argo、存储改造。

## 10. 当前基线与变更边界

当前03:07:55Z基线复核：#270 SUCCESS / last270 / queue0，V1 Summary SHA `ec9ee51a06d4b9f61c6c0eaf50b374d1e25e6d3ca687908b7596d3a2c794f5d8`、Jenkins job hash不变；PetClinic3/3、HTTP200、Argo Synced/Healthy、三节点Ready、socket0660；image仍 `sha256:489cb821573ff1f98edd846d5949d74bf3391b24e2f1fe5bcfb71c6be0793137`。11:15:31+08 的另一次业务GET也为200，EndpointSlice当前三Ready。

所有RCA remote payload都经严格校验host key的SSH stdin运行，不上传remote文件。Kubernetes采集为GET/raw/log，systemctl仅show，journalctl和文件读取，监控仅GET。Jenkins核验复用已审查只读脚本：已有relay exec与 `/scriptText` POST只读取构建/artifact和hash，不调度构建、不改配置。这些连接不是生产资源变更。没有重启/删除/驱逐、apply/patch、Helm、Docker daemon改动、清理、测试资源、DB更新、扫描、push、release或rollout。

原始配置/镜像/UID/generation比较证明与只读命令记录共同支持“本轮未发起变更”；不声称有全平台API审计证明其他操作者从未做任何操作。

## 11. 证据保护与验证

新证据只在 `evidence/2026-11-05/production-transient-rca/`。保护基线含 **13,894文件、12,956历史evidence文件**，记录内容SHA/size/mode/uid/gid/mtimeNs/ctimeNs/inode/symlink及历史清单。OS canary 覆盖/删除/chmod均DENIED，临时写入允许且清理。未执行旧回归入口、未覆盖前轮失败/成功证据。

离线分析有源JSON pointer、实际矩阵与raw时间，断言验证Pod UID/三个重启/143/旧RS/一致spec、Endpoint三NotReady、原job/summary/digest。源码语法用compile检查，不运行生产扫描。首次本地remote.py语法错误在SSH前修正；focused-metrics首次远端语法错误保存在focused-metrics.json，未执行API读取；后一次成功写独立attempt2，未覆盖失败。

封存与回归验证由verify-evidence.py读取；Git staged/commit bytes另核对manifest。**ORIGINAL_EVIDENCE_INTEGRITY=FAILED保持。** 本轮正向校验不重写旧判定。

## 12. 最小观察方案与唯一下一步

**唯一建议动作：复用现有Prometheus与日志做一次针对devops资源阻塞来源的有界只读观察/复发取证。** 不需要先改平台。正常时关联现有node_load1、CPU PSI、up/真实scrape时间与Pod CPU；若复发，立即保留同一15分钟前后窗口的k3s/containerd、Pod current/previous、Event first/last/creation、Endpoint条件及Argo日志，并同步保留Mac/QEMU与guest逐进程CPU/调度/IO信息和准确时区。现有资料缺少当时逐进程归因；不在本轮新建持续采集组件或监控规则。

必须补齐的关键证据：高压缺口内guest与Mac/QEMU进程级资源/调度数据；当次PetClinic代理access/upstream错误和请求ID；更精确HTTP失败/首次恢复打点；若怀疑网络，需同期packet/drop或两端日志而非当前route。未得到这些证据前不做具体生产修复。

完整逐项 verdict：`verdict.json`。本轮实际 PetClinic rollout=0；release=0；生产修复=NO；Candidate VERIFIED继承前轮且未重跑；production Manager NOT_ACTIVE；14/16与原Integrity FAILED不变。

**STOP。**
