# devops 节点资源争用：有界只读观察

本轮基线 `4e9ea4161e3f25d9a79f936aa652796352a8e708`，只读调查，无生产配置变更、发布、rollout、扫描或 push。文中时间使用北京时间（+08:00）；JSON 保留 UTC 原始时间。新证据全部位于本目录，历史 RCA 及封存证据不改写。

结论：**故障机制已缩小到显著的 runnable / CPU 调度争用，但始发进程及根因仍 UNDETERMINED。** `NODE_HIGH_LOAD_SOURCE=PARTIALLY_IDENTIFIED` 表示已识别压力类型和部分可见贡献，绝不表示找到了触发故障的具体进程。

## 观察执行及提前停止

- 原计划：六次采样，间隔 120 秒，覆盖约 10 分钟，硬上限 30 分钟。`observe.py` 首行注释误写为 seven，实际执行参数及 `observation-plan.json` 均为六次；保留执行时源码，不改写该注释。
- 实际仅一次 Host/Guest 配对采样：**11:37:41.756–11:37:48.277，6.521 秒**。没有把历史指标查询时间算入连续在线观察。
- Guest 采样 CPU 计数 1.032895 秒，Host 1.222684 秒，均超过预先设置的每次 1 秒自身开销预算；主程序停止，不再启动第二次采样。Host 的进程/子进程 CPU 统计是进程范围，在并行 SSH 存在时不构成精确的逐线程开销归因；采用保守停止。
- 当时未触发严重节点负载/业务不可用停止条件。该停止是自身预算约束，**不是采样导致生产故障的证据**。
- 停止后仅请求已有 Prometheus 历史序列及观察时刻的历史 instant 数据，无新增现场进程快照、后台 agent、无限循环、自动恢复或重试放宽预算。`observation-receipt.json` 为实际执行回执。
- 因连续观察未完成，`NODE_CPU_PRESSURE_OBSERVATION=INCOMPLETE`；没有完成 10/30 分钟观测，也没有证明周期性。下轮不得直接重跑当前采样器。

## 历史真实观测

事故分析窗口 10:05–10:45，新增历史 query_range 步长 30 秒。复用上一轮 `../production-transient-rca/` 的真实指标及日志，新增查询见 `historical-metrics.json`，离线统计见 `analysis.json`。下列是可见样本最大值，不是缺测期间的真实峰值上界；Prometheus evaluation 时间也不等于精确事件发生时间。

| 指标 | 可见事实 | 限制 / 意义 |
|---|---|---|
| devops vCPU | 6 | 既有配置，未修改 |
| Load1 / Load5 | 98.38 / 77.98，10:20:30 | Load 包含 runnable 和不可中断等待，不能单凭 Load 判定来源 |
| CPU PSI some rate | 0.9620，10:27:30 | CPU 调度等待显著，来自上一轮已封存指标 |
| runnable | **68，10:23:30** | 本轮新增 `node_procs_running`，远超 6 vCPU；确认 runnable 压力 |
| I/O blocked | 最大 1，10:14:30 | `node_procs_blocked` 不是完整历史 D-state 线程清单，不能排除缺测期 D-state 突增 |
| 非 idle 比例 | 99.594%，10:21:30 | 包含 iowait 等非 idle 模式，不冒充纯 user CPU |
| CPU 模式（上一轮） | user 最大 3.4624 核、system 最大 1.1067 核，均在 10:14:30；iowait 最大 0.02678 核；steal 可见值为 0 | 各模式极值不能相加当作同一时刻总量；steal=0 不能排除宿主机调度争用 |
| Guest memory PSI | 可见最大约 0.528% | 不能解释为全时段无内存压力 |
| Guest I/O PSI | 可见最大约 7.395% | CPU PSI 更突出；不能排除 I/O 贡献 |
| vda 平均读/写 service time | 26.64 / 18.66 ms，10:26:00 | 计数器 rate 比值，不是应用文件系统 P99 延迟 |
| K3s 进程 CPU | 最大 **1.3794 核，10:15:00** | kubelet metrics 的 process counter 对应 K3s 一体化 PID；不可把多个组件 endpoint 重复相加。10:15–10:28:30 间存在关键缺测，不能归因始发源 |
| CFS throttled periods / periods | Filebeat Kafka 最大 76.47%，10:15:30；三个 PetClinic 恢复期最大 69.32%–72.31%，10:26:30–10:28:30 | 只确认同事故/恢复窗口的容器限流相关现象，不是 CPU 时间损失比例，不证明任一 Pod 引发节点阻塞 |
| CFS throttled seconds | 当前没有该指标 | UNKNOWN，不当作 0 |

主要盲区：Node gauge 在 10:14:30–10:20:30 等区间缺测，KSM 在 10:14:30–10:21:30 缺测，cAdvisor 限流序列也有关键缺口。实际查询、标签、有效点数和缺口逐序列保存。已有数据不支持重建缺失时段的 PID 排名。

上一轮可见 container CPU topk 没有出现足以独立解释 Load98 的单个 Pod（例如 GitLab 可见峰值约 0.61 核）。这既不能排除业务并发，也不能据此指定 GitLab 为根因。三个 JVM 在恢复阶段各约 0.42–0.44 核，时间晚于初始 API/runtime 超时。旧 JVM exit143 且有正常收尾日志，不属于已证实 OOM。

复用的事故链仍成立：10:13:15 API/metrics 超时、10:13:16 runtime ExecSync 超时 → liveness 失败 → 三个 JVM 退出/重启 → ConfigMap/Secret cache 与 PLEG 异常 → 10:26:30 三 Endpoint ready=false → 10:28:20 Argo 恢复，随后应用恢复。其触发源没有因此确认。

额外读取观察前已存在的 11:07:41–11:37:41 指标（60 秒步长）：Load1 可见最大 6.1、runnable 最大 19、I/O blocked 全为 0；31 个评估点未见同级 Load98 事件。30 分钟历史窗口不足以证明无周期性，不能当作 30 分钟在线采样。

## 当前进程及容器：仅 11:37 配对快照

Guest loadavg 3.31 / 3.13 / 3.30；CPU PSI avg10=12.03%，memory / I/O avg10=0。线程状态 S=2839、I=78、R=3、Z=4，没有可见 D-state。`vmstat 1 3` 的两个间隔行 runnable=2/0、blocked=0/0、idle=78%/88%、iowait/steal=0、swap-in/out=0；首行是启动以来平均，不作为采样间隔结论。

29 条选中进程记录中，20 条通过 `/proc/<pid>/cgroup` Pod UID 与历史 KSM Pod identity 匹配。其余标为主机服务或明确未映射；完整关联和 request/limit、2 分钟容器 CPU/限流值见 `analysis.json#/currentProcessContainerJoin`。进程选择偏向 lifetime CPU 排名及目标服务，不是完整节点所有 PID 的实时排序。

| 当前进程 | 关联 | 约 2 秒进程 CPU delta（核） |
|---|---|---:|
| k3s-server PID1043 | system.slice/k3s.service | 0.2691 |
| containerd PID2597 | K3s 的 containerd | 0.0299 |
| java PID25250 | default / elasticsearch | 0.0548 |
| java PID22733 | ns-devops / jenkins | 0.0498 |
| prometheus PID22005 | monitoring / Prometheus | 0.0349 |
| PetClinic 三 JVM | 通过 UID 逐个匹配 | 0.0199 / 0.0100 / 0.0050 |

以上不是事故时进程快照。`ps %CPU` 为 lifetime 口径，单独保存，未冒充 interval CPU。Prometheus 2 分钟容器 rate 与约 2 秒 PID delta 也不直接等同；同一个 Pod 多个进程时不重复累加 Pod CPU。

三个 PetClinic 均在 devops，每个 requests=100m/512Mi、limits=500m/768Mi。Jenkins requests=500m/1Gi、limits=2CPU/3Gi；当前 Elasticsearch 只有 memory request/limit，Prometheus 只有 memory request（以可见 KSM 为准）。这些是资源清单，不据此自动修改任何配置或认定某个服务滥用 CPU。

## Host / Guest 对应

- macOS：10 CPU、32GiB；QEMULauncher PID64491 的 VM UUID `4C8DEDBC-D2FB-43F6-99EC-C2C6F9C1FF46` 匹配既有 devops system UUID；命令配置 6 vCPU、22528MiB RAM。未调整配置。
- 本轮 QEMU 约 2 秒 delta 为 3.6896 核，RSS 约 7.49GiB；Host top 第二次读数 user41.50% / sys35.28% / idle23.20%，并行存在 Code/Chrome/虚拟化等进程。
- Host swap used 4521.19MiB，top 显示约15GiB compressor，短区间 swapins +12 页、swapouts +0；`kern.memorystatus_vm_pressure_level=2` 原样保存，不未经核实解释为 OOM。
- Host/Guest **采集窗口重叠**，CPU 子窗口相近但不严格同步，也不能直接做 QEMU CPU 与 Guest CPU 的差值归因。Mac PID 比较使用 PID/comm/PPID，没有独立的 start-time 字段，存在微小 PID 复用不确定性。
- **没有事故时同时间 Host 进程级 CPU/内存/QEMU 记录**。因此宿主机和 QEMU 因果关联仍 UNKNOWN；Guest 内找不到 QEMU 不影响已确认的宿主机映射。不能把 11:37 的 Host 压力倒推为 10:13 的故障原因。

## Loki Candidate 关联复查

`loki-preparation-timeline-v2.json` 保存当前聊天已有工具调用的时间戳、行号和行 hash，只保存操作标签，不导出敏感参数。第一份时间线误用 custom_tool_call 的 arguments 字段，标签为空，保留并由 v2 显式纠正。

- 10:00:03 已有只读生产检查和 preflight 相关调用，10:01:13 可观测检查；准备并非全部在事故之后。
- 10:13:00 调用只是 **cat/sed/head 读取 preflight、fixture 与基线**，不能把文件名出现当作执行 preflight 或扫描。10:13:50、10:14:06 有只读检查。
- 10:16:10 写入本地 HTTP boundary/preflight/runner 脚本；此调用标签有 archive/runner 文本，**不表示此时已执行 archive 或 Node 测试**。
- 第一轮测试 runner 调度 10:16:28.500，估计 Node 10:16:53.940–10:16:58.963；后续测试约 10:19:14–19:52、10:21:16–21:23、10:24:31–25:12、10:27:44–28:08（估计值，原始 native receipts 及差异见上一轮 `local-execution.json`）。
- 这些 Node 测试运行于 Mac，本地 Mock 端口32185/32187，和 devops QEMU 共享宿主机。没有其历史 CPU/RAM/I/O 峰值；后续测试与故障重叠，既不能证明触发，也不能排除后续贡献。
- 第一轮 runner 在开始 Node 前还要校验保护文件、git archive、复制临时输入；没有完整逐步骤资源计数。此前编辑/准备阶段亦没有 CPU 时间线。本次补充时间戳不能补造这些计数。
- 初始 runtime 异常早于首轮 Node/runner，不能把测试认定为已确认初始触发源；也不以此排除所有准备活动。历史 RCA 检查时无残留测试进程，本轮未启动任何 Candidate 测试。

`LOKI_CANDIDATE_TEST_CAUSALITY=UNKNOWN` 保持。

## 假设、缺口及下一步

| 假设 | 本轮判断 |
|---|---|
| runnable 队列 / CPU 调度争用构成故障机制 | CONFIRMED，6 vCPU / runnable68 / PSI96% / 非idle99.6% |
| 大量 D-state / I/O 等待是主要来源 | NOT_CONFIRMED，可见 blocked≤1；关键缺测不允许排除 |
| K3s 自身 CPU 或 runtime 工作放大压力 | POSSIBLE，1.38 核可见贡献和同步 runtime 异常，但触发/受害关系未知 |
| 单个业务容器启动全节点阻塞 | UNKNOWN，现有历史 CPU、限流及缺口不足以确认 |
| 三 JVM 同时重启放大恢复压力 | POSSIBLE，恢复期 CPU/限流真实可见，晚于始发异常 |
| macOS / QEMU 调度、内存压缩竞争 | UNKNOWN，缺少事故时配对记录 |
| Loki Candidate 触发 | UNKNOWN，准备记录不完整、初始异常早于 runner、无历史进程开销 |
| 周期性峰值 | UNKNOWN，观察仅一组，短历史窗口不构成周期分析 |

现有证据**不支持立即调整探针/requests/limits、重启 K3s、修改 VM 或指定某进程作为根因**。三副本集中 devops 的故障域放大效应已存在，但不在本轮变更授权内，也不等同于 CPU 压力来源。

下一步建议仅限单独设计更低开销、分开计量 Host/Guest 的有限采样方式，并先离线校验开销。自然复发时需要同时间 PID/thread/cgroup CPU delta、runnable/D-state、Host QEMU/CPU/内存证据；优先复用已有指标。当前采样器已停止，不自动启用新采集，也不主动制造故障。不具备实施针对具体进程的生产修复证据。

## 生产保护及证据边界

最后一次真实在线健康读数为 **11:37:48.254**：三节点 Ready；PetClinic3/3、HTTP200；Argo Synced/Healthy。Pod UID、restartCount 与上一轮最终基线相同，三个 digest 未变。不是报告完成时的持续可用性保证。Jenkins#270、V1 Summary、Deployment spec、Docker/socket 完整基线沿用上一轮已验结果；本轮没有重新取所有服务的现场证明，不将历史证明冒充本轮末次实测。

本轮只执行 proc/ps/vmstat/sysctl/top、少量 Kubernetes GET、HTTP GET 和 Prometheus GET；SSH StrictHostKeyChecking=yes，不写远端文件、无常驻采样、未修改任何生产状态。`memory_pressure` 未执行分配压力，详见 `read-only-tool-choice.json`。发布/rollout均为0，未执行 Trivy 或 Dojo。

先运行了真实 sandbox Write Boundary Preflight：本轮 canary 的覆盖/删除/chmod 被拒绝，临时写入可用并清理，没有对历史文件做写入探测。在线父采集器因需要 SSH 网络，并未声称整体由该 network-deny sandbox 执行；其输出采用本目录固定路径和 exclusive create。边界最终还由保护清单比对证明，非仅口头承诺。

保护上一轮13,894个文件及新增RCA37个文件，共 **13,931** 个文件的内容和指定元数据（size/mode/uid/gid/mtime/ctime/inode/symlink），并检查历史 evidence 文件名集合无增删。核验见 `verification.json`；本轮文件封存清单 `evidence-sha256.json`。这只证明本轮未改坏既有基线，**不修复历史完整性失败**：`ORIGINAL_EVIDENCE_INTEGRITY=FAILED` 永久保留。

变更仅本轮报告、采集/离线分析脚本和独立证据，不改业务代码与部署文件。未重跑已封存的 Policy/Trivy/Docker 全套测试（相关源码未改）。`verify.py` 做离线语法/JSON、事实关联、停止条件及证据完整性核验，无远端操作。报告收口后 STOP。

## 最终 verdict

以 `verdict.json` 为结构化权威记录：

```text
NODE_CPU_PRESSURE_OBSERVATION=INCOMPLETE
NODE_HIGH_LOAD_SOURCE=PARTIALLY_IDENTIFIED
RUNNABLE_TASK_PRESSURE=CONFIRMED
D_STATE_TASK_PRESSURE=NOT_CONFIRMED
CONTAINER_CPU_CORRELATION=CONFIRMED
K3S_RUNTIME_CPU_CORRELATION=POSSIBLE
MAC_HOST_CPU_CORRELATION=UNKNOWN
QEMU_RESOURCE_CORRELATION=UNKNOWN
LOKI_CANDIDATE_TEST_CAUSALITY=UNKNOWN
ROOT_CAUSE=UNDETERMINED
OBSERVATION_DURATION=6.521s (one paired snapshot; stopped early)
PRODUCTION_FIX_EXECUTED=NO
CURRENT_PRODUCTION_HEALTH=HEALTHY (11:37:48 snapshot only)
EVIDENCE_WRITE_BOUNDARY=VERIFIED
FINAL_WIRED_CAPABILITY=14/16
ORIGINAL_EVIDENCE_INTEGRITY=FAILED
RELEASE_COUNT=0
ROLLOUT_COUNT=0
```
