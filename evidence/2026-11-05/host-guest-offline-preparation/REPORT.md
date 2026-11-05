# Host/Guest 低开销同步取证：离线准备

基线 `879db23821961b322d1c426512b9c00a28f9d8b9`。本轮仅离线源码、静态分析和禁止网络的临时 sandbox 测试；没有 SSH 到生产、没有在 devops 启动新采样，也没有查询生产 API。无生产配置变更、发布、rollout 或 push。

交付了可执行 one-shot `infra/observability/bounded-sampler/sampler.py`、独立离线 supervisor `runner.py`、时间/预算契约 `contract.py`、43项测试和 README。尚未启用生产传输或在线调度。**42 PASS / 1 SKIP 不等于 Linux 原生及生产开销通过。**

## 1. 原采样器开销：有证据与 UNKNOWN

来源为上一轮不可修改的 `../devops-resource-observation/{sample-00,observation-receipt,historical-metrics}.json` 及采集源码。结构化明细 `original-overhead-analysis.json`。

| 项目 | 实际可证事实 | 不可声称 |
|---|---|---|
| 总观察 wall | 6.521004s，Host/Guest 并行 | 不能当作 CPU 消耗 |
| Guest wall / combined CPU | 6.266488s / 1.032895 CPU-s | self/child 单独 CPU 未记录 |
| Host wall / reported CPU | 4.274396s / 1.222684 CPU-s | 统计是 process-wide，和并行 SSH/其他线程计量有重叠可能，不能当作严格独立 Host 线程成本 |
| 最大 RSS | UNKNOWN | 没有原始峰值记录，不补估计 |
| Guest 外部命令 | 源码路径可确认 ps2、vmstat1、kubectl3，共6次 | 不知道各命令耗时和 CPU 排名 |
| Host 外部命令 | sysctl1、vm_stat2、ps3（含QEMU args读取）、top1，共7次 | 不知道各命令耗时和 CPU 排名 |
| Guest PID CPU delta 窗口 | 2.006550s，围绕 vmstat 调用计时 | 不是所有命令的独立计时 |
| SSH 连接/远程等待 | UNKNOWN | 不能用总 wall 减 Guest wall 当作 SSH 时间 |
| Kubernetes API / HTTP | UNKNOWN 分项耗时 | 不指定 API 为最慢命令 |
| 输出序列化/写入 | UNKNOWN | 未做原始计时 |
| Prometheus 历史批次 | 11:40:59.328488–11:40:59.386921，0.058433s（远端原始批次时间） | 它在采样结束以后，不计入6.521s；逐query延迟、批次外SSH等待仍UNKNOWN |

所以 `ORIGINAL_SAMPLER_OVERHEAD_ROOT_CAUSE=UNKNOWN`。可从代码识别优化方向：删除全进程/线程 ps、删除外部命令、分离 Kube/HTTP/历史查询、使用每个 owned child 的 wait4，不凭直觉认定某条命令是超预算主因。

## 2. 最小 Guest / Host 实现

Guest 直接读取6个固定系统指标文件、最多8个预选PID的 stat/cgroup；没有 `/proc` 枚举、线程扫描、外部命令、网络、Docker socket、Kubernetes凭据或root依赖。每个文件16KiB上限，各级路径 O_NOFOLLOW，非正规文件拒绝，缺失/权限拒绝/解析失败/PID消失或复用均失败，不填零。进程CPU按各自读窗口及start identity求差；只提取PodUID，不输出cgroup路径。

Host 使用本机 SDK 可核对的 libSystem/libproc：逐CPU `host_processor_info`、`host_statistics(HOST_VM_INFO)`、只读sysctl、`proc_pid_rusage`；最多8个指定PID，返回QEMU/SELECTED_PROCESS类别，不导出进程路径/argv/environ/用户名。Mach port和VM返回缓冲释放。Host CPU利用率与Guest CPU PSI分别记录，不比较两个百分比就断言因果。

不自动发现QEMU或全局top进程；有限候选集可能漏掉真正触发进程。未来须单独核实VM/PID/start identity和候选集，不能使用历史PID当作当前事实。本轮Darwin测试仅使用测试进程自身，未刷新QEMU现场信息。

## 3. 实际测试环境与数据

Darwin 27.2.0、arm64、10 CPU、32GiB、Python3.13.13、UID501，非root。测试是**本机 OS sandbox 内的非生产临时进程**：禁止网络、只有独立临时树可写；仍与devops VM共享物理Mac，不能当作独占机器。先读取少量原生聚合计数，free+inactive超过512MiB、load1低于2/CPU才进入测试；每次最多两个64MiB预算worker，无CPU/memory压力生成，无测试工具安装。真实 admission 原值见 attempt*-preflight.json，不把 inactive 当作保证可分配内存。

最后一次 attempt4 全套：**43项 = 42 PASS + 1 SKIP，0 FAIL/ERROR，总wall 5.947348s**。测试性能是离线短序列，不模拟真实120秒生产采样间隔，不拿它冒充10分钟观察。

| 最后一次实测 | 数量 | worker wall 中位 / 最大 | lifetime CPU 中位 / 最大 | 最大RSS | 最大stdout |
|---|---:|---:|---:|---:|---:|
| Guest `/proc` fixture执行 | 12个独立worker | 0.26214 / 0.26784s | 0.04496 / 0.04760s | 20.03MiB | 2524B |
| Darwin 原生自身PID | 6个独立worker | 0.26359 / 0.27425s | 0.04567 / 0.05057s | 20.05MiB | 2659B |
| 受控失败路径 | 多种独立worker | 最大2.57553s（含启动及2.5s闹钟） | 最大0.05057s | 约19.98MiB | 保留最大1024B（小cap测试） |

supervisor单次CPU实测最大0.02311s。每个collector外部命令0；supervisor每对启动2个Python进程。spawn耗时、逐样本分布（min/median/p95/max）、failure成本、RSS、输出字节与reaped状态均见 `performance-analysis.json` 和 `attempt4-tests.json`。wait4按确切PID计量，CPU包含解释器启动；不混用Host线程累计子进程计量。worker wall为parent侧保守总窗口，不是纯系统调用耗时。

分类明确：

- **离线真实运行**：Darwin原生只读接口、独立Python子进程的timeout/TERM忽略/KILL/reap、真实受限文件权限、流输出截断、真实本地时钟握手。
- **使用合成输入的真实执行**：Guest fixture上的文件读取/解析/CLI，含缺指标、坏指标、PID缺失、symlink/FIFO、脱敏；不是Linux原生运行，更不是生产采样。
- **合成unit/契约测试**：PID复用、clock offset/step/uncertainty、120s调度虚拟时钟、Host headroom规则、SSH argv静态检查。
- **静态验证**：collector无subprocess/socket/遍历/kill/fork，固定文件与PID/字节上限。
- **未测试**：非生产Linux原生`/proc`（唯一SKIP）、真实SSH连接超时/不可达、真实远端断连清理、真实Host/Guest同步精度、生产开销。

SSH timeout/exit255、本地Host worker退出只用隔离Python进程模拟传输故障结果，验证父进程停/清理契约；不冒充实际SSH或网络验证。

保留全部尝试：attempt1为Host CPU_WINDOW_EMPTY真失败；原host_statistics接口在200ms内未返回变化，不能据此输出0利用率。改为host_processor_info后attempt2为38PASS/1SKIP；未增加窗口或预算。attempt3新增测试引号错误导致SyntaxError，未执行测试；原始错误保留。修正后attempt4为42PASS/1SKIP。测试尝试编号增加只为保留失败记录，不改变任何执行预算。所有临时树已清理，测得的owned workers全数wait4回收。

## 4. 时间协议与执行/停止契约

完整可执行规则见 `contract.py` 和源码README。每侧记录UTC epoch ns、ISO毫秒、UTC offset0、本地timezone offset、单机monotonic起止和时长。不同机器monotonic绝不互减；UTC相近不等于同步或因果。

H0=Host send，G1=Guest receive，G2=Guest send，H3=Host receive。Guest-minus-Host offset区间 `[G2-H3, G1-H0]`；midpoint仅估计，半区间为不确定度。不要求网络对称，把传输和启动纳入不确定区间。每机UTC duration与其monotonic duration偏差>20ms、负区间或半宽>500ms即停止。时钟同步状态保持UNKNOWN；本轮未查生产NTP/chrony/systemd时间状态，后续需最小只读核实。未观察到的时钟跳变/漂移仍是方法局限。

Guest映射到Host时间为 `[Gstart-offsetUpper, Gend-offsetLower]`；只认“扩大不确定度后的窗口重叠”，不宣布因果。每次采样使用新的时间包络，不拿初始offset外推10分钟。离线真实本地进程握手已通过，真实Host/Guest精度尚未测试。

未来流程：Preflight → 两侧独立Readiness → clock-only握手 → 有界采样 → 独立回执 → 时间窗join → 关联分析 → cleanup → 分离的Final Health。时钟/Readiness/健康检查必须算入同一个总deadline，不能预算外再开循环。当前collector不访问Kubernetes；该阶段未来需要已授权的有限历史查询/只读健康入口。

| 下一次计划上界 | 值 / 执行方式 |
|---|---|
| 次数/间隔/总时长 | code cap6次，间隔至少120s，总620s；下一次首次验证建议只批准1对样本，不自动使用6次 |
| 每侧wall | collector2.5s SIGALRM（不含解释器启动）；parent/transport4s（含启动），任一超时停止，不重试 |
| CPU | worker lifetime最多0.25s，getrusage/wait4审计，超过即失败且禁止下一样本 |
| RSS | worker峰值64MiB审计，超过失败；这是诊断stop规则，不是cgroup强制内存配额 |
| 输入/输出 | 每file16KiB、每侧stdout32KiB、stderr最多2KiB且只保存字节计数、session payload512KiB |
| 进程 | 每侧最多8个目标PID，collector不派生；local最多2个worker；未来SSH远端固定shell/Python最多2个，尚未实测，不允许其他helper/代理/持久连接 |
| 终止 | owned local child TERM→100ms后KILL→500ms内reap；未完全回收FAIL。非通用后代隔离证明，真实远端仍未测试 |
| Guest压力停止 | load1≥8/vCPU、CPU PSI some avg10≥70%、memory some≥20%、I/O full≥30%，先读廉价指标，超限不读PID；窗口后再查 |
| Host停止 | load1≥2/CPU，或free+inactive<512MiB；只读raw压力enum，不推断Guest压力 |
| 错误 | 未知指标/身份、解析、权限、断连、超时、clock不确定、输出/开销超限、任一peer失败，fail-closed，不启动下一样本 |

旧每侧1CPU-s、15/20s wall及30min上限均未放宽；新CPU/wall/总时长更紧。离线CPU/RSS是本机数据，不保证生产Linux达标。`runner.py`没有生产SSH入口且明确拒绝ssh命令；`ssh_argv`只构造未来严格校验参数，不会执行。没有在线授权文件、没有自动恢复路径、没有常驻任务。

## 5. 下次证据集合与尚缺条件

正常基线只证明开销/参考区间，不能识别历史故障始发PID。自然故障时需要同时间runnable/PSI/selected-PID CPU和Host/QEMU counters，再关联已有Node/Pod Ready、restart、Traefik5xx。历史Prometheus/Loki只读查询是独立有界阶段；不得把它塞回每次采样。已严重不可用时停止新增采样，不主动制造故障。

缺口：未选定并验证可用的非生产Linux执行上下文；真实Linux权限、原生计数、RSS/CPU、独立timeout仍未验；真实SSH丢连接的远端清理未证；真实时钟同步未知；固定PID候选可能漏掉触发进程；源身份仅label，VM/PID映射需另核实。生产root cause仍UNDETERMINED，Mac/QEMU/Loki关联UNKNOWN。本轮没有使Runtime14/16变成16/16。

**下一步唯一建议：先选定现有且获准的非生产Linux上下文，完成原生collector/权限/生命周期验收；不以devops生产节点替代。** 不申请新增服务器、磁盘或高权限agent。

未来在线验证需另行明确授权清单：

1. 指定主机/普通用户/可信host-key/只读入口及短维护观察时间，不关闭hostkey校验、不sudo、不加生产权限。
2. 明确源码hash、source ID、QEMU与Guest候选PID/start identity及最多8个目标，授权读取这些PID的有限计数。
3. 先完成非生产Linux和严格SSH timeout/断连清理验证，再审查生产传输；不因本轮本地cleanup通过就启用。
4. 首轮只批准1对正常基线，接受本报告更紧预算和任何失败立即停止；不得自动连续6次或反复放宽预算。
5. 授权独立的最小前后健康查询、现有时钟同步只读状态及新证据目录；不含发布、扫描或配置修改。

## 6. 边界、提交与验收

本轮先执行真实Evidence Write Boundary Preflight：新canary覆盖/删除/chmod均被OS sandbox拒绝；只允许临时树写入，禁止网络，未对历史文件探测写操作。保护上一轮13,931个文件及其22个新证据文件，合计13,953，逐个比对SHA/size/mode/uid/gid/mtime/ctime/inode/symlink及历史evidence文件集合。测试只运行临时副本，结果由父进程以exclusive create输出本轮目录，未运行已知会覆盖重放结果的旧回归入口。

最终核验见 `verification.json` 与 `seal.json`。原13,931文件保护要求继续满足；历史内容/元数据未再受损不等于修复原始完整性失败，`ORIGINAL_EVIDENCE_INTEGRITY=FAILED`保持。没有重验整个Security Manager；Candidate VERIFIED/Production NOT_ACTIVE沿用权威基线，不表示本轮做了新生产验证。

本轮不新增生产健康查询，最后可引用健康仍为上一轮11:37:48快照；不把它描述为本轮完成时实时健康。变更仅新增本目录和`infra/observability/bounded-sampler/`。可停用方式是继续不调用独立collector（没有安装服务或调度入口）；如需撤销源码提交，对本轮新增路径做独立revert并保留封存证据，不删除历史报告，无生产回滚操作。

结构化最终状态见 `verdict.json`：Guest实现和全平台隔离性能因Linux原生缺口为INCOMPLETE；Host实现/离线契约、输出/timeout/local cleanup验证通过；production overhead及real Host/Guest capture均NOT_TESTED。已满足本轮离线源码、测试、预算和执行准备交付；不满足生产启动条件。完成后STOP。
