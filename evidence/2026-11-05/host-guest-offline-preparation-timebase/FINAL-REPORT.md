# 本轮最终权威报告：低开销采样器离线准备

基线879db238。本报告及本目录verdict.json是本轮最终结论，补充并纠正兄弟目录`host-guest-offline-preparation/REPORT.md`。先前报告、seal、源码和所有失败结果均保留，未覆盖历史证据。无需生产回滚：本轮没有连接devops、没有生产采样、没有服务/配置修改、发布、rollout或push。

## 交付与发现

交付实际可执行Guest/Host采样器、独立本地supervisor、预算及UTC/monotonic时间协议、隔离测试及开销记录。当前入口 **`infra/observability/bounded-sampler/sampler_mach_time.py`**；使用说明以该目录CURRENT.md为准。旧sampler.py作为冻结基础实现保留，不单独作为当前Host入口。

原采样器6.521s是并行观察wall，不能称CPU消耗。旧Guest/Host回执只有combined CPU，缺少最大RSS、逐命令/SSH/API/写入耗时；Host计量还使用process-wide统计，不能隔离并行线程/SSH贡献。具体最慢命令仍UNKNOWN，未猜测。原始逐项分析见前目录`original-overhead-analysis.json`：Guest外部命令6次、Host7次（均为源码/执行路径计数），Prometheus批次发生在采样结束后，不算入6.521s。

新Guest直接读6个/proc系统文件与最多8个指定PID，不遍历全部进程/线程，无外部命令或网络/凭据/root依赖；逐级O_NOFOLLOW、16KiB单文件上限、PID身份校验、明确错误退出。Host使用只读原生Mach/sysctl/libproc，不启动ps/top/vm_stat，采样指定PID而非宣称全局top。路径/argv/environ不输出，cgroup只输出PodUID。

## 收口时追加发现的CPU单位问题

原43项测试覆盖“可读取”但没有验证Darwin进程CPU的单位。收口交叉核对发现它远低于getrusage，因而先前Host VERIFIED不能作为最终完整计量证明。本次没有删除或覆盖先前通过结果，也没有使用这些数值做生产归因。

Apple XNU中`fill_task_rusage`把task power counter赋给ri_user_time/ri_system_time；接口来源见[Apple XNU bsd_kern.c](https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/kern/bsd_kern.c)。本机实测需要Mach timebase转换，不能直接把raw counter当纳秒。追加`sampler_mach_time.py`仅修正Darwin后端，保持既有阈值和Linux实现不变。

真实自身进程交叉校验（`native-unit-sanity.json`）：

- timebase numer=125、denom=3。
- 修正前会得到0.007346564s；修正后0.306106833s。
- 同时getrusage前后0.306099–0.306161s，修正值落在该区间内。
- 此处是测试harness累计自身CPU，不是一个collector worker消耗；collector worker预算和性能用独立wait4计量，未被旧单位错误影响。

## 最终测试及性能

在同一Darwin27.2.0 ARM64 / 10CPU / 32GiB / Python3.13.13 / UID501非root Mac上，使用全新**禁止网络、只允许临时树写入的OS sandbox**。它是非生产进程隔离，不是独占物理机；Mac仍承载devops VM。本轮没有生成CPU/内存压力。环境admission原始free+inactive/load检查通过才执行；不将inactive当作保证可分配内存。

最终45项：**44 PASS、1 SKIP、0 FAIL/ERROR，wall5.967416s**。

| 当前入口实测 | 独立worker数 | wall中位/最大 | lifetime CPU中位/最大 | 最大RSS | 最大stdout |
|---|---:|---:|---:|---:|---:|
| Guest合成/proc fixture的真实CLI执行 | 12 | 0.26342/0.27723s | 0.04581/0.05487s | 20.27MiB | 2524B |
| Darwin原生自身PID执行 | 6 | 0.26167/0.26556s | 0.04504/0.04794s | 20.20MiB | 2784B |

受控失败最大wall2.568878s（包括启动和2.5s collector闹钟），逐失败路径CPU/RSS/output及分布见performance-analysis.json。supervisor单次CPU最大0.019741s。Collector子进程/外部命令0；supervisor每对仅启动2个受审计Python worker。全部测得worker已wait4回收，临时目录已清理。

真实离线测试：原生Darwin自身PID、真实本地时钟握手、proc fixture CLI、文件权限拒绝、symlink/FIFO/超量文件、输出cap、timeout、忽略TERM后KILL/reap、peer失败取消、脱敏。合成unit/静态部分：时钟offset/step/不确定性、PID复用、虚拟调度时钟、SSH argv与无外部调用检查。

唯一SKIP：**未选定可用且获准的非生产Linux上下文，原生Linux/proc没有运行**。Guest fixture执行不是Linux原生性能，也不等于生产事实。真实SSH timeout/不可达/断连清理未测试；本地Python睡眠/exit255仅验证父级故障契约，禁止冒充SSH验证。没有触及生产QEMU PID，仅测试自有进程。

## 预算与时间协议

原预算不放宽。当前候选上限：每worker CPU0.25s（含启动，审计超限即关闭session）、RSS64MiB审计、collector wall2.5s、parent/transport wall4s、最多8个PID、单文件16KiB、stdout32KiB、session payload512KiB、最多6次/至少120s间隔、总620s。下一次首次在线验证建议仅1对，不自动使用6次。CPU/RSS是计量后的fail-closed规则，不冒充cgroup硬配额；生产开销未通过。

Guest超load1≥8/vCPU、CPU PSI some avg10≥70%、memory some≥20%、I/O full≥30%时，廉价指标之后、PID之前停止；Host load≥2/CPU或free+inactive<512MiB停止。任一缺失/解析/权限/身份/输出/clock/开销/peer错误立即关闭，不重试。owned local child TERM→100ms KILL→500ms reap；不依赖全局kill，不宣称通用后代隔离或真实远端清理已完成。

每侧独立UTC epoch ns、ISO毫秒、timezone offset、monotonic起止及本机duration。不同机器monotonic不能相减。H0/G1/G2/H3建立Guest-minus-Host UTC偏移区间`[G2-H3,G1-H0]`，不假设网络对称；半宽>500ms、每侧UTC/monotonic duration差>20ms、负时间区间时停止。独立clock-only握手可执行；真实NTP/chrony精度仍UNKNOWN，不拿timer resolution充当精度。每次采样重新取时间包络，未观察到的时钟跳变/漂移仍是限制。

按`[Gstart-offsetUpper,Gend-offsetLower]`映射Guest窗口，重叠仅代表关联候选，不是因果。同步协议和预算代码/细节见前目录报告及源码README，入口修正以CURRENT.md为准。

未来流程已离线实现/测试相应collector、Session和supervisor契约：Preflight→两侧Readiness→Clock Alignment→Bounded Sampling→独立回执→Join→Correlation→Cleanup→独立Final Health。生产driver未启用；runner显式拒绝SSH。readiness/clock/cleanup/final health必须共用总deadline，不另加循环。Kubernetes/Prometheus历史/健康检查留在独立有界阶段，collector不调用API。

正常基线只能建立开销/参考范围；自然故障还需同步关联runnable/PSI/PID/Host/QEMU与既有NodeReady/PodReady/restarts/Traefik5xx。没有主动制造故障，没有宣称找到历史始发进程。ROOT_CAUSE=UNDETERMINED，MAC/QEMU/LOKI关联UNKNOWN保持。

## 证据及生产保护

首先完成旧目录真实Write Boundary Preflight；追加修正再做新canary预检，均无历史写探测，OS sandbox拒绝覆盖/删除/chmod。上一轮13,931文件及22个RCA观察证据=13,953继续保持内容及指定元数据；还保护了本轮先封存的34个文件/源码/manifest，共13,987。继承旧完整manifest及seal hash，追加seal纳入新入口/测试/报告，不覆盖旧记录。

verify.py最终核验SHA、size、mode、uid/gid、mtime/ctime、inode、symlink与历史文件名集合。CURRENT目录新文件是明确追加，不视为旧seal覆盖的原始内容；旧seal的每条已有内容/元数据均保持。本轮不启动旧回归或旧重放入口。

无新生产健康探测；上轮11:37:48健康只是历史快照，不冒充本轮末次实时健康。Security Manager Candidate VERIFIED / Production NOT_ACTIVE为继承权威状态，未运行新的生产验收。Runtime仍14/16，Trivy/Dojo未执行，ORIGINAL_EVIDENCE_INTEGRITY=FAILED保持。

## 尚缺条件与唯一下一步

Guest原生权限/计数/CPU/RSS/timeout、真实SSH断连清理、真实时钟精度及VM/PID映射未验，固定PID候选也可能漏掉触发源。**下一步仅选择现有获准非生产Linux环境，补原生验证及受控SSH生命周期验收；不使用生产devops替代。** 无需新服务器/磁盘，不申请新增权限。

未来在线授权清单：具体主机/普通用户/可信hostkey；固定source hash和最多8个PID/start identity；非生产原生/SSH验收完成后再审查生产transport；仅1对正常基线、更紧预算/立即停止规则；独立新证据目录、最小前后健康/时间状态只读查询。未获得这些条件，不启动生产采样。

停用/回滚：无部署、服务、调度或配置可回滚；不调用候选即可。若撤销本地源码，采用独立revert保留封存证据，不删除历史报告。本轮本地提交后STOP，不push。

最终逐项verdict见本目录verdict.json：旧开销主因UNKNOWN；Guest实现/全平台隔离性能INCOMPLETE；Host修正实现、离线时间/有界执行/输出/timeout/local cleanup VERIFIED；生产开销和真实同步采样NOT_TESTED；未修生产、release0、rollout0。
