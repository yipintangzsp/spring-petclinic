# 临时 Gitleaks Agent：可执行配置候选，尚未批准实施

本目录仅用于离线评审。没有导入 Job/Node、创建 Pod/SA/Secret/NetworkPolicy、构建镜像或运行 CI。
原禁用 Job、Manager、Runner、Policy、生产 Jenkinsfile 均未修改。候选 YAML 是合法 YAML 1.2 的 JSON 子集。
`rendered/pod.candidate.yaml` 故意保留不合法的最终镜像摘要占位符，避免被误当成可部署清单。
`plan.mjs` 是离线契约校验器，不是 Kubernetes admission engine、运行时 guard 或 provisioner。

## 真实发现与选型

基线 `5ec44c31`，未 push。Jenkins 2.568.1 在 K3s `ns-devops`，Controller Pod 是原生 ARM64。
只有一个 built-in executor，UID/GID=1000，附加组988，可访问 rootful Docker；本轮不改变它。
Kubernetes plugin 未安装，clouds 为空。实际线上也没有 `security-manager-v2-gitleaks-validation` Job；
此前“创建”的是本地禁用定义，不能当作已导入的 Jenkins Job。

选择 **现有 Jenkins core Inbound Agent + 人工受信 provisioner + 单次临时 Pod**。
不需要安装 Kubernetes plugin，不向 Agent 分发 Kubernetes 管理凭据。
Controller Service 是 `jenkins.ns-devops.svc.cluster.local:8080`，配置的 TCP Agent listener 为50000。
优先复用8080上的 WebSocket，不新增入口、端口、NodePort 或代理依赖。原 Jenkins URL 仍为
`http://jenkins.devops.local/`，不改全局 URL。只读取得 remoting JAR 200，固定 SHA 见 image lock；
`/wsagents/` 未带认证握手头返回400，仅证明处理路径存在，不是 Agent 成功连接。
实际 WebSocket 支持布尔值另见最终只读盘点；尚未执行握手或 Agent 注册。

技术路线可行，不代表当前全部实施条件就绪。SSH Agent plugin 虽已安装，也不新增 SSH daemon/主机账号。
不安装插件、不复用 built-in、不创建长期节点或 Deployment/DaemonSet。

## 七个实施前闸门

| 闸门 | 本轮结论 | 必须补齐的事实 |
|---|---|---|
| CAPABILITY | READY（规划层） | 已有 Java21/Node20、Inbound/WebSocket入口；真实连接留下一轮 |
| IDENTITY | NOT_READY | Pod 专用身份与现有 CI entry 的严格 systemd cgroup 检查不兼容 |
| RESOURCE | NOT_READY | 当前有容量，但最终组合镜像的解包/日志峰值与真实 Agent JVM峰值未知 |
| NETWORK | NOT_READY | 需新增目标 Pod 专用 egress 规则；还未获准应用及真实负向连通性测试 |
| IMAGE | NOT_READY | 只有独立已缓存 ARM64输入，无最终可信 Agent image digest |
| CLEANUP | READY（契约层） | 有定向清理、超时及失败恢复方案，真实删除验证仍 NOT_TESTED |
| JOB_BINDING | NOT_READY | 要离线评审 Pod backend、新 release manifest 和每次构建绑定，然后才可导入禁用 Job |

七闸门并未全通过，不得提出现在启动真实 Agent 或运行 Gitleaks CI。

## 配置与身份边界

候选 namespace 使用现有 `devsecops-execution`，不新建 namespace。
专用 SA `gitleaks-validation-agent`，`automountServiceAccountToken=false`，没有 Role、ClusterRole、
RoleBinding、ClusterRoleBinding。当前没有创建这个 SA。运行身份与 SA 是两种不同身份。
UID/GID24001是**候选**：当前宿主无该账号/进程，实际基础镜像passwd也无此UID，已观察 Node/Git/Java 是 root拥有、0755可读执行；
旧镜像的 `jenkins` UID1000 与65534均不用于新 Agent。最终镜像 passwd、所有权及24001实际启动仍需核验。
`supplementalGroupsPolicy=Strict`，仅自身 fsGroup24001，无 Docker组、host root、权限提升和额外 capability。
只读根文件系统，RuntimeDefault seccomp；没有 hostPath/PVC、hostPID/Network/IPC、共享进程 namespace。
没有其他 init/debug/sidecar 容器，不用多个容器冒充权限隔离。

一个容器内 Remoting 与可信 Manager 使用相同 UID，**不是彼此的安全边界**。
被扫源码只作为被动文件数据读取，不执行其脚本、Git hooks、Jenkinsfile、构建命令、Node import 或配置文件。
原生 Gitleaks、Manager、Policy和Router来自只读、root-owned、固定清单的镜像层。
普通项目代码不能写 Manager 路径；工作区挂载不覆盖 /opt 或输入目录。
若需要执行不可信项目程序，该单容器方案不适用，必须另行评审隔离架构。

Agent只持有绑定一个临时 Node 的 remoting secret，不持有 Jenkins管理员、Harbor、GitOps、age、签名凭据或API token。
只读RBAC盘点未发现该候选SA或namespace-wide SA组继承业务资源权限；仍会继承系统默认discovery/basic-user等权限。
这不等于“API零权限”，而且没有真实SA/token，真实认证与can-i验证仍未执行。
remoting secret存于一次性 Secret只读挂载 `/agent-auth/secret`，不出现在命令行明文、环境变量、工作区或归档。
其非生产 Node凭据也属于敏感数据；结束必须删除Secret和Node注册，不能声称Agent完全“无凭据”。Jenkins该版本Node Secret无独立TTL，按Node名派生；同名重建不是轮换。参见下方本轮补充。
当前 Controller 的 docker/root等效权限和全局授权遗留问题保持未解决，独立 Pod不等于Controller整体整改完成。

## 两个需要先适配的真实代码阻塞

1. `infra/security/manager-v2/ci/entry.mjs` 的 `inspectIdentity` 只承认
   `/system.slice/security-manager-v2-validation-*.service` cgroup，并扫描宿主 `/proc`。
   Kubernetes Pod实际cgroup/可见PID namespace不同，不能删除检查或用环境变量伪造验证。
   下一轮先增加**独立Pod身份backend**，保留旧systemdbackend；使用可信管理端绑定的Pod UID、runId、
   image digest、SA、安全上下文和node身份，与容器内UID/groups/NoNewPrivs/CapEff、mountinfo实测核对。
   Downward API/`NODE_NAME`/Agent自报不能独立当作可信证明。缺管理端证据必须拒绝。
2. `gitleaks-real.mjs` 当前要求root-owned普通approval文件、root-owned且不可写的source domain、
   原始inode/device身份，以及同一domain下 **执行UID拥有** 的outputs目录。
   fsGroup只改变组权限，不能把root拥有的emptyDir变成UID24001拥有；ConfigMap/Secret投射也存在符号链接语义。
   因此不能简单把投射volume当作旧guard已通过，不能用root init/hostPath/chmod放宽来绕过。
   需要评审Pod专用不可变输入批准契约：受信镜像根层中的源码/工具摘要与管理端签名的run绑定，
   `/work/private`中执行UID拥有的输出目录，真实只读挂载证明及扫描前后内容验证。
   此适配只改变执行/文件身份的证明来源，不改原Finding、严重度、原Gate分类或单次Policy求值。

上述两项本轮仅形成明确适配要求，**没有修改/替换原entry或Runner**。
只生成Pod YAML不足以解除它们，所以没有启用或更新现有 Job。

## 镜像、可信交付与架构

`image-lock.candidate.json` 固定实际缓存的 Jenkins Java21/Node20基础镜像、Gitleaks8.30.1工具镜像和
Controller提供的agent.jar SHA256。两镜像都只确认 linux/arm64，不能外推为amd64可用。
没有现成组合镜像。`Dockerfile.candidate`只作构建输入评审，不在本轮构建或推送。
以后由可信operator从已验证来源离线准备 `image-inputs/`，包含完整文件白名单与SHA、原Manager包、
经评审的新增Pod backend、固定Gitleaks二进制、agent.jar及非生产被动fixture。
不能由fixture仓库生成这份输入或SHA清单；必须先独立核验白名单、无额外文件/链接、无生产secret。
最终组合镜像产出后固定其真实digest，再核验root所有权/只读输入/工具版本/架构/大小。
当前缺输入树及最终digest，绝不能填写看似真实的假digest。

Pod采用 `imagePullPolicy=Never`，不会启动时访问不稳定外网；授权执行前在候选节点确认精确digest已缓存。
required nodeAffinity仅允许Linux/ARM64，依据是实际工具锁，不是随意偏好某个节点。
没有nodeSelector/nodeName/toleration；现有cloud污点保留，当前只能调度到devops。
未来要上amd64，必须先验证实际工具和最终镜像的amd64内容，不能用QEMU或改原工具锁绕过。

## 资源与目录预算

| 项目 | 候选值 | 依据与限制 |
|---|---|---|
| CPU request/limit | 250m / 1 | 正好在现有security-budget范围内；只允许一个Agent |
| 内存 request/limit | 512Mi / 768Mi | 现有quota上限，不降低业务request，不承诺未实测的Agent峰值 |
| ephemeral request/limit | 128Mi / 256Mi | 日志等节点临时存储计量/驱逐阈值，**不是强制文件系统quota** |
| work emptyDir | Memory / 128Mi | HOME、Remoting cache、Jenkins work、Candidate报告，仅临时数据 |
| tmp emptyDir | Memory / 32Mi | Java/Node/Gitleaks临时路径；这160MiB计入Pod内存上限 |
| deadline/grace | 600s / 30s | 不无限重连，异常有明确上限；Never重启、Never抢占 |

JVM heap192Mi、metaspace96Mi、direct32Mi、codecache48Mi，Node heap128Mi，Gitleaks原有GOMEMLIMIT128Mi不变。
这些是各自上界/目标，**不能机械相加当作精确RSS**；JVM堆外、线程、Go运行时和tmpfs还需真实采样。
OOM/资源上限触发只能判验证失败，不能重试扩大quota。单次原生报告上限仍为原Runner的1MiB。

基线devops：CPU allocatable6，已请求4.055；Memory allocatable约21.44GiB，已请求14.66GiB，
实际memory.available约4.76GiB；nodefs可用约42.54GiB。CPU PSI存在，Ready不等于无压力。
aliyun实际内存余量约726MiB，ucloud约1.62GiB，且两者均有NoSchedule污点，均不纳入默认候选。
最终镜像解包和日志峰值未知，资源状态仍NOT_READY；不能把tmpfs sizeLimit或监控当作完整磁盘预算证明。
不改Trivy的45.78GiB hard floor，不碰DB，也不把本Agent预算当作Trivy刷新许可。

## 网络边界

现有 `scanner-deny-network` 已覆盖execution namespace；k3s网络策略链可见，未禁用NetworkPolicy。
候选 `networkpolicy.candidate.yaml` 只选择本Agent标签，允许到ns-devops/app=jenkins:8080和
kube-system/kube-dns:53 TCP/UDP。没有GitLab、Harbor、Internet、proxy、API server显式允许规则。
Fixture与可信Manager均从离线受审计镜像层交付，不需要Git凭据或在线checkout。
不修改原deny规则，不给ZAP标签，避免命中现有到PetClinic的额外allow规则。NetworkPolicy规则按并集合成。

策略不按URL或单个容器隔离，也不等于TLS或认证；Agent到Controller同Pod8080的其他URL仍可达。
继承现有内部HTTP路径，本轮不修改Jenkins认证/TLS。remoting secret传输安全与API面限制属于实施评审项。
Kubernetes NetworkPolicy对本节点流量和Service DNAT有实现限制；尤其devops上有API server，
**不声称一份YAML就能证明API端点全部不可达**。后续真实Pod必须逐项验证DNS、WebSocket及
拒绝Harbor/GitLab/外网/代理/API的ClusterIP、nodeIP、podIP路径；无法证明则NETWORK_BOUNDARY=INCOMPLETE。
即使API网络仍可达，无API token/RBAC也必须验证匿名请求没有权限；不能把认证拒绝冒充网络隔离。

## Job绑定、启动与身份验收（以后另行授权）

`node.candidate.xml`：每轮唯一且永不复用的物理Node名、固定逻辑label、一个executor、EXCLUSIVE、独立/work/jenkins，WebSocket launcher。
run标签从可信Job整数BUILD_NUMBER产生，不允许用户指定label、shell、路径或镜像。
`job-binding.plan.json`列出对原禁用Job的最小改动：stage label改为
`gitleaks-validation-restricted && security-run-${BUILD_NUMBER}`，其余参数白名单、可信入口、非发布限制保留。
Manager版本升级必须重新生成和审查完整manifest/hash；不手改旧manifest来“通过”。
Agent不存在时父流水线8分钟超时失败，不回退built-in；identity/provision失败直接FAIL/NOT_READY。
不能仅用label/EXCLUSIVE当作跨Job授权隔离；未来受信provisioner必须校验Node、Pod UID和固定job/build归属，
核实当前队列、其他Job配置权限与Controller Agent-to-Controller保护。现有FullControlOnceLoggedIn仍是阻塞，不声称已限制其他Job。未经审核的Job不得借用该Agent。

未来顺序：

1. 全部规划前置条件（含Fixture批准）通过后，取得创建单次Node/SA/Secret/Pod/目标NetworkPolicy及清理的专项批准。
2. 重新只读采样，确认quota空闲、无生产发布冲突、所有受保护digest/summary不变，镜像已本地缓存。
3. 应用无权限SA、仅Agent专用网络规则；注册唯一EXCLUSIVE Node，绑定固定job/build/runId，安全注入仅该Node的secret。
4. 创建一个Pod，记录UID，验证真实UID/GID/groups、NoNewPrivs、capabilities、seccomp、只读mount、无socket/API token。
   可信管理端从API和runtime核对，不仅使用Agent自报。错误身份、未知mount/资源/网络状态均拒绝扫描。
5. 先完成真实Agent身份、文件系统、网络、生命周期与负例；不因Pod Running就运行CI。
6. 只有身份隔离真实验收后，另按已批准契约启用一次验证Job，固定可信Manager、被动fixture、Capability Check、
   Gitleaks执行、单次Policy、Candidate artifact、离线Router，归档只限redacted evidence，不能归档源码或secret。
7. Job finally归档校验并清理/work；管理端独立校验seal、runId、结果及底层资源删除。

## 终止、Controller失联和回滚

禁止全局kill、批量删Pod、删namespace、force-delete作为清理证明。
正常路径：停止派新任务→断开该Node→按namespace/name/**UID precondition**正常删除唯一Pod→
观察Pod消失且runtime进程不存在→删除仅该run的secret/Node注册→清理本run离线fixture→核对归档seal。
最后一个run结束且无任何使用者时，才删除新建的专用SA和新增专用allow NetworkPolicy；不动原scanner-deny规则。

Controller失联：`-noReconnect`限制连接断开后的重连；Pod activeDeadlineSeconds600和kubelet终止提供独立上界。
若初始连接挂起，deadline也必须收尾。timeout/SIGTERM忽略/多级后代由runtime终止整个容器域，
**具体行为留到真实负例验证**，不能因写了tini或deadline宣称VERIFIED。
若节点/kubelet失联，deadline不保证在墙钟600秒内停止进程；保留CLEANUP_INCOMPLETE，锁住后续run，
管理端确认进程已停止或节点可靠隔离前不得再执行；物理Node名在任何情况下永久禁止复用，不得用API force delete伪造清理。

`validateCleanup`只校验来自可信管理端的定向receipt契约；synthetic PASS不等于真实删除证明。
清理必须保留任何Pod删除失败、remoting Node残留或工作区残留的原始错误，不被finally成功覆盖。

本轮回滚：仅停用/撤回本目录未部署候选；无线上资源需要删除或服务需要重启。
将来实施失败：先禁用新增验证Job、定向销毁本run；恢复修改前的该Job定义，不改生产petclinic-ci或Controller全局配置。

## 离线测试、真实未验项与下一步

运行：

```sh
node --test infra/jenkins/gitleaks-validation/ephemeral-agent/plan.test.mjs
node --test infra/security/manager-v2/ci/contract.test.mjs infra/security/manager-v2/*.test.mjs
```

测试覆盖root/65534/docker组/socket/privileged/hostPath/host namespaces/token/capability/镜像摘要/
Manager身份/路径穿越/链接/未知参数/错误label/资源与网络条件缺失/清理失败/built-in fallback。
这些全部是STATIC_CONTRACT或SYNTHETIC_UNIT_ONLY。真实Pod身份、mount只读写入拒绝、网络阻断、
后代清理、admission、镜像拉取、工作目录启动、WebSocket握手和真实CI均NOT_TESTED/SKIPPED。

唯一下一步允许方向：**离线补齐Pod身份和fixture批准适配设计与可信镜像输入，重审七闸门**。
目前不允许创建Agent；不得把本轮静态测试作为创建许可。
实际创建/启动/删除SA、临时remoting Secret、NetworkPolicy、Jenkins Node与Pod、镜像构建/分发、
导入/启用Job、运行真实CI，都需要相应独立授权，本轮未申请或实施。

原始历史证据 `ORIGINAL_EVIDENCE_INTEGRITY=FAILED` 保留，Runtime14/16不变。

参考：[Jenkins Controller Isolation](https://www.jenkins.io/doc/book/security/controller-isolation/)、
[Jenkins Agent/WebSocket端口](https://www.jenkins.io/doc/book/security/services/)、
[NetworkPolicy限制](https://kubernetes.io/docs/concepts/services-networking/network-policies/)、
[临时存储计量与驱逐](https://kubernetes.io/docs/concepts/storage/ephemeral-storage/)。


## 2026-11-04 定向收口（当前权威补充）

本轮证据与完整执行清单：[readiness closure](../../../../evidence/2026-11-04/gitleaks-agent-readiness-closure/REPORT.md)。
历史证据不重写；a7379f13候选按Git历史字节验证，本目录是用户批准的候选演进。

- `identity-boundary.plan.json`分别列Linux24001、无Token SA、一次性Inbound Node、Node连接凭据、Controller管理身份。
  Jenkins2.568.1真实只读反射确认addNode/removeNode/JNLPLauncher/WebSocket可用，**没有调用凭据getter或任何mutator**。
  Node名格式为`gitleaks-v2-<build>-<管理端96-bit随机nonce>`；固定label保留。
  Jenkins Secret由全局密钥与Node名派生，非原生短TTL。删除Node仅在该身份不存在时拒绝认证，必须永久不复用名称；
  未来以非敏感tombstone登记，真实断连/删除后拒绝重连仍NOT_TESTED。不更改全局SLAVE_SECRET。
- `fixture-contract.json`固定java-fixture/java-web、clean/secret两份被动文本、逐文件SHA及contentDigest、无Git history、
  原Gate/Policy预期PASS/PASS和FAIL/FAIL。假token只由可信候选generator生成，从未向服务申请/使用；不归档明文。
  两份CI审批均PENDING_APPROVAL，授权主体/引用为null；单元测试里的APPROVED仅合成结构测试，**不是实际批准**。
- `readiness-contract.mjs`仅验证离线契约结构，明确`runtimeAuthorization:false`；`authorizeRuntime()`永远拒绝执行。
  不提供Pod backend，不更改原entry/Runner/Policy；唯一物理Node名目前会被冻结CI固定Node校验拒绝，不能伪造NODE_NAME。
- PID：实际kubelet podPidsLimit=-1。已存在的util-linux2.41提供prlimit；候选命令增加继承`RLIMIT_NPROC=128:128`及`CORE=0`。
  这是**每real UID含线程的限制，不是Pod cgroup pids.max**；专用UID、无CAP/NoNewPrivs必需，Java/Node/Go组合线程峰值未验证。
  本轮未执行该包装器/未创建Pod，不宣称PID/生命周期验收通过。不修改kubelet。
- 资源：只重新采样devops。基础quota允许单Agent，requests250m/512Mi、limits1/768Mi不变。
  tmpfs160Mi计入内存；临时存储128/256Mi是计量/驱逐限制，非强制quota。最终镜像/解包/线程/内存峰值仍未知。
- 工具：已读现有Controller内Java21.0.11、Node20.19.2、Git2.47.3、tini0.19.0、prlimit2.41、CA包版本/文件SHA/许可记录。
  公共agent.jar为3355.v388858a_47b_33，SHA与前轮一致。Gitleaks二进制出处是**HISTORICAL_ARCHIVE**，不是本轮扫描。
  组合镜像没有构建，无最终digest；amd64仍NOT_VERIFIED，不改ARM64约束。完整依赖闭包及最终镜像许可清单待构建输入审核。
- 网络：`network-boundary.plan.json`记录真实Service与/wsagents/路径。当前HTTP/WS，无TLS，不能声称证书已验证。
  Jenkins Ingress也无tls配置。需另行评审可信加密路径，不允许在本轮修改全局TLS/代理。
  可见17条KUBE-NWPLCY链不等于Agent数据面隔离通过；API/metadata/同节点流量及DNS负例全部NOT_TESTED。

本轮未构建镜像/创建任何线上资源/启用Job。下一步只能继续离线收口Pod身份和输入批准backend、受信传输及镜像输入清单；
相关变更需单独评审。真实创建与运行仍须后续专项批准，不能凭本目录的静态通过执行CI。
