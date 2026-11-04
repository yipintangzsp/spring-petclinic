# Ephemeral Gitleaks Agent readiness closure — 2026-11-04

本轮只完成候选演进、离线测试与现有主机/Controller只读检查。不是Agent实施验收。
基线：a7379f138f37974252a91d9ee3448dba6fedd9d1，未push。复用原目录，没有第二套部署配置。
没有创建/删除Pod、Node、SA、RBAC、Secret或NetworkPolicy；没有CI、镜像构建、发布、rollout。

## 身份与真实API能力

| 身份 | 候选/观察 | 未完成条件 |
|---|---|---|
| Linux | UID/GID24001，Strict无额外组，fsGroup24001、NoNewPrivs、dropALL | 基础镜像无该账号，root-owned0755工具可执行不代表组合镜像实际启动成功；HOME、工作目录、线程峰值待验 |
| Kubernetes | 专用gitleaks-validation-agent，无新增RBAC、不自动挂载Token | 尚无真实SA；继承系统discovery不等于业务授权或API零权限；实际can-i未验 |
| Jenkins Node | 独立固定逻辑label，唯一物理名gitleaks-v2-<build>-<96bit random>，EXCLUSIVE/1 | 无真实Node、管理端never-reuse registry/任务归属验证未实现 |
| Node连接凭据 | 仅一次性Secret投射0440，`-secret @/agent-auth/secret`，不进入env、控制台或artifact | 原生无TTL；删除后拒绝重连未实际测试；同UID的可信Manager与Remoting不隔离此凭据 |
| Controller管理身份 | 现有只读管理通道证明具有Create/Configure/Delete/Administer | 不注入Pod、不新增委托权限；当前FullControlOnceLoggedIn不提供项目之间的Node管理隔离 |

`jenkins-before.json`/`jenkins-after.json`记录真实Jenkins2.568.1：无Kubernetes plugin、clouds=0、WebSocket支持；
addNode/removeNode方法、DumbSlave构造器、JNLPLauncher.setWebSocket和getJnlpMac accessor存在。
仅反射检查，**没有创建Node，没有调用getJnlpMac，没有读取连接Secret**。验证Job在线不存在。

[Jenkins该版本源码](https://raw.githubusercontent.com/jenkinsci/jenkins/jenkins-2.568.1/core/src/main/java/hudson/slaves/SlaveComputer.java)
显示Node Secret按Node名从全局密钥派生。不能把它称为短TTL令牌，也不能以同名重建宣称凭据轮换。
候选因此改为每轮唯一物理Node名，用后删除并永久禁止复用；保留固定逻辑label和整数build标签。
Node删除后的认证拒绝是后续必验条件，未做过真实撤销测试，不修改全局密钥。

可支持的未来流程：可信管理端用DumbSlave+JNLPLauncher(WebSocket)注册唯一Node并绑定job/build/run；
仅管理端取得该Node凭据，经私密API流交付exact-run Secret；Pod通过现有Controller服务连接；
管理端校验实际Pod UID和执行身份；固定Job运行；只归档redacted结果；定向清理并记录Node名tombstone。
现有管理员技术能力足够不等于本轮创建许可。唯一所需后续授权范围是**单次精确run的临时资源创建/启动/运行/清理**，
且所有阻塞先关闭；不得把管理员Token交给源码或Agent。

**两个冻结代码阻塞保持：** 原CI entry只承认宿主systemd cgroup且固定NODE_NAME；原Gitleaks输入guard要求
root-owned不可写source/approval和同domain的执行UID私有outputs。Pod身份、唯一物理Node及镜像不可变输入/独立outputs
尚无受审backend。不能伪造NODE_NAME、放宽guard、用fsGroup或投射symlink冒充旧约束通过。
本轮未修改原entry、Runner、Policy或Job。Controller标签/EXCLUSIVE也不构成跨Job授权边界。

## Fixture契约

`fixture-contract.json`由同目录可信generator生成。两个项目用例均绑定java-fixture/java-web：

| 用例 | 来源/扫描 | 预期（未运行） | CI授权 |
|---|---|---|---|
| clean | 固定被动文本；逐文件SHA+聚合contentDigest；目录模式、无Git history | exit0 / Old PASS / Policy PASS | PENDING_APPROVAL，subject/reference=null |
| secret | 明确自行构造、从未向服务申请的非生产测试字符串；不认证、不联网 | exit1 / Old FAIL / Policy FAIL | PENDING_APPROVAL，subject/reference=null |

源码不得提供可执行文件、symlink、.git/.gitleaks配置、Manager/Node/Job命令。manifest最多16文件、每文件64KiB。
需要真实审批同时绑定case/project/contentDigest/Manager manifest；任一变更拒绝。
合成APPROVED仅用于结构单元测试，返回runtimeAuthorization=false，不能作为实际CI批准。
`authorizeRuntime()`始终拒绝，候选模块无provision或scanner客户端。

保留范围：可信generator作为版本化测试代码保留；将来固定非生产输入可随已批准镜像保留，**不声称清理Git/镜像层**。
本run的可写副本、私有报告及工作目录用后删除；归档只含脱敏原生报告/摘要/receipt，禁止明文测试canary或源码。
尚未生成真实运行输入包、审批或执行报告，未验证Gitleaks在本轮输入上的实际命中。

## 镜像与工具

| 组件 | 实际来源/版本 | 证据/限制 |
|---|---|---|
| 基础镜像 | 本地缓存jenkins-custom@sha256:4af1f673…d567，linux/arm64 | 运行中Controller imageID匹配；不是最终Agent |
| Java | Temurin21.0.11+10 | 实际二进制SHA、root权限、GPL/Classpath许可文件摘要 |
| Node | 20.19.2，Debian包20.19.2+dfsg-1+deb13u2 | 实际二进制SHA、包版本、混合许可文件摘要 |
| Git | 2.47.3，Debian1:2.47.3-0+deb13u1 | SHA/包/许可记录 |
| Agent JAR | 3355.v388858a_47b_33，1,407,936 bytes | 公共Controller端点只读取；SHA f8ff1d49076a2ee0d3f8cc60168f43c23c2277c4cbdddaf82a52b2558ad80df5；含LICENSE/NOTICE |
| Gitleaks | 8.30.1，ARM64工具镜像6b2d5224…1815 | 二进制SHA db4d43dd…5647d来自HISTORICAL_ARCHIVE；[上游MIT许可](https://raw.githubusercontent.com/gitleaks/gitleaks/v8.30.1/LICENSE)；本轮未提取或扫描 |
| tini/prlimit | 0.19.0 / util-linux2.41 | 现有可执行文件SHA/许可文件记录；不是包装器运行测试 |
| CA/基础依赖 | ca-certificates20250419，glibc2.41，libssl3.5.6，libstdc++14.2等 | 实际包版本/架构记录；CA bundle SHA 714d457d…a5 |

完整SHA、许可文件路径/摘要、包版本见`image-lock.candidate.json`及`network-tools.json`。
只记录包许可线索，不宣称完成所有第三方依赖的最终再分发许可清单。
Dockerfile无运行时下载、无latest，需可信operator离线准备全白名单输入和清单；最终所有文件/依赖/许可/所有权/架构需整体核验。
**未构建，finalAgentImageDigest=null；最终解包大小未知；amd64 NOT_VERIFIED。** 不占用共享Docker/Harbor存储构建。

## devops资源定向证据

仅资源检查实际候选节点devops（ARM64），其余节点只查询Ready健康。
68个已分配Pod元数据/requests/limits见live快照；有效requests按普通容器、init/sidecar及overhead计算。

| 指标 | 实际观察/候选 |
|---|---|
| allocatable CPU / memory | 6核 / 22,485,788Ki（约21.44GiB） |
| 现有有效requests | 4.055核 / 15,743,320,064 bytes（约14.66GiB） |
| 添加250m/512Mi请求后剩余 | 1.695核 / 6,745,255,936 bytes（约6.28GiB） |
| 后采样可用内存最小值 | 5,207,105,536 bytes（约4.85GiB） |
| 减去Agent完整768Mi limit后的简单余量 | 4,401,799,168 bytes（约4.10GiB）；**不是并发峰值保证** |
| CPU PSI some avg10 | 20.12%、31.33%、34.65%，不能称节点无竞争 |
| Memory/Disk/PIDPressure | 均false；memory PSI avg10为0 |
| nodefs可用最小值 | 45,742,907,392 bytes（约42.60GiB） |
| Namespace quota / LimitRange | 250m/512Mi request、1/768Mi limit、1 Pod，used0；无LimitRange |
| requests/limits候选 | CPU250m/1、memory512Mi/768Mi、ephemeral128Mi/256Mi，原值不变 |
| tmpfs | work128Mi+temp32Mi计入Pod内存；ephemeral limit不是强制FS配额 |
| PID | kubelet podPidsLimit=-1；候选prlimit NPROC128:128、CORE0:0，未实际验证 |

Node限额之和约30.89GiB memory/20核CPU，高于节点容量，不作为额外可用资源。
资源采样跨度约30秒（stats时间13:37:40/50/38:01 UTC），不是组合Agent负载试验；前采样有重复stats时间，未当作趋势证明。
PetClinic三个现有Pod全部在devops；Controller与Harbor等关键负载也在候选节点，本轮不迁移任何业务。
完整分布见live-after.json；quota足够只表示请求可容纳，不是生产余量保证。

[Linux RLIMIT_NPROC](https://man7.org/linux/man-pages/man2/getrlimit.2.html)按real UID计数且包含线程，继承的hard limit
在非root无cap时不可自行提高；不是Pod cgroup pids.max。UID独占、包装器生效及Java/Node/Go线程容量必须真实验证。
容器PID1 tini不在prlimit子树内，不宣称此值是整个Pod含runtime/exec进程的总PID上限。
尚缺Agent峰值、镜像解包/日志/失败清理峰值、实际PID验证，资源NOT_READY。
没有修改kubelet、节点、quota或Trivy45.78GiB hard floor。

## 网络设计与未验项

真实Service为jenkins.ns-devops.svc.cluster.local:8080，ClusterIP10.43.47.83，WebSocket `/wsagents/`。
无握手参数只读请求返回400，仅证明端点响应，**不是Inbound登录通过**。
当前Service和Jenkins Ingress均为HTTP，无tls配置；TLS证书验证无从成立，受信加密传输方案尚缺。
不改Ingress/Controller/代理，不使用跳过证书验证的参数。

候选allow NetworkPolicy只选择目的为gitleaks-validation的Pod，允许精确Jenkins selector8080与kube-dns TCP/UDP53。
原scanner-deny-network保留；不加ZAP标签；fixture及可信输入离线交付，不需GitLab/Harbor/Internet/proxy。
真实k3s未禁用NetworkPolicy，存在17条KUBE-NWPLCY chain；运行时隔离仍NOT_VERIFIED。
[Kubernetes网络策略限制](https://kubernetes.io/docs/concepts/services-networking/network-policies/)包含同节点流量及实现相关路径问题；
这里也不提供URL/L7、DNS内容过滤或TLS。Jenkins同端口其他URL可达，策略是并集合成。
API ClusterIP/nodeIP/podIP、metadata、同节点服务、Harbor/GitLab/Internet拒绝，以及DNS/WS正向均需后续实际Pod验证。
匿名API权限拒绝不能冒充网络阻断。现有证据不足，NETWORK_DESIGN NOT_READY，NETWORK_RUNTIME NOT_VERIFIED。

## 测试与证据保护

- STATIC/FIXTURE：候选158/158、冻结Manager/CI/源锁83/83，合计241/241；干净Git基线+仅候选overlay复现，见clean-checkout.json。
- STATIC/FIXTURE：候选身份/组/mount/Token/命令/label/镜像/架构/资源/网络/审批/摘要/清理负例，见candidate-tests.tap。
- STATIC/FIXTURE：原Manager/CI/源锁回归83项，见manager-regression.tap；没有跑真实scanner或CI。
- REAL：仅SSH严格host key下的现有主机/Controller只读快照、权限与API反射、工具版本及公共JAR、健康检查。
- NOT_TESTED：真实Agent UID启动、Pod admission/PID包装器、网络负例、Node注册/凭据投递/撤销、Job运行、runtime后代终止与清理。
- 已通过的Trivy190/190和完整Docker隔离测试未重跑；本轮未触及其源码。

所有冻结Manager/CI/Runner/Policy及历史evidence按本轮开始hash保护；候选是本轮明确允许变化的目录。
a7379f13候选原bytes与上一轮code-sha256按Git历史验证，不重写旧seal令其适配新候选。
原始历史证据完整性FAILED保留；新round seal不能追认旧证据或增加Runtime数量。

## 下一轮完整执行清单（不是执行授权）

| 项目 | 当前值/后续门槛 |
|---|---|
| 可信执行包 | 先评审Pod身份、唯一Node绑定和不可变fixture/output backend；更新版本化可信manifest与禁用Job，原Gate不变 |
| Fixture | java-fixture/java-web的clean+secret contentDigest已定；实际CI approver/reference缺失，PENDING_APPROVAL |
| 镜像 | 最终ARM64 agent@sha256 **缺失**；输入/许可/依赖/UID/尺寸审核和另批构建/分发；imagePullPolicy Never，精确digest需本地缓存 |
| 节点 | 仅devops候选，需再采样；PID/峰值/存储证明缺失，不许可Pod启动 |
| 网络 | 现有Controller路径已知；可信TLS路径/Controller面隔离方案缺失，另行评审；之后验证DNS/WS和全部拒绝矩阵 |
| 创建对象 | 仅未来批准的专用SA、exact-run Secret、候选allow NP、单Pod及单Jenkins Node；无RBAC/namespace/持久组件新建 |
| Jenkins Node | 真实名称尚缺：管理端由实际build+随机96bit nonce生成，并查never-reuse registry；不是固定label，也不是用户参数 |
| Job | security-manager-v2-gitleaks-validation；在线不存在，disabled候选；只用固定label+本build标签，无built-in fallback |
| Job隔离 | 当前FullControlOnceLoggedIn/共享Controller尚无严格任务授权边界；管理端必须证明仅被批准Job占用，不以新label冒充ACL |
| 管理批准 | 上述blocker关闭后，单次创建/连接/运行/清理专项审批；控制权限留管理端，不注入Pod/源码 |
| 真实先验 | 管理端API/runtime与容器实测联合证明UID/groups/NoNewPrivs/caps、RO/输出所有权、无socket/Token、资源/网络/后代终止 |
| 真实CI | 身份/网络/fixture先通过；然后另批启用一次固定Job，scanner实际报告→原Gate→单次Policy→同resultDigest归档 |
| 归档 | 仅脱敏report与固定metadata whitelist，独立验seal/job/build/run/image/fixture/resultDigest；不归档连接Secret/明文canary |
| 清理 | 停任务/Node offline→封存安全结果→Pod UID precondition grace30正常删除→90秒检查runtime后代→exact Secret UID+Node删除→tombstone与拒绝重连→run副本删除→无人用才移除新SA/allow NP |
| 残留/故障 | Node/Controller失联或清理无法证明则CLEANUP_INCOMPLETE，阻止后续run；无force/no namespace delete/no global kill，名称永不复用 |
| 回滚 | 本轮仅撤回本地候选提交/停止采用，无线上资源需回滚；未来失败仅停新增Job、按UID清理本run、恢复该Job原定义，不改petclinic-ci |

**当前唯一允许方向：继续离线评审上述Pod身份/输入批准/可信传输与镜像输入的最小适配包。不得直接创建Agent或运行CI。**

## 生产保护与结论

前后生产观察完全一致，详见production-comparison.json：#270 SUCCESS、V1 Summary SHA不变、生产Job定义SHA不变；
Argo Synced/Healthy、三节点Ready、PetClinic3/3且快照HTTP200；生产image digest不变；socket0660。
Trivy仅核对DB metadata.json的hash/stat与Pod UID/image/restarts未变，**未全量重读DB字节**；
Dojo仅核对Pod身份/镜像/Ready/restarts，不检查或修改数据库内容。
没有持续负载/HTTP无中断测试，没有宣称未来CI通过。Runtime14/16保持；V2生产未激活。
所有本轮创建、删除、构建、镜像推送、发布、rollout、Git push计数为0。
正式verdict见VERDICT.json。本轮到此STOP。
