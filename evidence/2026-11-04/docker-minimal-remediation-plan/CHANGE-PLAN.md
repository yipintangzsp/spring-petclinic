# Docker 最小整改变更单（仅方案，未执行）

本轮推荐路径：D。暂停 Trivy 真实执行，保留14/16和真实 blocker；其他已验证插件可按既有独立、非发布入口运行。生产强制Gate仍按冻结规则决策；组件 BLOCKED/UNAVAILABLE 不得当成 PASS，也不得为发布自动跳过 Trivy。

同时提交一个可独立批准的 socket world-write 风险收敛变更。它不解决 Jenkins rootful Docker 权限隔离、不解锁 Trivy。

## 真实来源、范围、依赖

- 当前 /var/run/docker.sock → /run/docker.sock，root:docker(988)，0666，inode1405。docker.socket vendor unit SocketMode=0660/root:docker，无socket drop-in。
- Docker service通过fd://接收socket。其 /etc/systemd/system/docker.service.d/override.conf 精确内容为 `[Service]` 和 `ExecStartPost=/bin/chmod 666 /var/run/docker.sock`；systemd记录该命令于2026-11-01 10:26:51执行成功。这是本次查到的直接持久化来源，不推测是谁/何时首次编写。
- limits.conf另有MemoryMax=6G/MemoryHigh=5G，必须原样保留；不评价其是否实际覆盖其他slice中的所有容器。
- Kubernetes全部Pod快照中，仅 ns-devops/jenkins 挂载该socket；其UID/GID/groups=1000/1000/[1000]，因没有988，当前依赖world权限。上轮#270真实built-in执行，构建Docker能力不能中断。
- Docker13个容器快照中，仅 /portainer 挂载socket，镜像默认root身份，root访问不受0660影响。不得重建Portainer或删除它的socket。
- docker组显式成员 zhang、gitlab-runner；主机登录进程的实际supplemental groups要在实施窗口重新核验，group文件不等于所有已启动进程的实时组。gitlab-runner是否正在调用Docker属于UNKNOWN潜在依赖，不能擅自移出组。
- ss只读取样无dockerd TCP监听/2375/2376；当前ExecStart仅fd://。没有据此排除未知代理转发或历史短时API连接。lsof当时无匹配连接，不代表无人依赖。整轮依赖清单是时间点快照。

## 最小变更：阶段0预检与维护窗口

需要单独明确批准的 Jenkins 控制面/构建暂停窗口。不能承诺在线零意外停机。PetClinic/Harbor运行容器不计划重启；Jenkins单副本增加supplementalGroups将产生Pod替换、UI/agent短时不可用，必须窗口内执行。

实施前必须重新完成：

1. 确认Jenkins #270、V1摘要、Argo、PetClinic、Harbor、三节点健康；确认无正在运行或排队且可能调用Docker的构建，暂停新触发并保留原触发设置。
2. 列出现有所有socket消费者、PID/UID/groups、Kubernetes hostPath消费者、Docker挂载消费者；核实gitlab-runner和Portainer的访问。出现本清单之外的UID则NO-GO，先补依赖。
3. 确认socket额外ACL和相关身份真实组；存在未知named ACL则NO-GO，先完成权限分析。确认当前source hash与本证据一致。确认 Jenkins Deployment 的权威配置管理者（现有源码 `infra/jenkins/jenkins-deployment.json` 需与live spec对齐，不盲目覆盖），锁定维护用具体Git变更/修订；不允许Argo/其他reconciler将变更反复覆盖。
4. 保留override.conf、limits.conf、docker.socket unit及DropInPaths、当前socket mode/owner/inode、Jenkins原supplementalGroups字段的存在性和值、触发器状态，备份存于root0700目录。没有备份则NO-GO。
5. 确认受影响服务联系人/恢复路径、独立SSH管理入口；不以Jenkins本身作为唯一回滚通道。无需业务数据库/PVC/镜像变更。

## 阶段1先保留既有Jenkins构建能力

仅在批准窗口内，通过Jenkins的正确配置源给Pod securityContext新增supplementalGroups: [988]（已有组取并集），保持runAsUser/GID1000和其他配置不变。不使用fsGroup，避免递归更改PVC所属组；不新建用户、不改socket owner。

该动作保留当前已经存在的Docker访问权限，**不是可信执行器隔离**，不是把docker组称作安全边界。普通项目代码仍能通过raw socket管理宿主；必须作为明确、限时接受的剩余风险单独批准。

等待Jenkins恢复，验证 `id` 包含988，执行只读 `docker info` 取得原daemonID，验证Git checkout/Maven等既有构建环境可用。真实完整流水线可能发布，不能未经单独批准用于本次验证；可先批准一个仅build/test、无push/deploy的既有验证路径。不得为测试制造发布。

若Jenkins未恢复/权限不符，先还原这一个supplementalGroups修改，停止；此时socket仍保持原0666，不继续收紧。

## 阶段2持久化与当前inode收紧

完整拟变更内容见 docker.service.override.proposed.txt 和diff。只将offending文件内那一条命令改为 `/bin/chmod 0660 /var/run/docker.sock`，保持其余字节和limits.conf不动。不要清空其他ExecStartPost，也不改vendor docker.socket。

以下仅是窗口内经批准后执行的运维顺序，**本轮未执行**：

```sh
# 备份目录需使用本次维护唯一ID，不复用旧目录
sudo install -d -m 0700 /var/backups/docker-socket-change-<WINDOW_ID>
sudo cp -a /etc/systemd/system/docker.service.d/override.conf /var/backups/docker-socket-change-<WINDOW_ID>/override.conf
sudo cp -a /etc/systemd/system/docker.service.d/limits.conf /var/backups/docker-socket-change-<WINDOW_ID>/limits.conf
# 安装审核过、哈希已锁定的proposed文件；不能把未审核工作树直接上传应用
sudo install -o root -g root -m 0644 <APPROVED_PROPOSAL_FILE> /etc/systemd/system/docker.service.d/override.conf
sudo systemd-analyze verify docker.service docker.socket
sudo systemctl daemon-reload
systemctl show docker.service -p ExecStartPost
# 验证owner仍root:docker、inode未变、Jenkins已经有988，再收紧当前inode
sudo chmod 0660 /run/docker.sock
stat -c '%a %u %g %i %n' /run/docker.sock
```

不需要重启docker.socket或Docker daemon；daemon-reload不会执行ExecStartPost。chmod只修改现有inode权限，不unlink/recreate socket。保留原inode可避免hostPath bind到旧socket的问题。不得执行 restart docker/docker.socket 来“让权限生效”。

持久化在下一次**另行批准**的daemon启动时由原docker.socket0660和改后的ExecStartPost0660共同保证；本窗口不验证重启场景，不宣称已完成重启持久性实测。

已打开的socket连接不因chmod自动撤销；发现不明已连接客户端时，不能声称收紧即撤销全部权限。需暂停变更并制定该客户端的定向隔离方案；不得通过全局Docker重启处理。

## 验证、失败与回滚

验证：socket0660/root:988、inode和daemonID保持不变；systemd解析的ExecStartPost无666；Jenkins UID1000带988且docker info成功；zhang/gitlab-runner依赖的操作正常；Portainer只读API正常；PetClinic/Harbor HTTP/Pod/Argo健康未变；生产digest和V1 Summary未变。

离线负例：非root且无988的计划身份在0660下应无法连接。此轮仅做UNIX权限模型验证，不在生产执行身份切换。真正拒绝测试需未来窗口批准，不等于阻止Jenkins自身raw API。

回滚触发：任何既有授权消费者新连接EACCES、Jenkins不能恢复、配置校验失败、未知消费者或业务异常。

- chmod之前失败：保持socket不变，还原新Jenkins组配置并停止。
- chmod之后出现授权消费者故障：经窗口内预先明确批准，可暂时恢复原0666，作为有时间限制的紧急恢复；这是重新暴露风险，必须单独记录，不得作为永久修复。然后恢复原override.conf并daemon-reload，确认没有意外重启。
- 下列为**未执行**的回滚命令：

```sh
# 仅在已批准紧急回滚、确认备份归属和哈希后执行
sudo chmod 0666 /run/docker.sock
sudo cp -a /var/backups/docker-socket-change-<WINDOW_ID>/override.conf /etc/systemd/system/docker.service.d/override.conf
sudo systemctl daemon-reload
systemctl show docker.service -p ExecStartPost
```

只有socket访问恢复后，才通过同一权威配置源还原Jenkins新增supplementalGroups字段（保留原先已有组；原字段不存在则还原不存在），等待Jenkins恢复并再验证全部依赖。不要盲目apply整个旧Deployment覆盖其他并发变更。原limits.conf和vendor unit始终不应变化。

## 完整Jenkins身份拆分：最小结构变化与阻塞

真正隔离必须改变“项目代码与控制器共用built-in执行身份+宿主socket”的结构：普通CI进入无raw Docker socket、无任意宿主API的新执行身份/隔离Agent；Docker特权操作由不可被项目仓库修改的可信入口执行。入口固定digest/argv/安全参数/挂载/执行目的，拒绝任意shell/env/create/exec/volume/image/daemon管理参数，且只允许非发布validation。可信入口不能与不可信构建共享可写脚本、凭据、进程身份或能改其配置的权限。

当前只有built-in executor；当前认证后全控制的Jenkins授权策略也不能支持可信入口与普通项目配置权限隔离。需要明确job configure/SCM写权限/可信代码来源治理，不仅仅新建Job。现有docker-safe和docker.original并存、raw socket可写，不能充当授权边界。

在不新增资源、不安装服务、不改变生产权限的本轮边界下，没有已验证的可用拆分执行环境；不重复七候选审计，不编造Agent。此部分PLAN=NOT_READY。未来具体变更至少涉及Jenkins Deployment与任务调度/凭据范围/授权策略，以及可信入口的受保护配置；没有现成、可直接上线的执行器文件。不得为了完成此项直接关闭built-in executor或移除socket而打断现有构建。

## ext4 quota最终判断

历史只读证据：ext4 features未启用quota/project；挂载rw,relatime；Docker为overlayfs/containerd snapshotter而不是已证明可用的经典overlay2+XFS配额路径。参数接受不等于执行。

启用文件系统配额可能涉及修改超级块特性、quota inode初始化、重新挂载，部分路径需要离线检查/重启；具体操作必须针对实际工具/kernel/driver验证，不能承诺在线安全。Docker是否读取这些配额仍需独立证明，单启用ext4 quota并不自动使Docker size生效。重新挂载/driver切换/迁移可能影响Harbor、Jenkins、k3s和所有共享根盘容器。

当前没有已证明可恢复的根盘一致备份和容量条件（Mac宿主余量也不足以假定可再放完整VM副本）。因此 STORAGE_QUOTA_CHANGE_FEASIBILITY=NOT_FEASIBLE_NOW。本方案不提供生产根文件系统改造执行命令，不批准重挂载/修改features/重启daemon。目录权限/Guard轮询不是容量强制边界。

## 四种架构比较

| 架构 | 现有资源可用性 | 前提与改动 | 代价/影响/等价性 | 当前blocker / 实施与回滚 |
|---|---|---|---|---|
| A Docker+权限分离+真实配额 | NOT_FEASIBLE_NOW | 身份拆分、授权和底层强制限额均需实证 | 影响共享权限/根盘；未达到安全等价 | 无可用执行身份及quota；不实施；未来需独立维护/备份/回滚方案 |
| B 严格容量隔离写区 | 小型scratch可用；完整Trivy NOT_READY | 已验证小tmpfs仅适于小数据；DB/刷新/报告内存与swap预算需上界 | RAM约4.98GiB available且swap在用；不能默认完整DB进RAM | 峰值未知、磁盘低于floor、元数据/COW无界；不增加内存盘，不实施；回滚仅未来已登记fixture |
| C 已有远程扫描/预置DB服务 | NOT_AVAILABLE_AS_VERIFIED | 只考虑当前已经验证安全契约/新鲜度/完整性/授权的服务 | 不能把普通镜像仓库或过期DB当等价扫描服务 | 既有封存结论没有合格现成服务；不重审七候选、不新增资源/地址；无部署可回滚 |
| D 暂停Trivy真实执行 | AVAILABLE，SELECTED | 不启动Trivy/Dojo，记录真实阻塞，其他已验证插件按既有入口独立工作 | 无新资源、无生产改动；不等价于扫描通过 | release强制Gate照旧，14/16；无需修改生产或做回滚 |

推荐唯一执行架构D。socket风险收敛作为独立的维护变更先审批，与Trivy执行架构验收分开；即使收紧成功也不解锁Trivy。

## 保留最终Security Manager契约（设计，未实施）

SECURITY_ENABLED → Security Manager → Plugin Capability Check → Independent Plugin Execution → Raw Report → Normalize → Policy Engine → Unified Result → Result Router。

Trivy capability不可用须记录 BLOCKED/NOT_AVAILABLE、原因（空间/配额/身份/DB）、证据和未执行事实，不输出伪造Raw Report/PASS。普通组件不可用状态与生产发布Gate决策分开：若冻结生产Gate要求Trivy成功，则按既有规则阻止发布；不允许根据组件开关静默弱化强制Gate。其他插件独立执行不能把14/16包装成16/16。本轮不实施Manager、Registry、SummaryV2或Router。

## 需要明确批准的未来操作

1. 仅socket world-write收敛的维护窗口、构建触发暂停、Jenkins补充组变更及Pod替换。
2. 修改唯一offending drop-in、daemon-reload、对当前inode chmod0660，及保留Jenkins root等效权限的过渡风险。
3. 若失败，是否预先允许短时恢复0666作为紧急回滚；否则遇到故障停在人工处置，不能擅自重新放宽。
4. 完整身份拆分/授权策略变更必须另开具体方案；当前没有获批实施路径。

本轮没有执行上述任一操作。唯一下一步：审阅并批准或拒绝第1–3项独立socket维护变更；Trivy继续暂停，不实施身份拆分/配额改造/扫描。
