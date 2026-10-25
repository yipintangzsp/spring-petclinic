# Terraform 执行隔离进展与阻塞 · 2026-10-25

**尚未完成完整隔离验收。** Jenkins #191 应用发布及原有业务事件检查通过，但新增 Terraform Isolated Plan 阶段失败，整条构建为 FAILURE。当前修复已通过本地测试，尚未发布复验；不得将下列单项预检视作最终成功。

## 10:12 状态与最终发布准备

#192的测试、Sonar、双架构镜像、Harbor扫描及GitOps晋升全部通过，但随后磁盘触发原停止线，已被资源守护中止；整轮结果为ABORTED，不能记为SUCCESS。运行镜像63f79225…及源代码bd18401…仍有完整前置检查证据。

用户另行授权后，仅清理两份旧公共库副本db-verified/trivy.db、java-db-verified/trivy-java.db；先逐字节确认与Mac已有官方归档完全相同，回收2876.48MiB。其余历史备份文件未变，当前公共扫描库未动，也没有新的数据外送。恢复这两份旧公共库需从Mac的trivy-db.tar.gz、trivy-java-db.tar.gz解压回传，原元数据仍保留。

在已扫描的192固定镜像上做受控开发预检，真实独立Job计划和共享状态锁/幂等均通过；控制失败exit42与随后的正常计划重试亦通过。超时演练遇到CNI按Pod安装规则的启动竞态，固定探针曾在规则就绪前连通，因此按设计在读取令牌、执行Terraform前停止。源码现增加15秒有界拒绝屏障，必须等到真实网络拒绝才允许后续步骤；始终可达则失败。超时演练预算改为60秒，仍必须取得DeadlineExceeded与临时资源回收证据。新屏障尚待193镜像中实际验收。

首次发布另增加原磁盘停止线之上的固定2048MiB构建增长预算，保持发布后门槛和所有运行停止阈值不变。针对192观测到的实际增长，避免再次只略过停止线即启动构建。80项Node、16项Python及Maven validate通过；最新三样本根盘48200–48208MiB，满足原门槛加2GiB；原状态/备份不迁移。

一次公开工具下载缓存清理的监控曾记录memory full PSI6.03%（原阈值5%），原始安全失败保留；不能宣称全部维护过程没有压力。该临时维护结束后已重新连续采样才准入后续任务。之后公共库刷新11个样本无安全失败、memory full PSI最大2.24%；192最终因磁盘停止线按记录中止。完整193仍需重新执行全部检查。

## 09:35 公共扫描库维护已完成

用户对四个公共缓存文件的明确授权已执行：原文件完整备份并核对SHA256、大小、uid/gid及权限后临时移出；保留原15%+12GiB（含额外4GiB）的刷新准入，使用正常Trivy命令安装官方固定摘要Java库f702563b…，再逐字节恢复仍有效通用漏洞库。没有修改NextUpdate/DownloadedAt。新Java库NextUpdate为2026-10-28 08:59上海时间；通用库仍有效至10月25日15:11。两类实际磁盘元数据检查通过，维护结束恢复Jenkins、释放共享锁。完整Job隔离仍待本次流水线复验，下方待授权段落保留为历史记录。

## 09:19 最新进展

本轮两镜像新增授权已执行完成：完整归档609984000字节，SHA256 c8c7308c31da5f7e9e988a1e944869e790c46436f9ebaa167cc9356074c25a35；逐层核验和实际Docker恢复比对通过，仅删除获准的两个本地标签及其非共享构建缓存。实测回收910.48MiB，所有受保护镜像、卷、PVC未变。详细结果在approved-191-cleanup/result.json。

另清理18份可重建公开工具下载副本，先逐一比对包内程序与已安装程序SHA256，回收776.23MiB；所有已安装工具路径和内容未变。最新根盘约47209MiB，高于普通任务门槛，但仍低于扫描库刷新需要的原15%+12GiB门槛。

以修正权限的公开工具副本实际执行离线容器预检：无网络、无凭据、UID65532、只读根、Landlock ABI8及额外seccomp限制，Terraform1.17.0 version/init/validate全部通过，memory.peak 101928960字节。没有挂载Jenkins目录或集群管理凭据。此为开发预检，尚未证明新运行镜像或完整Job端到端成功。

Java漏洞库在2026-10-25 09:08上海时间过期。新的明确阻塞是公共扫描缓存维护授权：拟备份核验四个公共数据库/metadata文件，临时移出以满足原4GiB刷新余量，正常刷新Java库，再精确恢复仍有效的通用漏洞库；失败恢复原缓存。自动审批拒绝了该PVC内公共缓存的备份与替换，已向用户单独请求授权，尚未执行。此前下文关于两个191镜像待授权的文字为早晨之前历史阶段，已被本节实际执行结果替代。

当前工作负载准入和扫描刷新门槛均未降低。Jenkins非quiet、共享锁已释放、没有遗留计算Pod；完整隔离仍未验收完成。

## 已执行与修复

- 源码78fd2fddd471052e9bdf49d4151d5d87c3234cc7按完整流水线执行。应用镜像34a52e2f…经GitOps提交ac2d17d…部署；Terraform专用镜像075eef58…构建及Harbor扫描成功，扫描成功不等于无漏洞。
- 新命名空间terraform-execution、受限运行/编排身份、单Pod配额、NetworkPolicy及三组失败关闭的准入策略已在开发预检中落地。旧tf-remote-lab运行身份读状态403；编排身份读状态403。恢复旧RoleBinding的独立server dry-run被拒绝。
- 合法Job server dry-run为201；错误身份、hostNetwork、hostPath、可写根、可变镜像、替换入口、lifecycle命令、token终止消息路径、特权模式、Secret环境变量十类请求均为403。明确设置Forbidden原因并对必需字段做存在性检查；未放宽seccomp/AppArmor要求。
- 真实Pod tf-191-plan-12320123-jvq44（UID 2bb7a690-8e55-4565-b392-74e246d5d87a）以65532:65532启动，512Mi/1CPU上限。内核前置探针已到达网络检查，但该业务计划未通过。
- 已修复控制器canary连接重置未处理，以及DELETE缺少Content-Length导致UID/级联参数未有效发送。真实本地HTTP回归测试验证DELETE正文完整。遗留自有Pod按UID正常删除，未删除finalizer；后续重放已验证Job与Pod正常回收。
- 主机抓包证实10.42.0.154访问Jenkins canary 10.42.0.3:6443收到ICMP端口不可达，与CNI的icmp-port-unreachable拒绝规则一致。新源码要求IP_RECVERR内核错误队列明确给出ICMP origin/type3/code3，普通TCP RST或本地拒绝不通过；该新检查仍待新镜像实际验收。
- 离线init实测发现provider目录继承700权限。新Dockerfile用COPY --chmod=0555固定公开工具目录权限，并避免chmod复制Terraform大文件层；新镜像离线init/validate仍待重新构建验证。
- 当前本地78项Node、14项Python测试以及Maven validate通过。#191原Java与消息链路测试通过；这些不代替新增隔离任务端到端成功。

## 数据及资源保护

预检后已核对：Jobs/Pods为空、platform-heavy Lease不存在、Jenkins非quiet；远端状态Secret UID fb5529e7-ee5b-48ce-a12f-5e54ca5996c6、lineage c7319894-9085-a3c1-a6f2-5cc641dfbf2c、serial5，仅一个真实ConfigMap。原15份状态/计划/日志SHA256全部未变。没有迁移旧状态或删除业务对象。

按明确授权完成原五个镜像的完整归档、逐层校验、实际Docker恢复比对和最终本地副本清理，实测回收2581.25MiB。归档1567867392字节，SHA256 c03393b41a99ab18ae728c5e24610fa713f667b888f4a9672dc54c2123d07e33。MySQL只备份原本实际存在的ARM64平台内容，原Docker内容库缺失的两个AMD64描述符不虚称已备份。#191后来重新拉取的mysql:9.7内容与旧备份不同，未删除该新版本。

另回收25条未使用、不与镜像共享的旧构建缓存，实测763.69MiB；全部Docker镜像ID和卷名不变。保留当前使用的安装缓存，没有运行全局prune。

截至01:58左右，根盘45926MiB（44.85GiB），原准入线45667.83MiB，仅余约258MiB增长空间；VM可用约9801MiB。禁止据此直接启动下一轮完整发布或降低停止线。已请求新增清理授权：完整备份校验本轮运行镜像191及应用191的Docker本地副本，再只清理这两个副本及其非共享构建缓存。Kubernetes运行镜像/缓存、Registry/Harbor原件、190/189/183/184、数据库、卷、PVC保留。自动审批拒绝了超出原五镜像范围的新增归档；当前尚未执行新增备份或删除。

## 待完成的最终矩阵

1. 新镜像完成正常构建、Harbor扫描、离线init/validate及真实Job计划。
2. 在Job内完成共享状态A/B真实锁冲突、等待后重试、幂等与最新成功快照读回。
3. 控制失败exit42、真实Job deadline、全部UID回收、Jenkins/重任务锁恢复。
4. 内核错误队列证据、前后健康canary、实际API越权拒绝及镜像摘要同时通过。
5. 重新执行完整流水线至SUCCESS，再复核状态UID/lineage、历史摘要和最终资源，更新文档。

运行资源：每次仅一个Pod，requests100m/384Mi、limits1CPU/512Mi，ephemeral-storage128/384Mi、emptyDir256Mi，Job deadline180s、重试0；失败演练deadline25s。沿用外层共享锁，不在Job里再次申请同一把锁。镜像内置provider离线镜像源，无DNS/包下载需求。

## 后续入口与排查

空间授权和准入通过后，继续现有petclinic-ci完整发布。新增阶段为Terraform Runtime Build & Scan、Terraform Isolated Plan、Terraform Shared State、Terraform Failure Cleanup。Jenkins只负责可信部署编排，Terraform引擎只在Job内执行；现有源码中的旧Jenkins/宿主自动化入口已拒绝执行，旧状态保留。

查看Jenkins阶段控制台，以及target/platform/terraform-runtime.json、terraform-isolated-{plan,shared,recovery}.json。私有原日志位于Jenkins /var/jenkins_home/terraform-runs/isolated-*；异常记录保留Job/Pod UID、退出码、日志摘要和清理状态。Job/Pod回收后从归档排查，不假定临时Pod一直存在。失败时先核对UID/owner及真实状态锁；禁止对业务资源执行destroy或盲目强解锁。

K3s Secret静态加密仍关闭；这是独立遗留，不把受限执行身份等同于节点静态数据加密。可信部署控制器仍具有管理权限，本轮隔离目标是Terraform代码不能获得Jenkins文件、宿主目录、Docker socket或管理凭据，不宣称能抵御集群管理员主动撤销政策。

证据根目录：/Users/zhangsir/code/evidence/platform-20261011/terraform-isolation-20261025。原#190独立共享状态验收保留，但不能代替本轮Job隔离结果。
