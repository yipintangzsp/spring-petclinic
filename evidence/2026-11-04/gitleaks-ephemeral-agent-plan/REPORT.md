# 专用临时 Jenkins Agent：只读审查与离线配置准备

基线提交 `5ec44c31`，本轮没有 push，没有生产变更，没有创建/删除Agent Pod。
结论：**路线技术上可行，当前实施前置条件尚未齐备，不启动Agent，不运行真实CI。**

详细设计、启动/清理步骤与审批清单见
`infra/jenkins/gitleaks-validation/ephemeral-agent/README.md`。
所有实际判定见 `verdict.json`，实测前后对比见 `verification.json`。

## 现有能力

- Jenkins2.568.1位于K3s/ns-devops，唯一built-in executor当前空闲，仍有Docker GID988。
- Kubernetes plugin不存在、无cloud、无可复用非生产Agent模板；不能假设插件自动创建Pod。
- Jenkins core WebSocket支持最终实测true，TCP50000已配置；方案复用Service8080 WebSocket，不新增入口。
- agent.jar公开读取200且固定SHA256；尚无Node注册、Agent握手或真实Pod运行证据。
- 真实线上独立验证Job不存在，本地禁用定义保留；没有Jenkins Build编号。
- 全局授权策略为FullControlOnceLoggedInAuthorizationStrategy；不将label/EXCLUSIVE当作权限ACL，
  不在本轮修改全局授权。Controller的rootful Docker残余风险不因候选Pod而消失。
- 凭据仅由现有relay就地使用做只读管理；未导出任何凭据、API token或remoting secret。

## 候选方案与实际交付

选择现有core Inbound Agent + 受信管理端一次性provision + devsecops-execution临时Pod，
不用Kubernetes plugin或新常驻组件。SA无业务RBAC且不挂API token。

候选Linux UID/GID24001：宿主无该账号/进程，实际基础镜像passwd无该UID；已核实工具文件root:root/0755。
这仅支持身份设计，不代表该UID已真实启动。root/65534/docker组均被离线契约拒绝。

交付Pod、SA、NetworkPolicy YAML1.2/JSON候选、Node XML、Dockerfile候选、镜像输入锁、
资源预算、Job绑定计划、显式七闸门、定向UID-precondition清理契约和离线负例。
最终Agent镜像digest仍为未解析占位符，不可部署；没有伪造摘要或默默使用latest。

可信Manager、原Policy和Router经独立审查后烘入固定只读镜像；fixture是只读被动数据，
不执行源码/配置/钩子，写区只在/work和/tmp。没有共享Controller目录、PVC或Docker Socket。
单容器内Remoting与Manager不构成彼此隔离；如果未来要执行项目程序，需另行架构评审。

## 资源与安全约束

当前三个节点Ready、无Memory/Disk/PIDPressure，但两个amd64 worker都有cloud=true:NoSchedule。
已缓存工具仅linux/arm64；不加toleration，保留污点，仅以实际架构设置required affinity，不设置nodeName/nodeSelector。
当前唯一符合候选条件的节点是devops，不把这一事实包装成跨节点可运行。

devops基线实际内存available4.76GiB，CPU allocatable6/已请求4.055；CPU PSI仍存在。
候选request250m/512Mi/128Mi ephemeral，limit1CPU/768Mi/256Mi ephemeral；
现有security-budget可容纳单Agent。128Mi+32Mi内存emptyDir计入Pod768Mi上限。
这些是候选预算，未实测JVM/Node/Go同运行峰值、日志与最终镜像解包上界，RESOURCE仍NOT_READY。
ephemeral-storage limit是计量/驱逐边界，不是强制quota；不把它或sizeLimit当成Trivy预算证明。

现有NetworkPolicy默认deny全部；k3s实际网络策略链存在，未禁用。
候选仅向该Agent标签增加Jenkins8080与DNS53，不给GitLab、Harbor、Internet、proxy或API显式allow。
使用离线镜像fixture，不需要Git/Harbor凭据和在线源码checkout。
NetworkPolicy本节点/API和DNAT路径不能靠静态YAML证明拒绝，因此NETWORK仍NOT_READY。

现有Kyverno匹配namespace/rule已盘点；候选静态符合非root、无host访问、只读根、资源和镜像仓库方向。
没有调用server-side create/dry-run admission，更没有创建Pod，所以真实policy compatibility保持INCOMPLETE。
新SA将继承系统discovery/basic-user权限；无业务Secret读取、exec或Pod创建授权。
该结论是现有RBAC绑定盘点，不是尚未存在SA的真实认证测试。

## 不能省略的阻塞

1. 当前entry硬编码宿主systemd cgroup，不能直接用于Pod；缺可信管理端绑定的Pod身份backend。
2. 现有原生Gitleaks approval还要求root拥有的普通文件、源inode/device和同域执行UID拥有的outputs。
   emptyDir/fsGroup/投射Secret均不能直接满足；缺保持同等安全语义的Pod输入批准与输出布局适配。
3. 缺最终组合镜像、真实digest、完整工具文件白名单/校验树、实际只读UID兼容性和解包上界。
4. 缺目标Pod网络策略真实正负验与本节点API路径证明；不改已有策略来降低边界。
5. 新manifest/hash与固定Job/build/run标签绑定需要离线重新生成、评审；原禁用Job仍未更新或导入。

不删除原guard，不用mock通过代替上述验证，不启用Job作为捷径。

## 实际测试与未验项

- 新增Agent离线契约：98/98 PASS。
- 原CI/Candidate回归：74/74 PASS。
- 原Gitleaks源码锁：9/9 PASS。
- 合计181 PASS、0 FAIL。候选XML与YAML1.2/JSON解析通过。
- 9类真实Agent验证明确SKIPPED/NOT_TESTED：身份、只读路径、WebSocket、admission、网络、
  后代/timeout/SIGTERM、峰值、镜像启动、真实清理/Controller失联。
- 原127个版本化差分/190兼容性及已封存Docker实验未重复运行；相关冻结实现未改。
- 本轮测试不是Gitleaks实际扫描或Jenkins CI，Runtime不能增加。

## 清理、回滚和唯一下一步

定向流程：固定Node停止派任务→归档redacted evidence并独立验seal→按Pod UID precondition正常删除→
确认整个运行域进程消失→删除仅该run的remoting Secret/Node→清除私有fixture。
节点失联或删除失败保留CLEANUP_INCOMPLETE并锁后续run；不得force delete、删namespace或全局kill。
Controller失联的noReconnect与Pod600s deadline只是设计；不能在节点失联时承诺墙钟超时后已清理。

本轮无资源可回滚；仅撤回未部署候选即可。实际创建/注册/启动及销毁Node、SA、Secret、NetworkPolicy、
Pod、构建/分发镜像、导入/启用Job、运行CI都需要对应独立授权，且先通过七闸门。

**唯一下一步允许方向：离线补齐Pod身份与fixture批准适配、可信镜像输入，重审七闸门。**
本轮完成即STOP，不申请或启动实际Agent。

## 生产保护结果

前后只读核验20项全部通过：#270仍SUCCESS，V1 Summary SHA与生产Job定义SHA不变，
Argo CD Synced/Healthy，三节点Ready，PetClinic3/3及HTTP200，部署spec与生产镜像digest不变。
Docker Socket仍root:988/0660；Trivy Pod与DB元数据/文件属性观察不变、未扫描/刷新；
Dojo Pod UID/image/restart不变、无import或数据写入。没有对整库做内容哈希或宣称新runtime验证。
11604个既有受保护文件按本轮起点比较未改变。

原始历史完整性仍FAILED，生产Security Manager未启用，Trivy/Dojo仍INCOMPLETE，Runtime14/16。
release=0，PetClinic rollout=0，Agent Pod create/delete=0。
