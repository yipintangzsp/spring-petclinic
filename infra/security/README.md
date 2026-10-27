# DevSecOps：隔离扫描、依赖清单与准入

新增单副本 Kyverno 1.19.2 / chart3.9.2，官方ARM64镜像按摘要转存现有Registry。控制器 requests100m/192Mi、limits500m/512Mi；单副本Recreate，仅为学习平台，不提供高可用。CRD来自固定SHA256的官方chart；values与controller.json一并保留。关闭后台扫描、报告/清理控制器和额外Grafana，复用现有观测平台。

`devsecops-execution`只允许1个Pod、无PVC，扫描Pod无服务账号token、只读根、非root、RuntimeDefault seccomp、丢弃ALL capabilities，default-deny网络。Gitleaks8.30.1按官方ARM64摘要固定，CPU100m/1、内存256/512Mi，600秒截止；扫描仅接收本次Git HEAD归档，不挂宿主、业务Secret或PVC。扫描复用外层platform-heavy Lease，不申请第二把锁。

流水线先用真实server dry-run验证合规允许和7种违规拒绝，再真实扫描完整Git HEAD；每轮用随机合成、36个互异字符的GitHub格式样本验证泄漏拦截（仅在隔离容器内生成，不是服务签发的凭据），并验证空目录允许。仅归档脱敏规则/位置/指纹，不归档token或原始匹配文本。发现真实泄漏即失败，不自动建立忽略基线；95条已人工核对的Helm SHA256/公开Go h1校验值按文件路径与完整行SHA256精确识别，原始计数与逐条误报保留，新增或变更内容仍阻断。异常finally和Jenkins post只按本次UID清理。未知替换对象保留并使构建失败。

复用原Maven CycloneDX2.9.3已嵌入应用JAR的生产依赖SBOM，不额外生成第二份依赖图；逐字节核对JAR内外SBOM后归档，验证1.6版本、非空组件、唯一bom-ref及依赖图；不把它当作整个镜像/平台的OS清单。release-evidence.json将SBOM SHA256、源码commit、双架构镜像摘要、Harbor结果和门禁结果绑定；目前为未签名证据，不声称实现Cosign签名验证。

PetClinic模板在隔离命名空间作同规则server dry-run审计，`business-template-audit.json`明确passed/findings；仅网络/API/结构错误使审计任务失败，审计发现不冒充阻断。生产命名空间暂未挂此Kyverno webhook，不影响生产API可用性。实际候选部署加入只读根、128Mi /tmp emptyDir、fsGroup10001及RuntimeDefault seccomp；必须经原GitLab/Jenkins/Sonar/Harbor/Argo完整发布与业务健康验收才生效。

现有Sonar质量门、Harbor Critical/High门禁、Terraform独立执行隔离、业务/消息/分析链保留。新Application platform-devsecops在GitLab源码审计后固定本轮commit，自动同步且不prune。

## 查看和排查

Jenkins petclinic-ci 的 DevSecOps阶段与归档 `.devsecops/*.json`；源码扫描、SBOM、准入拒绝、业务模板审计、GitOps与发布摘要各自保留真实状态。Pod删除后计算日志不再作为唯一证据。

```sh
kubectl -n devsecops-system get pods
kubectl -n devsecops-system logs deploy/kyverno-admission-controller
kubectl get clusterpolicy devsecops-workload-contract
kubectl -n devsecops-execution get pods,resourcequota,networkpolicy
kubectl -n argocd get application platform-devsecops
```

controller ServiceMonitor 接入既有Prometheus。实际采集、业务发布与各轮CI结果以本轮验收文档为准；Ready不能替代门禁验收。Kyverno ClusterPolicy API已被官方标为deprecated，版本锁定1.19.2仍支持；升级到删除旧API的版本前必须先迁移并重验。

未覆盖：全平台运行时威胁检测、集中漏洞处置平台、专用密钥管理/静态加密、完整签名准入、认证业务DAST、外部通知送达。它们不因本轮Pod部署而被标为完成。

Grafana看板UID `devsecops-control`，复用既有Prometheus与Loki数据源，不增加看板Pod。

扫描Pod额外实测：Jenkins临时Pod级canary前后可达作为基线，等待扫描容器连续两次无法连接该端口后才传输源码；读取实际有效UID、确认token文件缺失，并要求实际写根目录返回只读文件系统错误。运行时结果保存在source-gate.json的isolation字段。controller.json是最终GitOps期望，values是固定官方chart原始渲染输入；原摘要本地镜像与Recreate调整以已锁定SHA256的controller.json为准。

节点边界：原生NetworkPolicy不能作为宿主/节点防火墙保证。实际节点API TCP可达性单列记录；不宣称其被可靠阻断。无token和无Secret RBAC权限仍独立验证。Pod-to-Pod探针保留策略收敛尝试次数，始终无法阻断则失败并且不传源码。

策略默认值在Git中显式声明，allowExistingViolations=false，不忽略任何策略spec差异。GitOps同步成功后还逐一验证22个CRD的原生Established/NamesAccepted条件、实际策略spec与源码深度一致，并重新执行真实准入负例。所有资源顶层Argo实例标签显式归platform-devsecops，聚合ClusterRole选择器与之对齐；Pod模板及Service选择器仍保持kyverno。独立回归曾发现顶层标签被Argo覆盖后core角色未聚合、CRD读取403，已修复并新增标签模拟测试、实际SA CRD读取权限及13条core规则检查。未增加原权限，未修改全局Argo追踪或健康规则。

## 2026-10-27 接入候选（完整发布验收前不标完成）

新增 Cosign 私有仓库签名、三个 PetClinic Secret 的 SOPS 密文来源、六条 Java Semgrep 规则及 GET 白名单 ZAP 被动门禁。扫描复用已运行镜像的相同摘要本地 Registry 别名，不新建基础运行镜像；工具只以版本化硬链接目录复用，运行前逐文件核对锁定摘要。扫描在 devsecops-execution 串行运行，无 token、只读根、非 root；实际验证到 Jenkins canary 的阻断后才传工具/源码。ZAP 仅向 PetClinic Pod 的8080端口放行，禁止 spider、表单提交和主动扫描。

验签新增范围仅 petclinic 与 devsecops-supply-chain，匹配 core.harbor.domain/petclinic/*；其他命名空间/仓库不据此声称已保护。先签当前部署和214回滚基线，再经原GitOps流程注册策略；CI验证正确签名允许、未签名和错误密钥拒绝，随后签双架构候选和发布证据，promotion额外要求签名证据与源码/镜像一致。使用私有受控公钥信任，未上传公共透明日志，不声称具备Rekor透明性。

解密密钥分为业务与签名两份 Jenkins 文件凭据，恢复原件位于服务器root私有目录及Mac本轮私有证据目录。Git只保存公钥、age公有recipient和密文；签名私钥只在签名阶段临时解密，finally回收，不归档。业务迁移仅 petclinic-db、rabbitmq-client、petclinic-harbor-pull，不改变现有密码。CI用限定三个资源名称的身份进行get/patch/update，读取其他Secret、列举、创建或跨命名空间均应拒绝；Jenkins既有管理员能力未由此消除。现存值与密文不一致时拒绝覆盖，防止回滚外部轮换。

Semgrep ERROR发现阻断，扫描错误/空目标也阻断；六条规则不是全量SAST覆盖。ZAP通过本地合成测试卡号页面验证High检测，再GET首页、owners/find、vets和health；High阻断，其余发现保留报告，未覆盖认证与浏览器攻击。签名测试使用几KB的独立Harbor测试制品，不启动攻击Pod。所有成功结论以完整CI和独立记录为准；已有214不替代新门禁验收。

2026-10-27 接入复验进度：#220 在 NoHttp 校验处失败，增加了仅限 signing.mjs 与既有 Harbor 私有监听器的精确说明/例外；#221在Maven集成测试阶段触发原 full PSI>5 停止线而ABORTED，未发布。单独提前恢复原固定摘要MySQL后，完整Maven104项通过（0失败/错误/跳过），8次资源样本中full PSI最大1.44、最低可用2826MiB，未降低阈值。原生Semgrep隔离实扫44个Java文件、发现0项，正负重跑1/0/1；源码扫描原95条已审核公开校验值单列，新增阻断0；ZAP回环标准测试卡号样例已真实触发10062 High。新提交将Node测试并发设为1，并在测试JVM之前准备、核验MySQL原摘要；所有测试保留。

这些独立验证不能替代尚未通过的完整新CI。签名策略、真实Secret对账、候选镜像签名、发布后业务DAST仍须经完整CI实跑与独立复核。本轮新建测试容器/卷与候选源码副本已按所有权核对后回收，密钥恢复原件和执行证据保留；旧apt缓存仍未获得新增清理授权，因此未删除。
