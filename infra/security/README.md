# DevSecOps：隔离扫描、依赖清单与准入

新增单副本 Kyverno 1.19.2 / chart3.9.2，官方ARM64镜像按摘要转存现有Registry。控制器 requests100m/192Mi、limits500m/512Mi；单副本Recreate，仅为学习平台，不提供高可用。CRD来自固定SHA256的官方chart；values与controller.json一并保留。关闭后台扫描、报告/清理控制器和额外Grafana，复用现有观测平台。

`devsecops-execution`只允许1个Pod、无PVC，扫描Pod无服务账号token、只读根、非root、RuntimeDefault seccomp、丢弃ALL capabilities，default-deny网络。Gitleaks8.30.1按官方ARM64摘要固定，CPU100m/1、内存256/512Mi，600秒截止；扫描仅接收本次Git HEAD归档，不挂宿主、业务Secret或PVC。扫描复用外层platform-heavy Lease，不申请第二把锁。

流水线先用真实server dry-run验证合规允许和7种违规拒绝，再真实扫描完整Git HEAD；每轮用随机合成GitHub token验证泄漏拦截，并验证空目录允许。仅归档脱敏规则/位置/指纹，不归档token或原始匹配文本。发现真实泄漏即失败，不自动建立忽略基线；95条已人工核对的Helm SHA256/公开Go h1校验值按文件路径与完整行SHA256精确识别，原始计数与逐条误报保留，新增或变更内容仍阻断。异常finally和Jenkins post只按本次UID清理。未知替换对象保留并使构建失败。

CycloneDX2.9.1生成生产Maven依赖SBOM，验证1.6版本、非空组件、唯一bom-ref及依赖图；不把它当作整个镜像/平台的OS清单。release-evidence.json将SBOM SHA256、源码commit、双架构镜像摘要、Harbor结果和门禁结果绑定；目前为未签名证据，不声称实现Cosign签名验证。

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

Grafana看板UID `devsecops-control`，复用既有Prometheus数据源，不增加看板Pod。
