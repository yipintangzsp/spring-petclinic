# DevSecOps 门禁与发布验收 · 2026-10-26

## 完整发布与独立复验结果

Jenkins **#207 SUCCESS**，完整执行1115.979秒。源码 `c68a142a6135c818c42103651c55b65239e1922a`；经私有GitLab正常promotion产生 `84d8ead98969861507f0edc6ce7a4e77c0e5360b`，版本 `0.10.0-ci-207`。Argo正常同步发布，未绕过原测试、Sonar、Harbor或GitOps流程。

|验收项|本轮实际结果|
|---|---|
|合规/违规准入|合规允许，7种违规均被指定Kyverno策略拒绝；仅server dry-run，不创建危险Pod|
|真实源码扫描|发现原始95项，逐项核验95项公开校验值误报，真实泄漏0；合成密钥拦截及空目录放行均通过|
|扫描隔离|有效UID65532、无token、根目录实际写入拒绝，可信Pod canary前后可达而扫描Pod连续两次被阻断；本轮节点API TCP不可达，但不据此宣称宿主防火墙隔离|
|扫描资源及回收|Pod source-207-849639，cgroup内存峰值132.42MiB，正常结束回收，最终扫描Pod0|
|SBOM|CycloneDX1.6，143组件、144依赖节点，JAR内外字节一致；SHA256 b0a9ab3d854212e8ff6ace34cfd683775ce32cac955b9d41e038dca78dc2b3f3|
|GitOps|22个CRD原生条件通过，实际策略spec与固定源码一致，Synced/Healthy；同步后重新执行准入测试|
|AMD64/ARM64 Harbor|两种架构各Critical0、High0、Medium53、Low4，原始57项；本轮fixable0，不声称全部漏洞清零|
|实际业务发布|3/3副本、BUILD_NUMBER207、UID10001、RuntimeDefault；实际根目录写入拒绝，临时目录写入/读取/删除成功|
|业务HTTP|首页、owners/find、vets、actuator/health均200，健康UP|
|消息与既有隔离链|RabbitMQ release-207事件成功消费；Kafka petclinic-release-v09发布事件delivered=true；Terraform独立plan、共享状态和失败/重试/超时清理均通过|
|监控|Grafana devsecops-control看板HTTP200、5面板；数据源查询HTTP200、控制器up=1|
|最终恢复|Jenkins非quiet且无运行构建，重任务Lease不存在或空，扫描Pod0，Spark Operator/Webhook保持Ready|

双架构索引摘要：`sha256:c8160221d55311268ae8654ffa7289ee9bffefea378dc8a0b43190e090c43ee1`。独立运行时检查的业务镜像与本轮扫描/发布证据完全一致。

## 资源实测与证据位置

#207全程42次资源样本：VM MemAvailable最低7678MiB，根盘空闲最低56986MiB，Mac内存余量最低36%，swap最大增长283.44MiB，未触及原512MiB停止线。结束后三次复查：VM可用约8.77GiB、根盘55.61GiB，Mac数据盘约56.73GiB、内存余量40%；CPU requests4645m/6000m。Kyverno实测15m/112MiB（单次top），扫描峰值132.42MiB。测量值不代表未来资源承诺。

私有原始证据目录：`/Users/zhangsir/Documents/New project/devsecops-20261026`。`ci-207/`保存完整阶段、控制台、42次资源记录和本轮Jenkins JSON归档；`final-server-audit.json`记录实际Pod/HTTP/Grafana；`final-resource-audit.json`记录最终资源与锁。失败201–205、中止206及205 safety-stop原件均保留；206按用户临时排查链路追踪要求正常中止，不记作功能故障。链路追踪的独立可访问性与同TraceID三存储对照另存`tracing-access-20261026`，未改已有hosts/Ingress。

## 本轮范围

在既有私有 GitLab、Jenkins、SonarQube、Registry/Harbor、Argo CD 发布链上增加源码泄漏扫描、生产依赖 SBOM 核对、隔离任务准入校验和发布证据关联。现有 Terraform 隔离、RabbitMQ/Kafka 业务链和按需分析流程保留。本轮不是全平台安全认证，也不替代此前分析验收记录。

新增常驻服务只有 `devsecops-system/kyverno-admission-controller`：Kyverno 1.19.2、官方 chart3.9.2、固定镜像摘要，单副本 Recreate。requests100m/192Mi，limits500m/512Mi；后台/报告/清理控制器关闭。`devsecops-execution` Gitleaks8.30.1 扫描 Pod 按需创建，requests100m/256Mi、limits1CPU/512Mi，600秒截止，只允许一个Pod、零PVC。结束按本次UID回收。SBOM复用已嵌入应用JAR的CycloneDX，不新增常驻服务。

## 门禁与证据

1. 原测试、质量门和重任务锁保持；扫描复用外层 Lease，不重复申请同一锁。
2. 实际 server dry-run：合规Pod允许；可变镜像、hostNetwork、hostPath、提权、缺失limits、token挂载、root身份七种违规被指定策略拒绝。
3. 扫描当前 Git HEAD 归档，不宣称覆盖全部Git历史。传源码前，验证Pod级网络探针连续两次阻断，且可信端探针前后可达；实际验证非root、无token、根目录只读。节点API TCP可达性独立记录，原生NetworkPolicy不等于宿主防火墙。
4. 随机合成的未签发token必须被检出，空目录必须放行；业务源码扫描结果保留原始计数及逐项误报。95项公开校验值（91项Helm SHA256、4项Go h1）按精确路径、规则和整行SHA256核对，不作目录或规则级忽略。新增/变化匹配仍阻断。
5. 逐字节核对JAR内 `META-INF/sbom/application.cdx.json` 与构建目录，验证CycloneDX1.6、组件唯一引用和非空依赖图。此为Maven生产依赖清单，不是全部OS软件清单。
6. GitOps固定源码commit，验证22个CRD原生Established/NamesAccepted、策略spec与Git完全一致，再执行准入负例。不忽略spec差异或更改全局健康规则。
7. 绑定源码、SBOM摘要、双架构镜像摘要及Harbor真实结果。证据目前未签名，不宣称Cosign或SLSA认证。
8. 业务候选在隔离命名空间审计；生产webhook未全局启用。经原Git Promotion后，实际业务启用只读根、RuntimeDefault、fsGroup10001与128Mi临时目录，须再验证HTTP和运行时行为。

## 失败历史与资源保护

201因原NoHttp测试发现重复地址字面量失败；202发现多文档部署解析错误；203探针发现节点API并非可靠的原生NetworkPolicy隔离边界；204发现策略默认值和Argo追踪标签漂移。均保留失败证据并修正实现，没有关闭原门禁。

205的新安全门禁、GitOps、双架构镜像及扫描均通过，但在Worker发布阶段，Mac swap较本轮起点增长约642MiB，超过原512MiB停止线，受控中止，不能标为完整发布成功。临时扫描Pod和Lease已回收，主业务继续运行原200版。结束后仅回收一次干净客机页缓存；没有删除持久文件，也不将约6.2GiB缓存逻辑大小写成净释放量。随后全新五次准入采样通过，才重新运行完整流水线。所有原资源阈值保持，不设置定时清缓存。

## 操作与排查

在 `jenkins.devops.local/job/petclinic-ci/` 选择 Build Now，执行整条链。不得直接从部署阶段跳过安全门禁。查看DevSecOps各阶段、测试报告、Console及 `.devsecops/*.json`：source-gate、admission-gate、business-template-audit、sbom-summary、gitops、release-evidence与cleanup记录。凭据/原始匹配文本不归档。

Grafana `grafana.devops.local/d/devsecops-control/` 提供控制器up、策略结果、内存、扫描CPU及范围说明。已有业务/发布/分析看板保留。

```sh
kubectl -n devsecops-system get pods
kubectl -n devsecops-system logs deploy/kyverno-admission-controller
kubectl get clusterpolicy devsecops-workload-contract
kubectl -n devsecops-execution get pods,resourcequota,networkpolicy
kubectl -n argocd get application platform-devsecops
```

发现真实密钥时先撤销/轮换并修复源码，再从头重跑；不要把真实泄漏加入误报清单。策略拒绝先核对具体规则与Pod模板，不全局关闭Webhook。扫描超时/网络探针失败先查对应记录和CNI，不放宽阈值。资源停止必须保留原样本，确认无运行中任务、锁已恢复并连续重新准入，才开启新一轮。

业务回滚沿用Git审查及Argo链：对明确的业务promotion提交作可审查回退，经原发布流程处理，不直接覆盖数据库或PVC。未知UID资源保留证据，不批量删除。控制器是单副本，升级短时不可用会阻断扫描命名空间的新任务；生产尚未挂该Webhook。ClusterPolicy API已deprecated，升级到移除旧API的版本前需迁移并重新验收。

## 未覆盖的能力

生产全命名空间准入、宿主防火墙、运行时威胁检测、集中漏洞处置、专用密钥管理/静态加密、签名准入、认证业务DAST和外部通知送达未因本轮被标为完成。Harbor必须同时报告严重级别及原始数量，不将扫描成功写成漏洞清零。
