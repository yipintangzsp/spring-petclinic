# Terraform 平台接入与远端状态验收 · 2026-10-24

> 最新：#190完整发布与Terraform Shared State验收成功；Kubernetes远端状态、真实写锁竞争、跨目录零变更、短期受限身份和越权403均通过。旧本地状态未迁移。K3s静态加密仍关闭，Jenkins引导身份仍具管理员权限；本轮不宣称完整执行隔离。

> Jenkins接入及真实生命周期已完成：#189 SUCCESS，受检源码f161884266dfdad49e6704c4b651f169d031b4b0。Terraform Plan阶段生成并核对3个隔离create，未自动apply；发布通过后，1.17.0实际创建/幂等/非法输入拒绝/漂移修复/精确清理均通过。下文初次CLI安装状态为历史阶段。

服务器192.168.64.11（原身份192.168.1.58），Linux ARM64。已有1.7.0，本轮保留原二进制后安装官方稳定版1.17.0。入口/usr/local/bin/terraform，版本副本/opt/terraform/1.17.0/terraform，旧版/opt/terraform/1.7.0/terraform。无需常驻服务、Pod或访问域名。

官方来源：[版本目录](https://releases.hashicorp.com/terraform/1.17.0/)。安装包terraform_1.17.0_linux_arm64.zip的SHA256与同目录官方SHA256SUMS一致：f32478134ffc6d710eec474bbd316652cdddc0f4e336973a3745e8d3a3309cdf。本轮校验HTTPS获取的摘要，未执行GPG签名验证。安装后二进制SHA256：aa811293314ba9cdcd7519df5b5dd3c1a28feece1d1390d7844fea039e6f9782；保留旧二进制摘要90d689e317ae30d1c04bdd872d66bd8663f95609975ca13a1788ee7f06548cd8。

## 实际验收

/home/zhang/terraform-labs/cli-smoke-20261024 保存配置及version.json、init.log、validate.log、plan.log、apply.log、replay.log。目录由当前用户持有，umask077。本地terraform_data内置资源不使用外部provider，不连接云API，不创建Kubernetes资源。

- fmt -check、init、validate成功。
- 保存计划后apply成功：1 added、0 changed、0 destroyed；仅更新本地Terraform状态。
- 第二次plan -detailed-exitcode返回0，输出No changes，验证幂等。
- 初次CLI安装只做本地验收；后续Jenkins和隔离Kubernetes生命周期结果见下节。尚未配置团队远端状态后端或接管现有生产资源。

## 使用

```sh
ssh -o HostName=192.168.64.11 -o HostKeyAlias=192.168.1.58 zhang@192.168.1.58
terraform version
cd ~/terraform-labs/cli-smoke-20261024
terraform validate
terraform plan
```

新增实验应在独立目录中，先plan审查。状态和保存计划不提交Git，凭据不写入配置；该示例为本地状态，无团队远端锁能力。现有Argo管理资源仍由Argo负责，不以Terraform重复接管。需要旧版时可显式执行/opt/terraform/1.7.0/terraform，不用旧版读取新版状态；本轮未进行状态降级测试。

## Jenkins 接入实施

新增Terraform Plan阶段，位于Test之后、Package之前，复用已持有的共享重任务Lease，不重复申请锁。固定1.17.0 CLI在Jenkins持久工具目录，校验安装包及二进制摘要；provider沿用已锁定2.38.0。服务端控制器沿用原kubeconfig路径，Jenkins使用既有Pod服务账号；未增加集群权限，现有账号权限较大，不宣称最小权限验收。

CI只生成并检查隔离实验的3个create，不自动apply：命名空间tf-devops-lab、禁止Pod/PVC/Secret/Service的配额、无敏感数据的ConfigMap。已有命名空间、任何update/delete/replace、越界资源或放宽配额均拒绝。完整计划及日志在Jenkins私有目录，归档只保存target/platform/terraform.json的范围、摘要、源码与构建编号。新增6项越界/删除/配额保护测试，64项Node测试及本地格式检查通过；完整发布和新版真实生命周期验收以本轮最终证据为准。

## 本轮最终结果与操作

完整Jenkins #189 SUCCESS，应用版本0.10.0-ci-189；64项Node、104项Java及41项Python测试通过，Terraform Plan、Sonar、双架构构建、Harbor扫描、GitOps、Argo和业务验收完整执行。每次普通源码发布都会执行新增Terraform阶段，且复用原重任务锁；文档收尾用两个skip标记避免重复构建。

归档在Jenkins petclinic-ci /189/artifact/target/platform/terraform.json，保存源码、CLI版本、3个资源地址/动作及计划SHA256。原始计划与日志在Jenkins容器/var/jenkins_home/terraform-runs/ci-189-Z49yL8（Jenkins持久卷，私有目录）；该预览不应跨工作目录直接apply。既有特权服务账号未新增权限，不把范围检查当作权限隔离。

真实控制器按已通过的精确源码重新生成计划并创建namespace、ResourceQuota、ConfigMap，命名空间UID为1fed5c5d-c5be-4a7b-87e5-f63a3946a4ba。首次apply为3 added，重复plan退出0；Ansible第二次changed=0，非法业务命名空间输入被拒绝且原文件摘要未变；仅把本轮ConfigMap的版本改为out-of-band，plan退出2、只提议该对象原地update，修复后plan退出0。删除前核对UID、owner、状态中3个地址、没有外来对象或Pod/PVC/Secret，然后只清理该实验3个资源；最终state为空，重复destroy计划退出0。没有创建业务Pod/PVC，没有删除原平台数据。

最终核验：实验namespace和共享Lease不存在，所有瞬时进程已停止，Jenkins恢复原非quiet状态；Spark Operator/Webhook保持1/1，Flink维持按需0。26次工具调用最大观测cgroup内存峰值129.89MiB，每步硬上限768MiB、CPU100%、最多600秒；完整流程准入1024MiB加既有安全储备，未降低资源停止线。本轮最终VM可用9.78GiB、根盘空闲45.89GiB，仅代表记录时刻。

使用入口：Jenkins的petclinic-ci普通提交/Build Now会运行完整流水线并显示Terraform Plan；查看该stage控制台和terraform.json。CI有意不自动apply Kubernetes。需要重复完整隔离实验时，从Mac现有仓库使用下列受控入口（证据路径每次换一个全新目录）：

```sh
PETCLINIC_SSH_ADDRESS=192.168.64.11 python3 infra/devops-lab/iac/run.py \
  --build 189 --revision f161884266dfdad49e6704c4b651f169d031b4b0 \
  --evidence /Users/zhangsir/code/evidence/platform-20261011/iac-manual-UNIQUE
```

运行脚本和该revision版本必须一致，且它会自行核对Jenkins源码与成功结果、获取共享锁、暂停新Jenkins重任务并在结束恢复；不要在其外面再套同一把锁。若资源不足或namespace已存在则拒绝运行，不盲目导入或删除。失败保留private error.json、current-step.json和状态目录，先核对owner/UID及外来对象再处理；禁止强删finalizer或对业务namespace执行destroy。

本轮Mac证据：/Users/zhangsir/code/evidence/platform-20261011/terraform-ci-20261024；真实state/计划/日志保留于服务器/opt/petclinic-observability/labs/iac-20261024T123113。原始计划和state均不提交Git；未设置自动清理这些私有状态目录，后续运行应监控目录增长。现阶段仍为单机本地状态，未验收远端后端、多人协作锁或生产资源接管。

## #190 远端状态、协作锁与权限控制

完整构建#190 SUCCESS，源码d1bb0fa5484ff53d266dfb7999c7d9856e0629f0；72项Node测试、104项Java、41项Python及原质量/双架构/扫描/GitOps/健康/消息发布检查通过。新增Terraform Shared State位于这些检查之后，复用已持有的共享重任务Lease，不申请第二把重任务锁，也未新增常驻Pod。原Terraform Plan阶段仍执行原v1三资源预览，旧本地state/计划/日志的15项摘要前后相同。

采用[官方Kubernetes后端](https://developer.hashicorp.com/terraform/language/backend/kubernetes)：状态为terraform-state/tfstate-default-petclinic-remote-v1 Secret，UID=fb5529e7-ee5b-48ce-a12f-5e54ca5996c6；锁为同命名空间lock-tfstate-default-petclinic-remote-v1 Lease，UID=3c9cc7e9-faa3-420f-8064-4bfbe38ad9d9。解锁后Lease对象保留但holder为空，不能把对象存在误判为仍锁定。演示ConfigMap为tf-remote-lab/environment-manifest，UID=b62c4251-3a1f-4d5f-9b8f-84bc365ecda4。bootstrap只管理2个Namespace、2个Quota、1个ServiceAccount、2个Role及2个RoleBinding；Terraform只管理自己的演示ConfigMap和本轮虚拟探针，不接管Argo资源。

两客户端在Jenkins私有目录/var/jenkins_home/terraform-runs/remote-190-WmnSzB/a、/b分别初始化；A真实apply期间，观察到锁ID d74b4edf-95e8-a2af-d473-805f05f92758，B的plan因同一锁ID明确失败，exit=1；记录Operation=OperationTypeApply且writer_was_active=true。A退出后B重试plan为0；只删除无外部资源的terraform_data虚拟探针，最终B再次plan为0。两目录读取的lineage、serial、SHA256完全相同。每轮测试会短暂创建/删除虚拟探针并增加serial；零变更指去掉探针后的固定真实资源配置，不承诺跨构建state字节不变。最终state只含演示ConfigMap：lineage=c7319894-9085-a3c1-a6f2-5cc641dfbf2c，serial=3，SHA256=84af9d857409ffea6f721a29a1aba6c516631d1ff9b3d647054204498bfe6ac5。未使用force-unlock，未删除远端Secret、演示ConfigMap或命名空间。

### 运行身份和实测权限

Terraform子进程使用system:serviceaccount:tf-remote-lab:terraform-runner，每次TokenRequest约10分钟，不创建长期token Secret。环境白名单、独立HOME和仅含API地址/公开CA的kubeconfig阻止管理员凭据回退；不向子进程传递GitLab/Harbor凭据。移除KUBE_TOKEN后，真实terraform state pull被拒绝（exit1），而不是自动使用Jenkins管理员。后台元数据、计划JSON及pull状态均检查不含该令牌。HTTP API使用集群CA校验TLS，没有insecure或跳过证书校验。

|命名空间|资源|动作|SelfSubjectAccessReview allowed|
|---|---|---|---|
|tf-remote-lab|/configmaps|create|True|
|terraform-state|/secrets|get|True|
|terraform-state|coordination.k8s.io/leases|update|True|
|petclinic|/configmaps|create|False|
|tf-remote-lab|/secrets|get|False|
|tf-remote-lab|apps/deployments|create|False|
||/namespaces|delete|False|

除上述写权限评审外，实际读取petclinic/configmaps及tf-remote-lab/secrets均HTTP403，匿名读取状态Secrets为HTTP401。Role只在两个专用命名空间生效，无ClusterRoleBinding。状态命名空间只允许该实验state，不应放其他凭据；Secret/list权限覆盖该专用命名空间，以支持后端查找及分块。

既有Jenkins管理员仍用于受控bootstrap和签发短期身份，未收回其现有权限；Terraform运行在同一Jenkins容器，环境分离不是OS沙箱，不能用于不可信多租户代码隔离。当前K3s Secret静态加密为Disabled，本次没有启用全局加密或重写已有Secrets；状态只含公开演示配置，不能将此方案描述为已具备敏感状态静态加密。现有单机控制面不是跨机房高可用，也未新增异地备份。

### 查看、重复运行与恢复

在Jenkins petclinic-ci点击Build Now或普通源码提交，完整流程末尾会执行Terraform Shared State。归档target/platform/terraform-remote.json，含状态标识/摘要、两客户端动作、403及锁竞争证据，不含state内容或令牌。演示ConfigMap和远端state会保留供下一次构建重复读取，后续不得无授权销毁。全量state快照、计划及脱敏日志保存在上述私有目录；snapshot文件摘要已在原地核对。原v1操作仍按此前手册，不能把v1旧目录直接init-migrate到新后端。

排查顺序：stage控制台TF_REMOTE_STEP→私有steps.json及a/b日志→状态Secret元数据→Lease holder/UID及当前真实进程。若锁为空可按正常流水线重试；若有活动holder，不强制解锁。中断后遗留探针、未知state资源或无state却已存在的ConfigMap会被拒绝并保留，先比对本轮source/UID/lineage/serial再恢复。state.snapshot.json为同VM私有副本；恢复需先暂停所有写入、保存当前state、核对lineage和serial，之后才审查state push；本轮未执行破坏性回滚演练。启用全局静态加密和进一步收回Jenkins管理员权限均不包含在本次变更中。

provider使用已锁定2.38.0和Jenkins共享缓存，避免每个新工作目录重复解包；已将#189包移入缓存并保留原路径及字节摘要。主机CLI入口改为指向相同摘要/opt/terraform/1.17.0/terraform的符号链接，旧版1.7.0保留。仅删除本轮/tmp安装临时包并合并重复CLI副本，净回收259.80MiB；未删镜像、卷、旧state/计划/日志。private目录仍需容量管理，没有自动删除state快照的策略。

本轮34个资源样本：VM最低可用8.37GiB、根盘最低空闲44.95GiB、Mac内存余量最低42%，未触发原停止线。最终根盘44.94GiB、VM可用9.56GiB；无新增Pod/PVC，无活动远端锁和重任务锁，Jenkins非quiet且空闲。证据目录：/Users/zhangsir/code/evidence/platform-20261011/terraform-remote-20261024。

### 不重建业务镜像的受控复跑（已通过）

资源余量接近原停止线，因此没有为第二轮Terraform验证重建业务镜像。私有操作脚本replay_accepted.py先核对Jenkins #190 SUCCESS及精确源码d1bb0fa5484ff53d266dfb7999c7d9856e0629f0，只提取该提交中已经通过检查的5个运行文件；校验复制内容，使用原HeavyRun准入/共享锁和Jenkins静默恢复，运行固定受检代码，不执行当前工作区未提交源码，不创建新Jenkins构建。

复跑目录/Users/zhangsir/code/evidence/platform-20261011/terraform-remote-20261024/replay-20261024T151533：真实ConfigMap UID、Secret UID和lineage不变，初始计划只有虚拟探针create，无真实基础设施变更；再次完成真实锁竞争与最终plan退出0，探针移除。当前serial为5、SHA256为112e24dfa4c481c01ad973d8ff8c23e47267315921a0ba79a1186f5e9a44ab22；首次CI记录的serial3是当时快照，复跑后增加到5正常，不是重复业务资源。独立API审计确认远端state现在仅1个ConfigMap条目，所有本轮进程已停止、状态锁无holder、重任务锁不存在、Jenkins恢复非quiet；旧15项state/计划/日志摘要仍相同。

在Mac运行下方命令可重复验证已验收版本（会按资源情况拒绝运行；不降低阈值）。该操作辅助脚本位于私有证据目录，不是未经检查的新应用部署；其所执行的仓库运行文件固定到#190受检提交，source-manifest.json保存字节摘要：

```sh
PETCLINIC_SSH_ADDRESS=192.168.64.11 python3 \
  /Users/zhangsir/code/evidence/platform-20261011/terraform-remote-20261024/replay_accepted.py
```

每次创建新的私有证据目录，执行期间暂停Jenkins新重任务，完成恢复。发生未知资源/锁/身份或现存探针异常时保留现场，不自动销毁状态。普通GitLab源码变更仍须走完整Jenkins流水线；此入口不能用于运行未通过检查的新源码。未来如需更换受检版本，应先完整发布并更新门禁，不手改SHA跳过检查。
