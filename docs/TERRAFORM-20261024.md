# Terraform CLI 安装与验收 · 2026-10-24

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
