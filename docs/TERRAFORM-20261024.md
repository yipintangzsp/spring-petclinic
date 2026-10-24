# Terraform CLI 安装与验收 · 2026-10-24

服务器192.168.64.11（原身份192.168.1.58），Linux ARM64。已有1.7.0，本轮保留原二进制后安装官方稳定版1.17.0。入口/usr/local/bin/terraform，版本副本/opt/terraform/1.17.0/terraform，旧版/opt/terraform/1.7.0/terraform。无需常驻服务、Pod或访问域名。

官方来源：[版本目录](https://releases.hashicorp.com/terraform/1.17.0/)。安装包terraform_1.17.0_linux_arm64.zip的SHA256与同目录官方SHA256SUMS一致：f32478134ffc6d710eec474bbd316652cdddc0f4e336973a3745e8d3a3309cdf。本轮校验HTTPS获取的摘要，未执行GPG签名验证。安装后二进制SHA256：aa811293314ba9cdcd7519df5b5dd3c1a28feece1d1390d7844fea039e6f9782；保留旧二进制摘要90d689e317ae30d1c04bdd872d66bd8663f95609975ca13a1788ee7f06548cd8。

## 实际验收

/home/zhang/terraform-labs/cli-smoke-20261024 保存配置及version.json、init.log、validate.log、plan.log、apply.log、replay.log。目录由当前用户持有，umask077。本地terraform_data内置资源不使用外部provider，不连接云API，不创建Kubernetes资源。

- fmt -check、init、validate成功。
- 保存计划后apply成功：1 added、0 changed、0 destroyed；仅更新本地Terraform状态。
- 第二次plan -detailed-exitcode返回0，输出No changes，验证幂等。
- 本轮未配置Jenkins Terraform阶段、远端状态后端、Kubernetes provider或基础设施接管；不得把CLI验收写成平台资源自动化验收。

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
