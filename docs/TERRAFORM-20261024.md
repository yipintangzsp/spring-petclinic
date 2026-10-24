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
