# 求职与项目交付学习平台 · 2026-10-19

平台目标是面向招聘要求、接项目和生产运维的学习覆盖。不能仅因当前 Petclinic 业务不使用某组件就排除学习安装；同样，所有组件同时常驻也不是学习完成。每项应有正常使用、失败或负例、恢复、重复执行和资源证据。

## 已完成第一项：证书生命周期

实际验收时间为 **2026-10-18 20:57:29 Asia/Shanghai**，本页于10月19日整理交付。源码 `67ee231d22ed8f4cecb540eafbc8133781dae1d8` 经完整 Jenkins **#153 SUCCESS** 发布，私有晋升提交 `caa8f6f2631f01e018aa0cfbaceb6703146c98af`。前序 #151 在部署前被 NoHttp 检查拦截；为官方 CRD 的两个 HTTP 文档示例及既有私有 GitLab 地址添加精确文件/地址例外后，#152 完整成功。第一轮监控验收仍失败，原因是 Argo 实例标签覆盖使 ServiceMonitor 选不中 Service；暂停两个新应用自动同步、修正后通过 #153，才恢复同步并完成整轮验收。失败证据保留，未把局部 HTTPS 成功写成整轮成功。

|项目|实际结果|
|---|---|
|cert-manager|v1.21.2；3个单副本控制器，适配现场 Kubernetes 1.36.1|
|cmctl|v2.6.1，Linux ARM64；官方压缩包和二进制分别校验 SHA256，安装于服务器 `/usr/local/bin/cmctl`|
|GitOps|`platform-cert-manager`、`devops-tls-lab`；独立于既有 Petclinic 入口|
|证书|命名空间 `devops-lab`，内部 CA `lab-root`、站点证书 `tls-lab`|
|HTTPS|换发前后均使用显式 CA 信任校验，HTTP200；未用跳过证书验证的方式冒充通过|
|换发与密钥轮换|revision 2→3，序列号和公钥指纹改变，Traefik 实际提供新证书；原 CA 保持不变|
|失败负例|30分钟有效期的无效请求在 server dry-run 被拒绝，未持久化无效证书或密钥|
|重复同步|两应用再次同步后，revision仍为3，未重复签发|
|监控|3个抓取目标均UP；站点证书 Ready 指标=1|
|资源恢复|Jenkins quietingDown=false，专属资源锁释放；Spark Operator/Webhook保持运行|

使用内部学习 CA，浏览器默认不会信任它。本轮没有修改系统/浏览器信任库，没有验证公网 ACME；自动续期时间已记录为 **2026-10-24 20:56:55 Asia/Shanghai**，尚未到期实测，不能把手动换发等同于定时续期已实际发生。

## 打开与重复实验

入口为 `https://tls-lab.devops.local`；该名称须使用现有本地 DNS/hosts，或用下列命令显式解析。只导出公开 CA 证书，不读取私钥：

```sh
ssh zhang@192.168.1.58 'sudo kubectl -n devops-lab get secret lab-root-ca -o jsonpath="{.data.tls\.crt}"' | base64 -d > /tmp/petclinic-lab-ca.crt
curl --noproxy '*' --cacert /tmp/petclinic-lab-ca.crt \
  --resolve tls-lab.devops.local:443:192.168.1.58 https://tls-lab.devops.local/

ssh zhang@192.168.1.58 'sudo kubectl -n devops-lab get certificates,certificaterequests,issuers'
ssh zhang@192.168.1.58 'sudo /usr/local/bin/cmctl --kubeconfig /etc/rancher/k3s/k3s.yaml renew tls-lab -n devops-lab'
ssh zhang@192.168.1.58 'sudo kubectl -n cert-manager logs deploy/cert-manager --tail=100'
```

再次执行换发会创建新的证书版本；不要删除 Secret 来换发。CA/站点私钥、数据库、PVC及原有 Kafka 数据均不属于可随意清理的实验垃圾。停止学习页面可通过 Git 将 `tls-lab` Deployment改为0；证书控制器不能在保留离线 admission webhook 时简单全部缩到0。

Prometheus中可查：

```promql
certmanager_certificate_ready_status{exported_namespace="devops-lab",name="tls-lab",condition="True"}
```

官方 ServiceMonitor `honorLabels=false`，抓取目标的 namespace是cert-manager，业务证书namespace在`exported_namespace`；不要混淆。查看 Argo 的两个新 Application、证书 Conditions/Events/CertificateRequest、三个控制器日志及监控抓取错误即可逐层排查。

## 实际资源与边界

三个控制器加Web的常驻 requests 为CPU225m、内存344Mi；内存limits合计704Mi。临时 startup API-check另外请求CPU10m/32Mi、内存limit64Mi。没有申请新的PVC；生成的CA/站点Secret仍是持久化状态。

恢复验收8次 metrics-server 采样，合计内存最大187.27Mi、CPU最大16.12m；结束时内存187.27Mi、CPU6.43m。这是采样结果，不是内核瞬时峰值，也不包含全部宿主机开销。全机CPU requests在结束时为3805m/6000m，VM可用11142Mi，根盘可用20835Mi，Mac swap2550.5→2542.5Mi；资源监控未触发停止线。

原联合分析预算若仍为5620m，加入本轮225m和250m储备将达6095m，超过本地6000m。后续分析必须重新准入并受控释放足够余量，不降低储备。已有四轮联合分析完整验收仍未完成，不因本轮证书成功而改写。

Chart来自官方v1.21.2，SHA256与官方索引一致，未验证Chart的GPG签名。Jenkins归档中的Harbor扫描覆盖Petclinic发布镜像，不能据此称新cert-manager官方运行时镜像或全平台均无漏洞。版本、imageID、原始指标、证书公钥和验收记录保存在私有证据目录，不把私钥或凭据写入仓库。

## 后续补齐顺序

|顺序|方向|现场情况与实际实验要求|
|---|---|---|
|1|证书生命周期|本轮已通过；公网ACME和到时自动续期未验收|
|2|Terraform、Ansible|已通过隔离环境创建/回收、check/diff、重复执行、非法参数拒绝、漂移发现/原地修复；见[IaC实操](IAC-LAB-20261019.md)|
|3|Argo Rollouts|未发现部署；补灰度、指标判断、失败回退与蓝绿实验，先用独立应用|
|4|Nexus|未发现部署；补Maven代理、私有制品发布与构建引用；按需开启|
|5|RabbitMQ、Nacos|未发现部署；分别补确认/重投/死信/消费幂等，注册发现/配置更新/故障恢复；分批运行|
|6|备份及Velero|已有局部备份；补独立存储与隔离恢复、内容核对、RPO/RTO，不假设所有hostPath可自动一致恢复|
|7|Vault、Kyverno、Cosign|未发现部署/工具使用证据；补授权轮换、密钥注入、策略拒绝、签名验签；先Audit再局部Enforce|
|8|Istio、分布式存储、Hadoop|未发现相应部署；纳入专题安装，优先隔离环境、按需运行，避免直接替换现有CNI/存储|

“未发现”以10月18日工作负载、Helm、CRD和仓库检查为范围；后续每项实施前再核对，避免重复安装。现有 MinIO、Airflow、Flink、Kafka UI、Zabbix等已安装但按需关闭，不能算未安装。公共云IAM/VPC、托管数据库和跨可用区容灾不能由本机模拟冒充已验证，收费资源须有具体预算和授权。

## 来源与证据

- [配置与操作说明](../infra/devops-lab/README.md)
- 私有证据：`/Users/zhangsir/code/evidence/platform-20261011/cert-lab-20261018-recovery`；前序失败保留于`cert-lab-20261018`。
- 招聘样本（10月18日查阅，不作为岗位比例统计或仍在招聘的保证）：[ShyftLabs DevOps](https://jobs.lever.co/shyftlabs/477f2323-f909-4e59-8fd8-915932d67454)、[Zingtree Platform Reliability](https://jobs.lever.co/zingtree/8cae8c0a-2f42-472c-9707-e70a69f81f54)、[应用运维校招](https://career.hznu.edu.cn/job/view/id/1026876)。
- [CNCF平台能力分类](https://tag-app-delivery.cncf.io/whitepapers/platforms/)、[cert-manager支持版本](https://cert-manager.io/docs/releases/)、[Certificate生命周期](https://cert-manager.io/docs/usage/certificate/)。

## 10月19日重启后复核

复核时节点uptime约3分钟，学习Web有一次SandboxChanged重建，lastState为Unknown/exit255，未记录OOM；节点重启根因未在本轮调查。随后使用原CA校验HTTPS返回200，站点证书仍revision3、根证书revision1，Prometheus Ready=1、Jenkins非quiet且无重任务Lease。两实验应用、Petclinic、Spark Operator均Synced/Healthy。该记录是重启后的功能复核，不是长期稳定性保证。原始证据为私有`cert-lab-20261018-recovery/post-reboot-20261019.json`。
