# Petclinic 流水线修复 · 2026-10-02

## 故障与修复

Jenkins #83 在构建、测试、双架构推送、仓库验证和 Git promotion 后，等待 ArgoCD Synced + Healthy 超时。UCloud 通过 SSH TUN 传输镜像存在停滞，节点 Ready 不能保证下载正常。

- Alibaba 原隧道密钥的 `permitopen` 仅授权 `10.0.0.3:6443`。在同一条受限密钥配置上增加精确的 `10.0.0.3:30050`，保留其强制命令、禁止 PTY/agent/X11 等其他限制。原文件备份为 `/root/.ssh/authorized_keys.bak-petclinic-20261002`。
- UCloud 新增 `k3s-registry-forward.service`，使用原密钥和已验证 known_hosts；监听 `127.0.0.1:13050`，独立 SSH TCP 转发到仓库。最终将两个 CRI mirror endpoint 显式改为 本机 13050 端口的 HTTP endpoint，启用开机启动和失败重启。先前尝试的 OUTPUT 重定向已撤销，最终服务不依赖 NAT 规则。不开放新的公共监听端口，不修改容器仓库名称或 Kubernetes manifest 中的镜像地址。
- UCloud 的 HTTP-only registry 配置带有 `insecure_skip_verify` TLS 选项，导致 kubelet 的 CRI 路径先尝试 HTTPS。备份 `/etc/rancher/k3s/registries.yaml.bak-petclinic-20261002` 后移除这两个 HTTP registry 的 TLS 选项，保留原 endpoint 和 auth，并重载 k3s-agent。
- #86 在获取 Jenkinsfile 前因 GitHub SSH 22 端口超时失败。Jenkins 持久卷中的 `.ssh/config` 针对 `github.com` 改用官方 `ssh.github.com:443`，保留严格主机密钥验证。443 端口 ED25519 密钥指纹已与 GitHub 官方文档及既有信任的 GitHub 密钥核对一致；未更换部署密钥。
- Jenkins Git 同步阶段仍要求 Synced 与精确的 promotion revision，随后检查线上镜像；副本健康在 Rollout Verify 中检查，要求 rollout 成功且 Argo Healthy。并未忽略健康失败。
- rollout 的 600 秒等待与 Deployment 默认进度期限对齐；Argo 健康缓存额外等待最多 120 秒。保留三副本、滚动更新策略、节点调度和探针。
- 每段 Jenkins shell 经 `sh -n` 验证。最终还必须重新运行真实流水线，不能用语法检查或已有健康部署替代。

## 验证结果

UCloud 实际拉取已成功，约 13.6 秒；服务重启后仓库访问正常。#84 在 Test 阶段发现前次验收文档的 HTTP 链接违反 NoHttp 规则，已改为服务主机名，未关闭规则。本地 `./mvnw -B clean test` 成功：79 项测试，0 失败/错误、2 跳过；Checkstyle 0 违规。Jenkins #85 全阶段 SUCCESS，81 项测试全部通过且无跳过，三个节点上的新副本都已就绪。由于 registry 配置在 #85 运行期间才修正，#86 暴露出 GitHub 22 端口超时，已修复；继续以 #87 验证配置从头生效时的全自动发布。历史失败记录不重写。

## 回退

停止并禁用 UCloud 的 `k3s-registry-forward.service` 会移除该服务的 OUTPUT 重定向；恢复 Alibaba 的 authorized_keys 备份可撤销仓库端口授权。恢复 UCloud 的 registries.yaml 备份并重载 k3s-agent 可回退 HTTP registry TLS 选项修正。Jenkinsfile 可通过普通 Git revert 回退。Jenkins 的 GitHub 连接可通过恢复 `.ssh/config.bak-petclinic-20261002` 回退；此前没有 config 时存在 `config.bak-petclinic-20261002-empty` 标记。数据库无需回退。

官方连接说明：[GitHub SSH 443](https://docs.github.com/en/authentication/troubleshooting-ssh/using-ssh-over-the-https-port)。

## 稳定性限制与生产调度

#87 在全部阶段 SUCCESS 后，页面复查仍发现跨云请求间歇超时。阿里云在新旧副本并行期间停止上报节点状态，原因尚未确认，不能直接归因于 OOM；需合法 SSH 连接继续排查。新副本由 Kubernetes 自动迁移到了健康节点。UCloud 的 TUN 仍有丢包，尽管本地和云上 Pod 的健康接口均可返回 UP，大页面访问不能据此视为通过。

生产 Deployment 因此明确固定到 `devops`，保留三个副本、已有镜像和发行指纹；通过普通 Git 提交及 ArgoCD 生效。此举不提供跨节点容灾，恢复多节点前必须先通过节点及 Pod 网络验收。数据库和视觉代码无需修改。

UCloud 的显式本机 CRI mirror 已加载，`k3s crictl pull` 成功。最终需要重新核对生产页面和三副本状态。阿里云旧的两个 Terminating Pod 不强制删除，须在确认实际节点进程状态后处理。
