# Petclinic 流水线修复 · 2026-10-02

## 故障与修复

Jenkins #83 在构建、测试、双架构推送、仓库验证和 Git promotion 后，等待 ArgoCD Synced + Healthy 超时。UCloud 通过 SSH TUN 传输镜像存在停滞，节点 Ready 不能保证下载正常。

- Alibaba 原隧道密钥的 `permitopen` 仅授权 `10.0.0.3:6443`。在同一条受限密钥配置上增加精确的 `10.0.0.3:30050`，保留其强制命令、禁止 PTY/agent/X11 等其他限制。原文件备份为 `/root/.ssh/authorized_keys.bak-petclinic-20261002`。
- UCloud 新增 `k3s-registry-forward.service`，使用原密钥和已验证 known_hosts；监听 `127.0.0.1:13050`，独立 SSH TCP 转发到仓库。仅将本机发往 `10.0.0.3:30050` 的 TCP 重定向到该端口；启动恢复规则，停止移除规则，启用开机启动和失败重启。不开放新的公共监听端口，不修改容器仓库名称或 Kubernetes manifest 中的镜像地址。
- UCloud 的 HTTP-only registry 配置带有 `insecure_skip_verify` TLS 选项，导致 kubelet 的 CRI 路径先尝试 HTTPS。备份 `/etc/rancher/k3s/registries.yaml.bak-petclinic-20261002` 后移除这两个 HTTP registry 的 TLS 选项，保留原 endpoint 和 auth，并重载 k3s-agent。
- Jenkins Git 同步阶段仍要求 Synced 与精确的 promotion revision，随后检查线上镜像；副本健康在 Rollout Verify 中检查，要求 rollout 成功且 Argo Healthy。并未忽略健康失败。
- rollout 的 600 秒等待与 Deployment 默认进度期限对齐；Argo 健康缓存额外等待最多 120 秒。保留三副本、滚动更新策略、节点调度和探针。
- 每段 Jenkins shell 经 `sh -n` 验证。最终还必须重新运行真实流水线，不能用语法检查或已有健康部署替代。

## 验证结果

UCloud 实际拉取已成功，约 13.6 秒；服务重启后仓库访问正常。#84 在 Test 阶段发现前次验收文档的 HTTP 链接违反 NoHttp 规则，已改为服务主机名，未关闭规则。本地 `./mvnw -B clean test` 成功：79 项测试，0 失败/错误、2 跳过；Checkstyle 0 违规。Jenkins #85 全阶段 SUCCESS，81 项测试全部通过且无跳过，三个节点上的新副本都已就绪。由于 registry 配置在 #85 运行期间才修正，继续以 #86 验证配置从头生效时的全自动发布。历史失败记录不重写。

## 回退

停止并禁用 UCloud 的 `k3s-registry-forward.service` 会移除该服务的 OUTPUT 重定向；恢复 Alibaba 的 authorized_keys 备份可撤销仓库端口授权。恢复 UCloud 的 registries.yaml 备份并重载 k3s-agent 可回退 HTTP registry TLS 选项修正。Jenkinsfile 可通过普通 Git revert 回退。数据库无需回退。
