# 2026-10-08 续接检查与准确停点

本记录继承 INCIDENT-20261008.md；旧报告是历史停点，不能继续当成当前状态。未宣称本轮完成主机根因修复或发布新版本。

## 仓库与访问

检查仓库及 /、/Users、用户目录、code 父目录，未找到适用 AGENTS.md；仓库内部搜索也无结果。保留 README.md、docs/ALIYUN-MEMORY-CHANGE-PROPOSAL.md、infra/observability/proposed/aliyun-memory-budget.yaml 的既有未提交修改。

终端和 192.168.1.58 的 SSH 可用。当前工具没有上一轮 cua_repl 桌面入口；macOS 拒绝 osascript 辅助访问，Chrome Apple 事件 JavaScript 仍关闭。复核时 Chrome 标签列表没有阿里云 VNC。没有开启权限、绕过限制或提取浏览器/Termius 凭据。

之前浏览器 URL 指向 cn-beijing/i-2ze32e4b6zvj9ybatuo2；devops 的 WireGuard peer endpoint 为 47.93.213.70:51820，Kubernetes aliyun-worker InternalIP=10.0.0.1。仍需通过 ECS 实例详情或主机 metadata 同时核对 instance-id、公网 IP、machine-id；尚不能只凭打开的 URL 宣称身份已完整核验。

本轮后续 SSH 47.93.213.70 已进入认证，root/ubuntu 的现有密钥被拒绝。旧“SSH 超时”不能继续作为当前结论。没有确认 sshd 实际配置、封禁规则、安全组或 relay 系统日志，不能把两节点归为同一根因或据 NotReady 认定 OOM。

## 已重新验证的实际状态

- 14:16 UTC 的审计显示三个节点 Ready。Aliyun Ready transition=12:19:45 UTC，UCloud=13:53:01 UTC；当前 Lease 持续更新。transition 时间本身不替代持续采样。
- Jenkins #112 SUCCESS，构建源码为 061a4a6baf48ad40f4352da82a0f06e5727d62cf，版本 0.9.0-ci-112；远端 GitOps 提交 d4b99da8374c0c7abdd85fe80a492bb9601ab750。该构建已在本轮复核前完成，不属于本轮新构建，也未包含 3f9e0a6。
- Argo 当前 Synced/Healthy，revision=d4b99da。更早快照曾为 Unknown/Healthy，后续审计无 conditions，分别保留证据。
- PetClinic 3/3、无新增容器重启，仍全部位于 devops。hostname 分散为 ScheduleAnyway 软约束，不能宣称三节点副本高可用。
- 业务七个入口及 health/readiness/liveness/prometheus 为 HTTP 200；env/loggers/configprops 为 404。数据库聚合数量 owners=200、pets=350、vets=20、visits=1200；未写业务数据，SQL 初始化配置未改。
- PetClinic 三个 Prometheus target UP；两个 worker 的 kubelet、cadvisor、probes、node-exporter target 均 UP。Loki 有近期业务日志，两个 worker Alloy 均 2/2 Running。上述健康不证明所有日志采集链路长期无错。
- Aliyun Alloy Pod 和 UCloud Trino Pod 的 DNS/Service 检查均取得 PetClinic readiness UP。UCloud 直连 Service IP:80、Pod IP:8080 返回 200，API Service 和 10.0.0.3:6443 返回未认证 401，证明网络/TLS入口可达，不代表使用了有效 API 凭据。
- 初次探测误用 Service:8080，已更正实际 Service:80；后续短超时域名请求曾解析超时。绝对域名重测取得 200；没有据错误端口诊断网络故障。
- API 中旧 PetClinic、两个 audit、旧 Trino 删除对象已消失；当前 Trino worker Running，归属原 ReplicaSet，挂载仅 ConfigMap/projected，没有 PVC。本轮通过已授权 Kubernetes node proxy 读取两个 kubelet 的 runningpods：旧 PetClinic、audit e/f、旧 Trino qcc6v 均不在实际运行 Pod 列表，当前 Trino UID与API相符。仍缺主机 crictl 与孤立进程/挂载核验，不能将此结果扩大为完整主机清理验收；本轮没有强删或清理它们。

## 尚未达到基础设施完整验收

Trino worker 日志仍持续出现 discovery announce 的 3000ms 超时。UCloud 到 coordinator 的四条只读 HTTP 路径均成功，但采样总耗时约 1.1–1.7 秒；DNS 查询约 0.5–1.0 秒。devops 的有界抓包记录重复 TCP 序列/ACK 和延迟，说明需要继续调查路径质量，尚不足以定位隧道、主机资源或特定丢包位置。CoreDNS 同时有其他域名上游查询超时；不能直接将这些日志认定为 Trino 本次超时根因。

保留 trino-path-latency.txt、trino-dns-tcp-packets.txt、runtime-selected.txt。抓包限时 20 秒、最多 120 包，仅文本协议头摘要，没有保存业务请求正文，没有修改路由、防火墙、DNS 或全局参数。随后在原 coordinator 中运行只读 SELECT system.runtime.nodes，确认 coordinator 与新 UCloud worker 均 active；这证明当前查询/发现可用，但不能消除持续 announce 超时证据。

SSH/TUN 当前 unit、tun0、路由和 NRestarts 尚未取得主机证据；RestartSec=30s 是上一轮已验证的缓解项，当前不能声明它已带来长期稳定。Ready/Lease 连续采样单独记录，不等同于隧道根因闭环。

## 本地发布准备

审查 3f9e0a6 的六个文件：两次发布前检查、Lease 推进、有效 Pod/Endpoint UID 关联、错误非零退出及证据归档符合原范围。节点与 Lease 即时检查不覆盖 DNS、隧道质量、跨节点业务分布，因此不能凭该检查通过放行本次完整恢复验收。

当前 24 项 Node 测试通过（preflight/rollout/GitOps 共20项，service-readiness 4项）；真实 Jenkins 容器内 preflight 返回0，7次样本、约30秒，三个节点 Lease 有推进。沿用上一轮 Jenkinsfile linter 的成功证据；本轮未声称重新执行 linter 或完整 CI。

git fetch 发现本地 3f9e0a6 与远端 d4b99da 分叉。确认远端仅更新 #112 镜像/版本/构建追踪五字段后，使用正常 merge 生成 076d3ee，保留 3f9e0a6 SHA 与既有工作区修改。合并前 HEAD 及既有修改 patch 已在 continuation 证据目录保存。未推送，也未触发新 Jenkins。

45行 relay-console-readonly.sh 已逐项审查并通过 bash -n，保留原文件。它不修改服务或配置，不打印 WireGuard 私钥；缺失工具会报错后继续。sshd -T 的默认结果不能覆盖 Match 条件，拿到实际连接用户/源地址后须补查 sshd -T -C；ECS安全组需在控制台另查，metadata访问失败不能据此判断实例身份。

## 恢复执行顺序与回滚

取得已授权的主机管理入口后，先核对 ECS 身份、sshd 监听/配置和日志，再读取隧道 unit、tun0、路由、NRestarts、agent及OOM日志。日志证据确认后才修改，每次先将受影响文件保存到权限0600的主机备份目录，验证新配置语法，限定重启单个必要服务。禁止清空防火墙、全机重启或批量强删。

在 UCloud 对照当前 Trino ReplicaSet/Pod UID、crictl 容器及 sandbox、挂载和进程，确认旧实例实际状态。针对 Trino announce 延迟先在两个隧道端限时对齐抓包、检查丢包/重传/MTU和资源，再决定定向修复；不单纯增大超时掩盖故障。

主机证据和持续网络验证通过后，再评估副本分布、推送可靠性提交、按0.9.0-ci-${BUILD_NUMBER}规则执行完整Jenkins并观察发布。线上回滚走Git revert/promotion，由Argo收敛，保留数据库/PVC。3f9e0a6 尚未上线，无线上回滚动作。撤销本地合并如有必要，优先正常 revert 076d3ee 的第二父侧变更并审核清单，禁止用 hard reset 覆盖既有工作区。

业务下一项尚无明确已约定功能规格。基于现有未来就诊日期和Visit模型，候选为只读“就诊计划总览”：日期范围、主人/宠物搜索、分页、从结果进入现有详情及新增就诊；复用现有表和数据，不创建预约第二套模型或自动迁移生产库。这里只记录准备方向，未实施/发布，也未把它表述为历史已约定计划。待基础设施完整验收后，补齐控制器/查询/页面交互测试及桌面手机验收，再交付真实页面变化。

## 持续观察结果

北京时间 2026-10-08 22:18:56—22:28:56（UTC14:18:56.676691—14:28:56.723513），41次采样，跨度600.046822秒。两个worker每个节点均41个不同Lease时间，全部Ready；HTTP失败0/41，最低availableReplicas=3，最低Ready Endpoint=3。没有发生新发布，不能将此窗口当作新版本滚动发布零中断证明；也没有主机NRestarts采样，不能将Ready/Lease稳定扩大为SSH/TUN长期稳定验收。

结果保存为 observation-summary.json 和 continuity.jsonl。完整本地证据：evidence/2026-10-08/continuation/。主机侧取证缺口和Trino超时未消除前，停在推送之前。
