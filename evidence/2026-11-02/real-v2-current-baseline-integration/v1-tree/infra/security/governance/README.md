# Kubescape 与 DefectDojo 集成

本目录扩展 #250 的只读验收，不改变原有 FAIL/WARN 规则，不发布业务。

- Kubescape 4.0.17 原生 CLI 在 Jenkins 工具目录运行，单核、Go 内存目标384MiB，限时扫描 NSA 与 CIS v1.12.0。二进制与离线制品摘要在 tools-lock.json。使用30分钟只读身份，禁止读 Secret、禁止写业务；不启用 Operator、主机探针、镜像扫描或 SaaS 上传。主机层 CIS 项不可据此声称完整验收。
- 集群和 k8s/production YAML 分别保存原生 JSON。历史失败为 AUDIT。文件正反例仅验证 C-0057，不部署、不导入 DefectDojo 为真实漏洞。
- DefectDojo 3.4.301 沿用官方 Compose 拓扑，在既有 Docker 中隔离运行。单进程 Web、单并发 worker；数据库/缓存不暴露端口，保留原资源停止线。
- UI：http://192.168.64.11:18095 。账号 platform-admin；密码仅在服务器 /opt/defectdojo/bootstrap-credentials.json（root/0600）。不要提交、打印或复制凭据到工单。
- 新 CI 用户不是 staff/superuser；Open Source 3 使用 Product.authorized_users 授权，仅加入 PetClinic 产品。凭据保存在 Jenkins defectdojo-api-token。

## 数据流

Gitleaks（已脱敏原生JSON）、Semgrep、Harbor/Trivy、ZAP、SonarQube API 与 Kubescape 报告由一个导入模块统一调用官方 importer。固定产品/Engagement/Test，采用 reimport 与同步去重；同文件重复导入比较 Finding ID，不自动关闭旧发现。只有原 Gitleaks 门禁已有逐行证据的误报才同步 false-positive 状态。CI gate 失败的完整真实扫描结果仍可导入，不能用 Dojo 状态解除 Jenkins 阻断。

DefectDojo 负责实时漏洞治理；Grafana 负责流水线/运行时总览。新增 Dojo 指标是最近一次 Jenkins 同步快照，人工状态变化后的实时结果以 Dojo 为准。无需新 exporter、Operator 或采集服务。

## 运维

配置：/opt/defectdojo/compose.json；私有环境：/opt/defectdojo/.env。

```sh
sudo docker compose --project-directory /opt/defectdojo --env-file /opt/defectdojo/.env -f /opt/defectdojo/compose.json ps
sudo docker stats --no-stream
```

故障先查看本轮 Jenkins `.devsecops` 归档和 DefectDojo import/reimport Test。禁止在未核对 UID/归属前删除其他任务资源。不要把未修复、未证实问题永久标记为已修复/误报。状态流转验收仅在真实 Finding 上短暂验证后恢复，不生成假 Finding。

磁盘余量紧张，完整扫描前需检查原 15%+8GiB 停止线；不得降低阈值或擅自清理历史镜像、数据库和卷。
