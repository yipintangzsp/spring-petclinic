# Security Manager V2 可视化交付

实际运行地址：<http://127.0.0.1:17862>。仅从当前 Mac 访问。最终 HTTP 验证：2026-11-05 14:06:26 +08:00，页面与 API 均 200；19 项 HTTP 定向验收 PASS，0 FAIL。服务保持运行；start/stop/restart 已实际验证。当前 Work 设置禁用浏览器自动化，未宣称完成浏览器视觉验收。

采用本地 Node.js 只读页面。Grafana `/api/health` 200，但当前未认证 `/api/user`、`/api/datasources` 401，因此未执行 Dashboard 导入、未申请管理员权限、未覆盖既有面板。

页面固定读取 10 个封存场景、30 条三插件记录。默认最近三插件完整执行的 Service 项目；可选择更晚的身份拒绝记录、Java 正例、Gitleaks/Semgrep/Cosign 真实受控负例、显式禁用、超时和不可用记录。Policy 决策直接来自原始结果，没有重新运行工具或求值。禁用、错误等状态没有伪造 PASS。REAL 指历史受控真实工具执行，当前页面展示方式为 REPLAY，Cosign 仅离线 Blob 验签。所有场景保持原始 run 边界。

Router 区显示实际归档回执与来源：Loki ACKNOWLEDGED（HTTP 204）、Dojo HTTP ACKNOWLEDGED，均为独立历史 MOCK 协议测试，真实远端投递仍 NOT_TESTED；不与所选插件拼为 same-run 16/16。

HTTP API 仅输出允许字段：状态、身份、时间、摘要和固定来源路径；不提供原始 findings、凭据或任意文件下载。校验封存 summary/result/raw 哈希、结果自身 digest 和绑定。缺失/损坏时 UNAVAILABLE。19 项验收覆盖真实正负例、禁用与错误区分、同源/只读边界、敏感字段检查。1,001 个相关历史 JSON 文件的内容、mode、ctime、mtime 前后未变；此范围检查不修复 ORIGINAL_EVIDENCE_INTEGRITY=FAILED。

生产只读快照 14:04:59 +08:00：三节点 Ready、PetClinic 3/3、HTTP 200、Argo Synced/Healthy、socket 0660。Deployment UID/generation/spec/image 与历史基线一致。Jenkins #270 SUCCESS，14:06 同口径核对 job 配置及 V1 Summary 哈希一致。REST config.xml 与历史 configFile.asString() 的表示哈希不同，已另以历史原方法核对，不能据不同表示判定配置发生变化；对应原始观察均保留。未执行任何生产写入、扫描、镜像变更、发布或 rollout。

启动/停止/重启见 `infra/security/manager-v2/view/README.md`。回滚只需 stop 本地服务，不需要恢复生产配置。运行状态文件在当前用户临时目录，不安装开机任务。

未接通：生产 Manager、Jenkins V2 Real CI、Trivy/Dojo runtime、真实 Loki/Dojo 投递、Grafana V2 真查询和 Summary V2。Canonical Runtime 保持 14/16。下一步仅允许用户使用页面确认展示内容；本轮到此停止。
