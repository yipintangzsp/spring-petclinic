# 页面执行入口：安全预检已接通，真实执行仍未完成

同一服务 http://127.0.0.1:17862 ，仅当前 Mac。实际 HTTP 验证时间 2026-11-05T07:05:33.788Z，24 项 API 验收通过；既有三个 Runner 契约测试 62/62 通过。未运行重型测试或 Trivy。

新增 Live Validation Results、插件/固定场景选择、运行按钮、状态与持久化审计记录。Historical Replay Results 单独保留。新 API /api/plugins、POST /api/run、/api/runs/:runId 已实际访问。固定白名单、Origin/Host、不可预测 CSRF Token、1 KiB 请求体、单并发、私有目录、禁止覆盖及路径链接检查生效。未新增服务、Manager、Policy 或 Router 框架；未修改现有 Runner、Gate 与 Policy。

真实阻塞：三个已有 Runner 仅接受已批准 Linux 非 root 身份（NoNewPrivs/zero capabilities 等）、固定工具、root-owned fixture 批准记录。当前 Darwin arm64 UID 501，不符合契约。command -v 未发现 gitleaks/semgrep/cosign。没有批准过的 Mac 原生 Runner/fixture。没有改写 platform、放宽身份、安装新工具或回退到生产节点。

当前 Mac 资源亦不足：最终 Gitleaks Clean 请求 Load1=9.53076171875，10 核，空闲内存 91914240 bytes。入口使用本地小 fixture 准入预算（load<=0.75*CPU、free memory>=512MiB、disk>=512MiB），不是 Trivy guard。不降低任何阈值。

实际请求：三个插件各 Clean / Controlled Finding，共六种，每轮都返回 BLOCKED / NOT_TESTED / LOCAL_RESOURCE_BUDGET_BLOCKED；没有执行扫描，没有漏洞结果，没有 Policy PASS/FAIL，没有 Result Digest。只有新的审计 UUID、时戳和 auditDigest；后者不能冒充 Result Digest。最新 Gitleaks Clean Run ID: web-d417a76d-be12-4ed0-88ce-bf06cc973f62，审计耗时 0ms，不是扫描耗时。

资源预算若通过，当前代码仍只将真实 Darwin platform 传给现有 Manager 能力预检；得到 UNSUPPORTED 时保留 Policy=null、evaluationCount=0，并使用本地 dry-run Router。没有实现或启用可在 Mac 安全运行的真实后端。不能据预检声称扫描完成、Policy 单次求值或下游 Result 复用通过。

验收范围：API 24 PASS，旧页面 HTTP 验收 19 PASS，Runner 契约单元测试 62 PASS。浏览器自动化此前被禁用，当前工具中也没有浏览器操作入口：未实际点击按钮，不宣称 UI REAL 验收。真实 Runner integration、真实进程 timeout/descendant cleanup 均 NOT_TESTED。第一个 Host 测试发现 Node fetch 规范化 Host；改用 node:http 在真实线上发送非法 Host 后，确认返回 403，属于测试客户端修正。

1,001 个相关历史 JSON 内容及所检元数据未变。原 ORIGINAL_EVIDENCE_INTEGRITY=FAILED 不变。实际新运行目录 .devsecops/security-view-runs-v1，未提交运行材料与凭据，审计投影写入本轮独立 evidence。没有测试密钥、原始秘密或环境变量注入入口。

生产只读快照：三节点 Ready，PetClinic 3/3、HTTP200、Argo Synced/Healthy、Jenkins #270 SUCCESS，Deployment spec/image、V1 Summary、Trivy DB metadata、Docker daemon 与此前基线一致。socket0660。无生产写入、发布、rollout、push。

最小下一步：单独授权并验证 Mac 原生受控执行适配（固定本地工具/fixture 身份、受限执行、清理），同时满足本机资源预算；在此以前三个真实入口保留 BLOCKED。不能用 Linux 的历史结果替代本轮真实执行。

回滚：stop 同一个 control.mjs 服务；或恢复 view 文件到提交21a900a7再start，不删除历史或新审计记录。服务 start/stop/restart 命令与上一轮一致。运行记录上限100，不自动清理证据。
