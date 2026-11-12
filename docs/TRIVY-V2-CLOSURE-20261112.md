# Trivy V2 残留收尾记录 · 2026-11-12

基线：`docs/DEVSECOPS-V2-HANDOFF-20261107.md`（含 2026-11-08 Trivy 准入补充）与 2026-11-12 13:08 状态表。本轮只闭合非生产 Candidate/V2 链路；生产 Manager 保持 `NOT_ACTIVE`，发布 0、Rollout 0。证据目录：`evidence/2026-11-12/trivy-v2-closure/`。

## 逐项结果

| 项 | 结果 |
|---|---|
| 严重级别标准化（正式 Adapter 路径） | 已闭合。Adapter 把 Trivy 原生 CRITICAL/HIGH/MEDIUM/LOW/UNKNOWN 映射为 Policy 规范值（UNKNOWN 落入最低评级档，与冻结分类器在所有级别下判定一致）；无法识别或缺失的级别在进入 Policy 前以 `RUNNER_REPORT_ERROR` 失败关闭。真实原生样本（离线报告 HIGH/MEDIUM 条目）+ 合成 CRITICAL/LOW/UNKNOWN 经 `policyOwner → 冻结 Policy 引擎`正式路径求值通过，不再出现 `invalid finding severity`。冻结的 `engine.mjs`/分类器未改动（哈希钉扎）。 |
| Web/API 管理开关与执行入口 | 已闭合。`controls.mjs` 托管插件加入 trivy，旧 revision 34 配置文件自动补齐 trivy 默认开启；页面/API 实测：关 → Capability DISABLED、运行 DISABLED 且零求值；开但未武装 → BLOCKED/`TRIVY_EXECUTION_NOT_ARMED`；武装 → READY 并真实走 SSH 受限入口。修复一处 Codex 遗留缺陷：`trivy-real.mjs` 武装状态文件相对路径多退一级（指向仓库外 `~/code/.devsecops`），导致开关永远无法武装，已改为与其它状态文件一致的仓库根 `.devsecops/`。 |
| 超时清理与失败诊断 | 已闭合。Adapter 失败统一携带 `TrivyExecutionDiagnostic`（远端门禁码、scannerStarted），Core 落盘 `trivy.execution-error.json`，页面映射 `*_BLOCKED` 为 BLOCKED 并显示具体原因；SSH 超时/取消分别归一为 `RUNNER_TIMEOUT`/`RUNNER_CANCELLED`。服务端 `entry.py`（与仓库副本字节一致，sha256 `e37075d9…`）补强：错误输出携带 stages、重复正式尝试返回 `FORMAL_SCAN_ALREADY_CONSUMED`、扫描期间收到 SIGHUP/SIGTERM 先杀扫描器进程组；原有 185 秒超时强杀不变。改前备份在服务端 `setup/entry.py.bak-20261112-diag`。 |
| 隔离契约测试 | 已闭合。整仓一次性副本内：manager-v2 核心集 86/86、runtime-facts 回归集 147/147、trivy-real 7/7。既有异常与本轮无关且未被掩盖：`consumers/loki.test.mjs` 的 HTTP/REPLAY 用例因固定历史时间戳超出校验窗口失败（真实树与干净副本一致，30/156）。 |
| 漏洞 DB / Java DB 更新 | 已闭合。devops/Linux 侧官方 GHCR CDN 解析失败未改 DNS：改走 Mac 下载官方 OCI 工件（`trivy-db:2` 清单摘要 `sha256:69f786ce…`、`trivy-java-db:1` 清单摘要 `sha256:91f7488e…`，TLS 校验开启）→ 文件 SHA256 双端核对 → SSH 离线传输入独立缓存。主 DB UpdatedAt 2026-11-12T07:01Z、Java DB UpdatedAt 2026-11-12T00:58Z；此前缺失的 `db-cache/java-db/` 已补建；旧缓存备份在 `db-cache.bak-20261112`。入口实测已越过 DB 新鲜度门禁。 |
| Harbor Candidate 真实扫描 | **用户决定跳过（2026-11-12 18:19）**：待凭据续期后补做，阻塞证据原样保留，不作遗漏处理。全链路实测（页面提交 → Adapter → SSH 强制入口 → 身份/工具/资源/DB 门禁全过）停在 `CREDENTIAL_EXPIRED_BLOCKED`：项目级只读 Robot `robot$petclinic+security-manager-v2-trivy-pull`（robotId 250）已于 2026-11-09 过期。按红线未借用生产 `harbor-creds`、未新建 Harbor 账号。一次性正式扫描标记未消耗；凭据续期后由操作员武装并从页面重跑即可完成，届时再补 Policy 判定、Loki 投递与 Grafana/UI 显示验收。 |
| K8s 三节点 Ready（13:08 基线） | 复核时点一致：本轮 17:40 首次只读观察 `ucloud-worker` 为 NotReady，18:15/18:17 两次复查三节点均为 Ready（原始输出见 `raw/devops-state.log`）；状态波动与 `DEVSECOPS-V2-CONTINUATION-20261008.md` 既有隧道稳定性未闭环项一致，属平台基础设施，不在本轮 Trivy 范围，未做任何变更。 |

## 与冻结 Backlog 的边界

2026-11-07 冻结 Backlog 本轮一律未动：Harbor 候选 SBOM 可信 Digest 绑定（仍 `UNVERIFIED`）、候选 Cosign 签名/发布批准（仍 `SIGNATURE_MISSING`/`NOT_APPROVED`）、Summary V2 迁移、其他未激活插件的真实 Runtime、生产 Manager 激活、GitLab CI/GitHub Actions 适配。SBOM Runner 已于冻结时闭环，本轮未重开。GitHub 私有备份仓库与恢复脚本未触碰；全部提交仅本地 commit，未向任何远程 push。

## 本轮提交（本地，未 push）

- `17ca30e4` fix(trivy): wire real Trivy runner, normalize severities, preserve gate diagnostics
- `9dd706c4` feat(view): manage Trivy from the candidate console
- `62fe8359` docs(view): expose candidate signing and release approval status
- `9177c21f` docs(ops): record Harbor High closure and 2026-10-28 resource mode
- `6f668a52` ci(runtime-facts): add non-release verification pipeline

## 未吸收的历史未跟踪文件

仓库中仍有 2026-11-01/02 父代兼容性轮次的大量未跟踪记录（`docs/*COMPATIBILITY*`、`evidence/2026-11-01/02`、`infra/security/policy` 与 `runtime-facts` 测试材料）。它们属于已冻结的 V1 兼容性工作流，不是本轮交付物；本轮未逐项吸收，保留原状待用户单独决定是否归档提交。`.devsecops/` 为运行时状态（含本轮验收运行记录），不入仓。

## 第三方复核

全部结论的原始输出保存在 `evidence/2026-11-12/trivy-v2-closure/raw/`（测试日志原件、Web 验收转录与脚本、两次武装尝试的封存记录、官方 GHCR 清单原件、服务端状态原始捕获），复现步骤见同目录 `REPRODUCE.md`，逐项代码坐标（路径+行号+提交）见 `evidence-coordinates.json`。
注：2026-11-12 18:19 用户拍板，Harbor 凭据项（真实扫描及连带 Loki/Grafana/UI 验收）先跳过，等其处理凭据后再补；本记录与证据按最终状态定稿。
