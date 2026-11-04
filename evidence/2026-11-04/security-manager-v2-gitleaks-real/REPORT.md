# Gitleaks Candidate 真实插件闭环 — 2026-11-04

验收范围：FIRST_REAL_GITLEAKS_CANDIDATE_ONLY。生产 Security Manager 未启用。
新真实证据分类为 REAL_CONTROLLED_EXECUTION：在两个一次性测试 Git 仓库的只读快照中真实运行 Gitleaks。不是生产事故、历史 raw 恢复，也不是 canonical 16/16 Runtime。

## 结果与证据

| 项目 | 实际结果 | 证据 |
|---|---|---|
| hash 根因 | 首次差异 90b4fcaaa2dce362049dc8bac2cfa4ad7e817a1e：Jenkinsfile.security-audit 增加 Helm Shadow 四块内容。其余八个冻结依赖一致 | hash-root-cause.json、first-difference.patch |
| 原身份 | e6e7c1b8f838e42e8bc9b3aa35e731515e2e05feb300bd1833d64aa921c54ed2 | 原 frozen manifest 未改 |
| 当前身份 | 6179859f70c1d6fec2560621ec1ae71dba20514de4ff430d84b7d60a1c319b3c | 新 gitleaks-parent-helm-shadow-v1.json |
| 版本兼容 | 两个 manifest 固定 SHA、九个源文件锁、原/新 adapter 身份、判定主体 SHA、四块投影还原原 Jenkinsfile。未知变更继续 POLICY_ERROR | source-lock-tests.tap；版本 manifest |
| Gate 语义 | 原/新各 140/140；127 个父 Gate/Shared Library 样本一致（15 PASS、112 FAIL），raw 事实相同。主体从 const absent= 起字节未变 | versioned-differential.json、verified-round/ |
| 历史 raw | 仅查权威 capture/gate/result 索引；rawPayloadPersisted=false、reports=[]；NORMALIZED_ONLY。HISTORICAL_RAW_REPLAY=INCOMPLETE，搜索已关闭 | historical-raw-availability.json |
| Runner | 静态 opt-in gitleaks-real，真实模式默认 disabled；仅允许显式开关、root-owned approval/source/tool，固定版本、配置与 dir 参数；非 shell，10 秒 timeout | infra/security/manager-v2/gitleaks-real.mjs、registry.mjs、cli.mjs |
| 执行身份 | UID/GID 65534，groups=[65534]，NoNewPrivs、CapEff=0、清空环境；不能读取 Docker socket/admin kubeconfig；不执行项目代码 | real-linux/outputs/*/gitleaks.runtime-facts.json |
| 工具来源 | 现有固定 digest 镜像经 k3s 缓存只读导出，验证 OCI 全链及二进制 SHA；版本实际输出 v8.30.1。未拉取镜像、未创建容器 | linux-tool-provenance.json、linux-package-retry.json |
| 真实失败样本 | java-fixture/java-web：本轮随机生成、从未签发的假 PAT；native exit=1、1 个 finding；旧 classifier FAIL、standard FAIL | real-linux/outputs/java-real-secret/ |
| 真实成功样本 | python-fixture/python-api：一次性清洁源码；native exit=0、0 finding；旧 classifier PASS、standard PASS；复用同一 Manager Core | real-linux/outputs/python-real-clean/ |
| 密钥保护 | --redact=100；native Secret 校验；全部导出文件逐字节确认不含测试假 PAT 明文；不导出源文件、生产密钥或凭据 | real-linux/export-proof.json |
| 单次 Policy | 现有 evaluateAsync，每个成功扫描 evaluationCount=1；原事实 hash 前后相同。未增造 severity | runtime-facts/facts/result 文件、verification.json |
| 摘要复用 | Gate 与 Candidate Summary 共享同一个冻结结果；rawReportDigest/factDigest/resultDigest 可验证；artifact 独占写入、只读文件、seal、重复读取通过 | 两个真实目录的 candidate-summary.json、candidate-seal.json |
| 开关/异常 | master/plugin DISABLED；缺 SOURCE_DIR NOT_CONFIGURED；Darwin UNSUPPORTED；未授权目录 POLICY_ERROR；错误 Policy 在输出/启动前拒绝；真实不可执行工具 ERROR，无 Policy PASS | normal-suite.json、tool-error-suite.json、gitleaks-real-suite.mjs |
| Router | dry-run + 本地接收成功；重复投递到独占目录真实失败并产生 ERROR receipt；扫描计数和 Policy 计数不增加，resultDigest 不变 | real-linux/outputs/router-receipts.json |
| 回归 | Candidate 52；源码锁 9；原/新 Gitleaks 各 140；干净 HEAD+指定变更 201；Trivy 各 190；Helm 43；Trivy 锁 54；Policy 5；Contract 10 全通过 | test-summary.json、compatibility/、clean-checkout-full-head-tests.tap |
| 清理 | 私有 scan 目录、二进制、临时 Git 仓库、源码、package、outputs 全部移除；剩余进程 0；Kubernetes 资源创建 0 | linux-cleanup.json |
| 生产 | Jenkins #270 SUCCESS；V1 SHA ec9ee51a06d4b9f61c6c0eaf50b374d1e25e6d3ca687908b7596d3a2c794f5d8；Argo Synced/Healthy、revision 340ef4b8c74e3c2a5820da8d98b0f134283bb8d9；三节点 Ready、3 Ready Endpoint、PetClinic 3/3、HTTP 200、Harbor 7 Ready；socket 0660；daemon 重启 0；13 容器身份/状态未变 | pre/post JSON、verification.json |
| 不完整项 | 历史 raw 未恢复；Trivy/Dojo runtime、全局 Runtime/Policy Owner/ImmutableArtifact/Summary V2 仍 INCOMPLETE；原历史完整性仍 FAILED；canonical 14/16 | verdict.json |

## 语义范围与限制

GITLEAKS_OLD_GATE_POLICY_EQUIVALENCE=VERIFIED 的真实执行范围，是原 source-gate.mjs 中未修改的 source-secret classifier 对本轮真实 findings 的判定；仅把临时绝对路径双射到原 /work/source 前缀，native raw 未改。Policy 消费同一份原始位置、review 记录与真实行 SHA。
完整父 Gate、Pod/Lease/网络隔离与 canary/Shared Library 条件通过独立冻结差分证明逻辑兼容，本轮没有重新执行生产 Pod/Lease/canary。不得把这两类证据拼接为一次完整生产执行。

SECURITY_MANAGER_CANDIDATE=VERIFIED 仅表示本轮首个 Gitleaks 受控插件闭环。所有 Promotion 始终 BLOCKED；正式 V1 Summary、Jenkinsfile、部署与 GitOps 未修改。Artifact 是篡改可检测的 Candidate 文件，不能抵抗 owner/root 改写，不宣称 WORM 或生产 ImmutableArtifact 完成。进程组清理用于固定可信 Gitleaks 单程序，不宣称解决对抗性后代逃逸或 Trivy 内核隔离。

首次真实尝试因版本文本带 v 前缀被严格拒绝，未扫描、未 Policy 求值。修正仅允许预期版本的可选 v 前缀后成功。保留首次输出及原 artifact。初版冻结 harness 缺少生成目录、初版 clean-checkout 打包缺少冻结依赖也全部保留；最终测试没有过滤失败记录或改变 Gate。

生产 digest 保持 core.harbor.domain/petclinic/petclinic@sha256:489cb821573ff1f98edd846d5949d74bf3391b24e2f1fe5bcfb71c6be0793137。DB/cache inode/大小/mtime/metadata、挂载、环境配置未变；df 空闲量是实时观测，不要求字节相等。Trivy hard floor 仍不满足，未执行 DB 刷新或扫描；本轮无 Dojo API/导入。

## 变更与回滚

commit-scope.json 列出本轮七个受控已跟踪变更、新文件和为可复现性纳入 Git 的原有测试依赖。五份用户先前改动的 docs 未动。10216 个既有受保护文件保持原 SHA；旧 evidence 与原 frozen manifest 全未覆盖。生产没有配置需要回滚；停止使用 Candidate CLI 即停用。若撤回代码，仅定向撤回本轮本地提交并保留证据，不回退用户其他变更、不执行部署。

唯一下一步允许操作：评审已封存 Gitleaks Candidate 证据，制定其受控 CI 验证范围；本轮 STOP。任何生产启用、其他插件真实 Runner、Trivy/Dojo 执行或 Summary V2 迁移需下一轮明确范围。禁止 push、release、rollout。
