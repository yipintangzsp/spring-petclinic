> **2026-11-07 最终交付 / 功能冻结**：当前能力、操作与Backlog以[阶段交付说明](../../../../docs/DEVSECOPS-V2-HANDOFF-20261107.md)为准。下文保留开发阶段与特定入口的历史记录，不代表当前系统全部状态。

# Gitleaks 独立 Jenkins 验证入口（未部署）

当前状态：**CI_EXECUTION_NOT_READY**。只有默认禁用的 Job 定义和离线契约测试。
没有创建 Job/Agent，没有 Build 编号，没有 Jenkins 真实扫描证据。
上一轮 2ca60f7 的本地真实 Gitleaks 验收继续有效，不能据此宣称 CI VERIFIED。

## 已交付

- `contract.mjs`：固定八个业务参数及一个白名单测试 case；禁止路径、Shell、Docker 参数、凭据输入。
- `entry.mjs`：受限身份与 root-owned release 验证，复用原 Manager/Runner/Policy；单次求值的标识绑定，原 resultDigest 复用，独立 CI receipt；本地 Router 正/负投递测试。
- `render-job.mjs`：从原封存包的 SHA 清单生成固定 release manifest、Pipeline 和禁用 XML。
- `infra/jenkins/gitleaks-validation`：可审查的生成结果。`disabled=true`，无触发器，sandbox=true，固定 Agent label，无 built-in fallback，无 SCM checkout/withCredentials。

默认参数：SECURITY_ENABLED=true、GLOBAL_MODE=audit、SECURITY_LEVEL=standard、PROFILE=java-web、POLICY_VERSION=baseline-v1、GITLEAKS_ENABLED=true、VALIDATION_PROJECT=java-fixture、VALIDATION_RUN_ID=空（按 job/build/project/case 绑定生成）。
另一项目固定为 python-fixture/python-api。测试 case 只允许 master-off/plugin-off/clean/secret/missing-capability/runner-error/policy-error。
关闭分支不执行扫描、不产生 Policy PASS。Secret case 只允许原 Gate=FAIL/Policy=FAIL；期望结果验收叫 EXPECTED_POLICY_FAIL，不能称漏洞扫描 PASS。

## 真实阻塞

2026-11-04 只读检查：Jenkins 仅一个 built-in executor。实际 UID/GID=1000、附加 GID=988，Docker socket 0660 且可访问；NoNewPrivs=false。现有安全验证 Job 同样共用此执行器。已有 admin 管理入口不能当作扫描执行身份。

宿主机有 Java/setpriv，但 UID65534 正被 13 个进程共用，包含 node_exporter、Alertmanager、Kyverno 等生产组件。不能把上一轮仅运行固定可信 scanner 的 nobody 身份直接扩展为通用 Remoting Agent。新入口明确拒绝 UID65534，要求经 operator 绑定的专用非生产 UID、仅自身主组、NoNewPrivs、零 capabilities、无 Docker/admin kubeconfig/SA token/发布凭据访问，以及独立的验证 cgroup 域。未知状态拒绝执行。合成 UID24001 仅用于单元测试，未创建这个账号。

当前不存在已授权并配置好的上述 Agent。不能改 socket、给 built-in 增权，或仅新建 Job 后声称隔离完成。

## 唯一下一步：受限 Agent 的专项变更评审

先明确批准专用临时非生产执行身份及 Agent 的创建/启动/清理范围。现有 Linux 上的最小方案必须先审查以下约束，然后再实施：

1. 唯一专用 UID/GID（实际核验无其他服务共用），单 executor、EXCLUSIVE 固定 label；不修改 built-in、生产 Job 或 Jenkins 全局授权。
2. 由 operator 通过既有可信管理通道启动临时 Agent，NoNewPrivs、drop capabilities、独立命名 cgroup、资源上限；不得创建高权限容器或赋予 Docker 组。真实生命周期/权限测试通过后才允许启用 Job。
3. Root-owned、不可由验证仓库修改的固定 release：本轮 `manifest.json` 的 93 个文件逐一校验，Manager 基线为 2ca60f750525cf8858d5644abc09bd7202e3fdf6；不得把项目 checkout 用作管理代码。
4. Operator 准备一次性合成 Git 源码、固定工具和批准文件。`fixture-bindings.json` 必须 root-owned、schemaVersion=1、固定 job/agent、executionUid=实际专用 UID、仅项目/case→受控 fixture 的映射。缺 binding 明确 NOT_READY；本轮未生成假 binding。
5. 工具故障使用独立、不可执行的测试工具副本；不改变生产工具权限。Missing capability 不传 SOURCE_DIR。Policy error 仅内部固定无效版本，不能由用户提供任意配置。
6. 七 case 以及两个项目均由 Jenkins 真实启动。记录 job/build/参数/源码/身份/原生报告/清理；由管理端独立核验 Jenkins 归档与 seal，不能仅信工作区自报。
7. `archiveArtifacts allowEmptyArchive=false`，错误向上传播；workspace 在 finally 清理。Root-owned fixture、Agent 注册、Agent token、专用临时执行域需要 operator 结束清理与验证。CI receipt 明确保留 PENDING_OPERATOR_PROOF，不能提前称全部清理完成。

本轮未实施这些基础设施变更。不可直接导入并启用 XML。离线 Groovy 语法通过不代表 Jenkins Declarative runtime 或真实 CI 已通过。

## 回归与边界

运行 `node --test infra/security/manager-v2/ci/contract.test.mjs infra/security/manager-v2/*.test.mjs`。
测试为 SYNTHETIC_UNIT_ONLY / LOCAL_CONTRACT；不计为真实 Gitleaks 扫描或 CI。
原 Gate/Policy/Runner/Jenkinsfile/Trivy/Helm/V1 都不修改；生产 Promotion 永远 BLOCKED，Runtime 14/16。
回滚只需停止使用未部署的定义，或定向撤回本轮本地提交；没有在线 Job/Agent/服务需要删除或重启。
