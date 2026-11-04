# Gitleaks Independent Jenkins CI Validation — 2026-11-04

**本轮结果：CI_EXECUTION_NOT_READY，CI 集成 INCOMPLETE。**
已交付 CI 入口代码、默认禁用的 Job、固定配置、离线测试与真实只读管理证据。没有创建 Job/Agent、没有触发构建、没有真实扫描。本轮没有 CI Build 编号。
上一轮 2ca60f7 的本地 Candidate/Gitleaks VERIFIED 全部保持，未以本轮 CI 缺口降级或覆盖旧验收；也没有拿本地成功替代 CI。

## 阻塞依据

- Jenkins 只有一个 built-in executor，现有验证 Job 共用此执行器；无 Kubernetes Agent 插件。builtin-identity.json 实测 UID/GID=1000，groups=[988,1000]，NoNewPrivs=false；rootful Docker socket 0660 可访问。
- 管理入口已有 admin/createJob/createAgent 权限，但管理权限不构成扫描执行身份，也未用于创建资源。授权策略现为 FullControlOnceLoggedInAuthorizationStrategy；本轮未改变。
- 进一步只读评估了现有 Linux：Java/setpriv/node 均存在，但 UID65534 已被 13 个进程共用，包括 node_exporter、Alertmanager、Kyverno 等。agent-resource-observation.json 保存实际 PID/name/cgroup；不能直接把 nobody 作为通用 Remoting Agent。上一轮固定可信 scanner 的窄范围身份结论不被扩展。
- 没有可证明合规的现有专用 Agent/UID/执行域。未创建账号、systemd unit、Agent、Pod 或修改 Jenkins/Docker 全局权限。按附件第四节的 fail-closed 分支停止真实 CI。

## 交付清单与执行状态

| 验收项 | 本轮结果 |
|---|---|
| 1. 独立入口 | 计划名 security-manager-v2-gitleaks-validation，未导入 Jenkins |
| 2. Job/参数 | infra/jenkins/gitleaks-validation/{job.xml,Pipeline.groovy,manifest.json,readiness.json}；disabled=true、无触发器、sandbox=true、固定专用 label。8 个业务参数 + 白名单 VALIDATION_CASE，不允许任意路径/脚本/工具参数 |
| 3. 身份边界 | 当前 built-in 被明确拒绝；共享 UID65534 也拒绝。专用身份由 operator 批准绑定，NoNewPrivs/零 caps/独立域/无 Docker-K8s-发布凭据是前置条件，尚未真实验证 |
| 4. CI Build | NONE；前后 Jenkins inventory 都是原 55 个 Job、仅 built-in、queue 为空，计划 Job 不存在 |
| 5–11. 七模式 | master-off、plugin-off、clean、secret、missing-capability、runner-error、policy-error 均为 CI NOT_RUN；离线契约覆盖关闭、缺能力、错误 Policy 及期望判断。没有把 mock/合成结果当 CI |
| 12–14. Gate/Policy/单次求值/digest | 入口复用原 runCandidate/权威 evaluateAsync；evaluationId 是现有求值身份绑定，不是二次求值。Gate/Summary/Router 复用原 resultDigest 的检查代码已写；CI 证明 INCOMPLETE |
| 15–16. Artifact/Summary | 代码产生 Manager 原始 Candidate artifact + 独立 CI receipt/seal；包含 job/build、配置、digest、身份等。实际 CI artifact/summary 不存在，未伪造；仍不是 canonical ImmutableArtifact |
| 17. Router | 只允许既有 dry/local consumer。重复投递独占目录作为受控失败，保留 ERROR receipt；不得重跑扫描/Policy。本轮没有 CI Receipt |
| 18. 跨项目 | 仅 java-fixture/java-web 与 python-fixture/python-api，固定映射，同一核心；真实跨项目 CI 尚未执行 |
| 19. 失败/阻塞 | 无合规执行身份；初次只读 inventory accessor 失败已修正；首个 host 组合健康断言失败的具体谓词未保留，仍 UNKNOWN，后续保存的 pre/post 均正常。记录见 preflight-observations.json；未修基础设施、未宣称持续健康 |
| 20. 清理 | 本轮没有远端测试资源；本地临时 Git checkout 和 Groovy bytecode 目录均删除。未来 Job 的 workspace finally 删除；root-owned fixture/Agent/token 清理需 operator 独立证明，代码明确 PENDING_OPERATOR_PROOF |
| 21. 回归 | 22 个 CI 契约 + 原 Candidate 52 = 74/74；Gitleaks source-lock 9/9；干净 HEAD+本轮新增文件 83/83；XML round trip/Groovy 语法通过。未运行 Jenkins Declarative runtime，不能称 Jenkins 验收 |
| 22. 生产 | Jenkins petclinic-ci #270 SUCCESS、V1 SHA 不变；Argo Synced/Healthy；三节点 Ready；PetClinic 3/3、Endpoint=3、HTTP200、Harbor7Ready；digest/socket0660/daemon/容器/Trivy DB 元数据保持。前后快照正常，不声称全窗口无瞬时波动 |
| 23. 修改 | 仅新增 infra/security/manager-v2/ci、infra/jenkins/gitleaks-validation、本轮独立 evidence；既有 Gate、Runner、Policy、Jenkinsfile、GitOps 与旧 evidence 均未改。五份用户原有 docs 修改保留 |
| 24. 唯一下一步 | 评审并明确批准专用临时非生产身份及受限 Agent 的配置/启动/清理范围；先做真实身份验证，再启用独立 Job。具体前置约束见 ci/README.md。本轮 STOP |

## 信任与结果规则

入口不 checkout 项目管理脚本；固定 root-owned release + 93 文件 SHA，基线 2ca60f750525cf8858d5644abc09bd7202e3fdf6。项目只供目录扫描，不作为可执行脚本。实际 release/fixture bindings 未安装，因而 readiness 仍为 NOT_READY。

Secret case 旧 Gate/Policy 必须 FAIL；CI 独立验收名为 EXPECTED_POLICY_FAIL，绝不把它说成安全 PASS。工具异常、缺能力、Policy Error 都无 Policy PASS。audit 只允许普通 Candidate 测试继续，Promotion 永远 BLOCKED。

archiveArtifacts 使用 allowEmptyArchive=false，不吞掉失败，finally 清理 workspace。归档内容在管理端校验及 operator 最终清理未发生前，禁止标记 CI VERIFIED。cgroup 名称和离线 identity 模型本身不构成真实隔离验收，也不是 Trivy 隔离方案。

## 封存复用与生产保护

原 Gitleaks manifest、Trivy 兼容性和 Helm Shadow 相关源文件 SHA 都未变。原 Gitleaks 两版各140、127差分、Trivy两版各190、Helm43仅复用封存证据，不计本轮执行；本轮有独立 source-lock/Candidate 回归及旧 seal 再验证。

Jenkins #270 V1 Summary SHA：ec9ee51a06d4b9f61c6c0eaf50b374d1e25e6d3ca687908b7596d3a2c794f5d8。
生产镜像：core.harbor.domain/petclinic/petclinic@sha256:489cb821573ff1f98edd846d5949d74bf3391b24e2f1fe5bcfb71c6be0793137。
Argo revision：340ef4b8c74e3c2a5820da8d98b0f134283bb8d9。

Docker 仅通过既有只读 ps/inspect 核对容器身份，没有 run/create/build/stop/rm 或 daemon/socket 配置变更。DB 检查仅读文件大小/inode/mtime/metadata，未刷新、未扫描；无 Dojo API/导入。No push、release=0、rollout=0。

Runtime14/16、原历史证据完整性FAILED、Trivy/Dojo runtime/全局 Runtime/ImmutableArtifact/Summary V2 INCOMPLETE 保持。新代码和新证据可本地提交，但不得把本轮离线验收当生产或 CI 验收。

回滚：没有在线变更，无须删 Job、重启 Jenkins/Docker 或操作 Kubernetes；停止使用未部署的定义，必要时仅定向撤回本轮本地提交，保留证据及用户其他改动。
