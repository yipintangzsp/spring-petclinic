# SOPS fixture prerequisite design — 2026-11-02

本轮为 **DESIGN_ONLY**。下文的路径、资源、命令链和结果均为未来设计或预期，不能作为执行证据。未创建 fixture，未运行 Gate/differential，未生成密钥，未下载工具二进制。没有修改 guard、生产 Gate/runtime、Policy adapter、Jenkins、PetClinic 或实际 Summary。

```text
SOPS_FIXTURE_PREPARATION_READINESS =
NOT_READY
```

已完成清单、RBAC、数据、密钥、加密映射、12 场景、比较契约、工具来源和清理设计。阻塞在于：现有 guard 的已验证边界尚不能直接承载本设计要求的最小权限 Linux 执行器；不得用既有 kind 管理员凭据代替最小权限身份，或更改固定连接信息绕过校验。另需澄清完整矩阵所需的第二个一次性 age 测试密钥对。

## 1. 复用批准的 guard，保留已有验证边界

唯一允许的未来入口为 `infra/security/testing/isolated_sops_executor.py`。此前 18/18 guard tests 的通过结论保留，本轮没有重跑或扩大其含义。冻结源码及摘要见 `frozen-source-index.json`。

现有默认绑定：

- dedicated config：`/private/tmp/security-manager-kind-gdasvx1h/kubeconfig`；摘要 `ce4f1a493632c692bc23bf7470460dbea17af70247d13f9a0c9c0bbf553946d9`。
- cluster/context：`kind-security-test-sops`；server：`https://127.0.0.1:59645`。
- kube-system UID：`54f300a4-5f1b-4e1e-86a1-d173e5a402d8`；CA 摘要：`90507a6f34d0b4e9b31cf862d74b7c2694b465c2e959f99bb45705ef0c8a46d8`。
- kubectl：`/opt/homebrew/bin/kubectl`。默认 CLI 只允许 check/sentinel；库 child 模式要求显式绝对命令和私有工作目录。
- 每次拒绝默认配置回退、多文件配置、连接覆盖参数、错误身份/权限；为 child 创建临时 HOME、配置快照和 kubectl shim。

**新发现不推翻旧结论，但限制其可复用范围：**

1. 专用测试 kubeconfig 中的公开客户端证书主体是 `CN=kubernetes-admin, O=kubeadm:cluster-admins`（仅离线读取该测试证书公开元数据，见 `test-client-public-certificate-metadata.json`）。它不是本设计的 executor 最小权限身份。没有将此证书身份推断为本轮已查询的实时授权结果。
2. `validate` 和 `proxy_argv` 的默认固定摘要不允许直接替换成新 restricted kubeconfig；给库单独传另一个 Binding 并不能同时改变后续 shim 中的 EXPECTED。禁止这样尝试绕过。
3. macOS kubectl 绝对路径与 host loopback API 地址不能直接搬进 Linux 容器；容器内 127.0.0.1 不是宿主机。禁止 host network、Docker socket 或关闭 TLS 来掩盖该问题。
4. `child_environment` 目前会移除 `BUSINESS_AGE_FILE`、`HEAVY_HOLDER` 和 `DEVSECOPS_READ_ONLY`；没有已经验证的 fixture 专用受控注入接口。

因此：`KUBECONFIG_FAIL_CLOSED_BOUNDARY=READY` 仍仅指此前批准的入口边界；`LEAST_PRIVILEGE_LINUX_EXECUTOR_INTEGRATION=NOT_READY`。本轮没有修改它。

## 2. 执行器设计与文件系统边界

目标形式：现有 **security-test Colima** 内一次性 Linux/arm64 非特权容器，不是常驻 Deployment/DaemonSet，也不创建 scanner Pod。`secrets-gate.mjs` 本身不调用 `withScanner`，故不搬用生产 scanner Pod、devops nodeSelector 或 canary 网络检查。

未来执行链必须是：批准 guard → dedicated config 离线验证 → 精确测试集群在线身份验证 → 清洁环境 → 受控 fixture 输入注入 → 未修改的生产 prerequisite/Gate → 事实观察 → 独立 Policy 比较。不能直接启动未经过 guard 的 kubectl 或 Gate。

容器约束：UID/GID 10001、非特权、drop ALL capabilities、no-new-privileges、只读 rootfs、默认 seccomp、禁用 host PID/IPC/network/device/socket。建议单个 executor 上限 1 CPU / 512 MiB / 128 PIDs；仅本地加解密和串行 API 操作，不是集群承载能力调整。若实际执行超限，记录实际错误并停止，不能把 timeout/null exit 换成预期 FAIL 样本。

运行 ID：`sm-sops-20261102-01`。未来 VM 私有根目录为 `/var/tmp/security-manager-sops/sm-sops-20261102-01`，必须新建、0700、无符号链接且不得复用来源不明的现有目录。**本轮没有创建此目录。**

| VM 内专用目录 | 容器内位置 / 权限 | 内容 |
| --- | --- | --- |
| `…/cases/<CASE>/work` | `/fixture/work`，RW，工作目录，0700 | 仅白名单复制源码、`.git-sha`、四个测试加密文件及 Gate 输出；不挂载整仓库 |
| `…/tools` | `/var/jenkins_home/platform-security/20261027`，RO | 与生产锁完全一致的 SOPS 文件；age/age-keygen 仅用于准备阶段，不替换生产锁 |
| `…/keys/<case>.agekey` | `/fixture/keys/current.agekey`，RO/0400 | 一次性合成身份；Gate 用户可读，其他身份不可读 |
| `…/boundary` | `/fixture/boundary`，RO/0400 | 仅未来已审批并校验的 restricted 测试配置快照和边界状态；管理员配置不得挂入容器 |
| `…/cases/<CASE>/out` | `/fixture/out`，RW/0700 | 脱敏事件、退出状态和结果摘要；不输出解密正文 |
| 专用 tmpfs | `/fixture/home`、`/tmp`、cache，0700 | 空 HOME、临时文件；无 `~/.kube` fallback |

源码白名单：`secrets-gate.mjs`、`scanner-runtime.mjs`、`scanner-tools.json`、`tools-lock.json`、后续比较所需的原有 Policy Engine/adapter 依赖闭包；逐文件固定摘要。`.git-sha` 写入实际冻结源码 SHA，而不是伪造生产 Jenkins 构建。四个 `.enc.json` 必须来自本次合成数据，不能复制仓库中的生产 ciphertext。不是挂载宿主机 `/var/jenkins_home`。

基础执行镜像必须后续另行选择并固定 Linux arm64 digest，包含所需 Node/Python/PyYAML/kubectl；当前没有构建、拉取、宣称镜像可用。执行前还须验证包装所需二进制与源码摘要。这是实施前检查，不是本轮已完成的镜像验证。

环境采用默认拒绝：沿用 guard 的 LANG/LC_ALL/TZ 及显式 HOME/PATH/TMPDIR/cache/KUBECONFIG/context。未来 fixture 输入仅允许固定文件型 `BUSINESS_AGE_FILE=/fixture/keys/current.agekey`、固定 `HEAVY_HOLDER=sm-sops-20261102-01`、`DEVSECOPS_READ_ONLY=false`；read-only 独立案例才可为 true。生产 Gate 内部自己从 BUSINESS_AGE_FILE 派生 SOPS_AGE_KEY_FILE。不继承任何额外 AGE/SOPS、KUBE、AWS、SSH、代理、registry、Jenkins credential、DOCKER_HOST 或 NODE_OPTIONS；测试观察器必须显式固定命令，不从环境接受任意 preload。

这套 fixture 环境接口**当前不存在，不能通过在 guard 之后任意覆盖环境来声称完成边界验证**。

### 待解决的 transport / identity 衔接

设计方向为同一批准入口内的固定测试 transport：宿主机上经 guard 校验的 broker 保有 restricted config，仅接受当前容器的私有 IPC 请求；容器中的 kubectl transport 原样传递 argv/stdin，并回传真实 stdout/stderr/status。broker 必须重用 guard 的逐请求配置固定、拒绝覆盖参数和身份验证；不得成为第二条 kubectl 入口，不得暴露 TCP 监听端口、管理员配置或可调用任意主机命令的接口。

当前 guard 不具备该接口，固定的 admin config 也不符合要求；所以以上是**待单独审批和验证的设计**，没有启动 broker、实现 shim、改 Binding 或放宽校验。若采用在 Linux 内直接连接测试 API 的另一实现，也必须先证明固定 CA/server/UID 与 restricted config 的完整绑定；不能把更换 endpoint 当作已经批准的实现。没有选择任何旁路作为现成解决方案。

## 3. 准确资源清单和数据模型

完整逐对象字段、消费者、创建/删除依赖、UID 台账规则见 `fixture-inventory-design.json`；它是设计 JSON，**不是可直接 apply 的 Kubernetes manifest**。

| 类别 | 设计数量 / 精确名称 |
| --- | --- |
| Namespace | 3：`petclinic`、`devsecops-system`、`data-infra`，仅专用 kind；若已存在且不能证明确为本 run 独占，停止，不接管 |
| Secret | 4：petclinic 下 `petclinic-db`、`rabbitmq-client`、`petclinic-harbor-pull`；devsecops-system 下 `kyverno-registry-pull` |
| Lease | 1：`data-infra/platform-heavy`，holder 为 run ID；Gate 仅检查 holder，不发明续租/过期规则 |
| ServiceAccount | 2：devsecops-system 下 `platform-secret-reconciler`、`kyverno-admission-controller`，automount=false；只做 impersonation，无 token Secret |
| Role / RoleBinding | 各 7，精确名称/规则见下一节及 JSON |
| ClusterRole / ClusterRoleBinding | 各 1：`sops-fixture-cluster-identity` / `sops-fixture-cluster-identity-binding`，只读 kube-system 身份 |
| 临时 CSR | 2：`sm-sops-20261102-01-executor`、`sm-sops-20261102-01-mutator`，为无 privileged group 的短时客户端身份；不是额外 SA |
| 加密文件 | 4，见第 6 节；未创建 |
| age 身份 | 基线 1 对；WRONG_AGE_KEY 需另加 1 对，不能混淆“基线一对”和“矩阵总共一对” |

设计共 26 个持久到清理阶段的显式对象，另有 2 个签发后即清理的 CSR；当前创建数为 **0**。Namespace 控制器未来可能创建 default SA/root-CA ConfigMap，必须另行记账，不能说整个集群总共只有两个 SA。无需创建 Deployment、Pod、PVC 或 Secret Store。

所有手工对象的 harness ownership 标签为 `security-manager.test/run-id=sm-sops-20261102-01`、`security-manager.test/purpose=sops-controlled-compat`，annotation 记录上述 kube-system UID。它们是清理安全条件，不是现有 Gate 新增要求。

| Secret | 类型 | 设计数据（纯文字，未 base64） |
| --- | --- | --- |
| petclinic-db | Opaque | username=`FIXTURE_ONLY_DB_USER_20261102`；password=`FIXTURE_ONLY_DB_PASSWORD_A_20261102` |
| rabbitmq-client | Opaque | username=`FIXTURE_ONLY_RMQ_USER_20261102`；password=`FIXTURE_ONLY_RMQ_PASSWORD_A_20261102` |
| petclinic-harbor-pull | kubernetes.io/dockerconfigjson | `.dockerconfigjson` 为 JSON auths，仅 `registry.fixture.invalid`；username/password 用 `FIXTURE_ONLY_*` 常量；无真实 token，不执行 registry login |
| kyverno-registry-pull | kubernetes.io/dockerconfigjson | 同 schema，另用 `FIXTURE_ONLY_KYVERNO_*` 常量；不是复制生产 pull credential |

精确 pull 常量与 schema 见 inventory JSON。当前 Gate 只比较 desired/live 的 type、data 和 scope，不要求这里选用的 key enum、test label 或某个固定 type；这些是合法的合成输入选择，不是新安全规则。

每个对象在未来创建响应时记录真实 UID；每次破坏性操作前重新核对 cluster identity + ns/name + UID + ownership。Gate 比较所用 UID 必须取自它自己真实的第一次和第二次 API read。desired JSON 不放 UID/resourceVersion/stringData。UID 负例真实删除并重建测试对象，值保留负例实际 patch 测试值，均不篡改 API 响应。

## 4. 最小 RBAC

精确规则、subject、scope、否定条件见 `rbac-design.json`。RoleBinding 名称为各 Role 名加 `-binding`，roleRef 指向对应 namespaced Role。

| Role / namespace | Subject | apiGroup / resource / verbs / resourceNames |
| --- | --- | --- |
| sops-fixture-reconciler-business / petclinic | reconciler SA | core / secrets / get,patch / petclinic-db,rabbitmq-client,petclinic-harbor-pull |
| sops-fixture-reconciler-registry / devsecops-system | reconciler SA | core / secrets / get,patch / kyverno-registry-pull |
| sops-fixture-verifier-registry / devsecops-system | verifier SA | core / secrets / get / kyverno-registry-pull |
| sops-fixture-executor-lease / data-infra | User security-fixture-executor | coordination.k8s.io / leases / get / platform-heavy |
| sops-fixture-executor-impersonation / devsecops-system | executor User | core / serviceaccounts / impersonate / 两个精确 SA 名 |
| sops-fixture-mutator-db / petclinic | User security-fixture-mutator | core / secrets / get,patch,delete / petclinic-db；另有本 namespace secrets create，标准 RBAC 对 create 不支持 resourceNames 限制 |
| sops-fixture-mutator-lease / data-infra | mutator User | coordination.k8s.io / leases / get,patch / platform-heavy |

reconciler 无 create/list、无其他 Secret get；verifier 无业务库/业务 pull Secret get 和 list。SSA 对**已存在**的目标只授 patch，不授 create；若目标缺失，不允许自行创建掩盖故障。

最小权限 executor 不拥有直接 Secret 读取权限，通过生产代码原有 `--as` 执行。对 ServiceAccount 的 impersonation 在 Kubernetes v1.35 中以目标 namespace/name 授权，Role+RoleBinding 足够；不是 users/groups impersonation，也不用默认关闭的 alpha constrained impersonation。依据：[对应版本实现](https://raw.githubusercontent.com/kubernetes/apiserver/v0.35.0/pkg/endpoints/filters/impersonation/impersonation.go)。

唯一 ClusterRole 原因是 guard 验证的 `kube-system` Namespace 为 cluster-scoped，授 executor/mutator `get namespaces`，resourceNames 仅 kube-system。跨 namespace Secret 权限通过各 namespace RoleBinding 处理，不以此为由扩大 ClusterRole。没有新 cluster-admin、通配 verbs/resources 或集群级策略变更。

现有 `system:basic-user` 的 SelfSubjectAccessReview 和 `system:discovery` 是 kubectl auth/schema discovery 的先决条件，应在后续授权的只读验证中确认，不修改默认绑定，不把它们隐含为新授予权限。[v1.35 bootstrap 源码](https://raw.githubusercontent.com/kubernetes/kubernetes/v1.35.0/plugin/pkg/auth/authorizer/rbac/bootstrappolicy/policy.go)。

restricted executor/mutator 设计使用未来新建 TLS 客户端身份：CN 如表，无 O/group，CSR signer=`kubernetes.io/kube-apiserver-client`，client auth，申请 3600s。批准和 fixture provision/cleanup 只能由已有**专用测试**管理身份经批准 guard 执行，不能挂进 Gate 容器；不导出 CA key，不新建 cluster-admin grant。CSR 删除不撤销已签发证书，清理必须同时移除其 fixture RBAC 并销毁私钥，记录实际有效期。当前尚未申请/签发。

mutator 的 namespace-scoped create 仍能创建该 namespace 的其他名字，不能谎称 RBAC 已按名称限制。只在 run 独占的 disposable namespace 使用，另由 harness 限定 DB schema/name/ownership；若不接受该边界，应保持 UID 场景阻塞，不扩大 Gate SA 权限。

## 5. age 生命周期

基线私钥：`/var/tmp/security-manager-sops/sm-sops-20261102-01/keys/baseline.agekey`；public recipient：同目录 `baseline.recipient`。目录 0700、私钥 0600，容器 read-only 0400 挂载为 `/fixture/keys/current.agekey`。只由 future age-keygen 在私有范围生成，记录 public recipient，绝不记录 private key 或打印其命令输出。

仅用该 recipient 加密四个本轮文件。所有值都是本设计常量；key path 不得与任何生产 age/credential path 重叠，不挂载 host HOME/SSH/AWS/registry credential，不走 Jenkins production credentials。

WRONG_AGE_KEY 需要一个独立有效的测试 identity：`…/keys/negative-wrong-key.agekey`。空文件、随机文本、未设置 BUSINESS_AGE_FILE 不能替代“合法但不匹配的 key”。附件清单明确一对而矩阵要求此负例，因此应先明确总计两对的临时材料范围；当前不假定已获生成第二对的许可，更没有生成第一对。

后续“生产 key 从未读取”的证明必须来自：guard 输入路径 allowlist/拒绝记录、无 host HOME/production key mount、容器 mount/env 清单、file-open 观察只指向专用私有根、清理前后目录检查。不以“没有打印 key”代替“没有读取 key”。观察日志只存路径类别/允许结果，不复制敏感路径或内容。

完成所有比较和脱敏证据捕获后，停止进程，卸载文件，删除整个自有 keys 目录中的精确文件，再检查不存在、无持有句柄、无遗留 mount/volume。SSD 上普通删除不声称物理 secure erase；靠从未归档私钥、临时存储和销毁运行范围避免留存。

## 6. 加密文件映射

生产 Gate 原样读取以下相对路径，工作目录必须为 `/fixture/work`：

| 路径 | Secret |
| --- | --- |
| infra/security/secrets/petclinic-db.enc.json | petclinic/petclinic-db |
| infra/security/secrets/rabbitmq-client.enc.json | petclinic/rabbitmq-client |
| infra/security/secrets/petclinic-harbor-pull.enc.json | petclinic/petclinic-harbor-pull |
| infra/security/secrets/kyverno-registry-pull.enc.json | devsecops-system/kyverno-registry-pull |

明文 schema：apiVersion=v1、kind=Secret、metadata 仅正确 namespace/name、相同 synthetic type/data；无 UID/resourceVersion/stringData。未来仅在准备进程内将合成常量编码成 Kubernetes data 并加密；当前没有 base64、加密或写入明文 Secret 文件。使用基线 recipient，SOPS JSON data encryption；执行后必须真实解密观察确认，不由设计推断成功。

加密基线只生成一次并记录摘要；各 case 拷贝到独立工作目录。DECRYPT_ERROR 只损坏 case copy。type/data 不匹配改变测试 API 对象，不能“顺手重新加密”使其通过。每次比较前后校验加密基线摘要，原始事实留在内存，归档只放脱敏元数据和哈希。

## 7. 未来执行矩阵

逐场景精确 setup、必需观察、adapter raw 状态、cleanup 和破坏范围见 `execution-matrix-design.json`。**全部当前 NOT_TESTED，没有新增真实差分样本。**

| 场景 | 旧 Gate 预期 | standard 预期 | 真实观察关键点 |
| --- | --- | --- | --- |
| POSITIVE_FULL_PATH | PASS | PASS | 4 次解密及全部读/SSA/后读、9+4 RBAC、报告写入成功 |
| WRONG_AGE_KEY | FAIL | FAIL | 合法不匹配 key；真实 SOPS 非零退出 |
| DECRYPT_ERROR | FAIL | FAIL | case ciphertext 损坏；真实解密非零退出 |
| SECRET_MISSING | FAIL | FAIL | 真实 get NotFound，不返回伪造空对象 |
| SECRET_TYPE_MISMATCH | FAIL | FAIL | 真实 live/desired type 不同，Gate 在 apply 前拒绝 |
| SECRET_DATA_MISMATCH | FAIL | FAIL | 真实 live/desired data 不同，拒绝覆盖 |
| UID_CONTINUITY_FAILURE | FAIL | FAIL | 两次真实 read 之间删除/重建 DB，UID 不同、数据相同 |
| VALUE_PRESERVATION_FAILURE | FAIL | FAIL | apply 后真实 patch DB，UID 相同、数据不同 |
| LEASE_HOLDER_MISMATCH | FAIL | FAIL | 真实 holder 不同，pre-try requireLease 抛错 |
| RBAC_DENIED | FAIL | FAIL | 测试 Role 临时去掉 get；真实 Forbidden |
| TOOL_MISSING | FAIL，prerequisite execution error | FAIL | 固定路径 fs ENOENT，不伪造 spawn exit |
| REPORT_WRITE_FAILURE | FAIL，execution error | FAIL | 所有检查完成后 writeFileSync 真实 EISDIR |

12 个必需场景均有现有源代码依据，无需强造 NOT_APPLICABLE。额外不适用语义：desired UID 不匹配不是现有检查；Lease 过期/抢锁不是现有检查；单独缺 age executable 不是这里 verifyTools 的条件；test ownership label 不是 Gate 条件。

UID/value 场景需要测试专用同步 barrier，在第一次 read/SSA 后、第二次 read 前，等待真实 mutation API 成功并捕获 UID/data 关系。未捕获正确时序则该 case 仍 NOT_TESTED，不能修改 API 响应或靠碰运气后宣称稳定覆盖。RBAC_DENIED 对 fixture Role 的临时变更由 guarded provision manager 执行，mutator 不获 RBAC 修改权。

### 实际事实收集契约（待实现/验证，不是本轮工具）

只读取 `.devsecops/secrets-gate.json` **不够**：Lease/tools/credential/source 错误发生在 try/finally 之前，可能没有报告；报告写入失败时 in-memory status 仍可能为 success。未来测试专用 observer 必须观察真实子进程退出、每个 prerequisite、spawnSync 的真实 status/error、前后 API read/SSA、auth 查询和最终 fs write。

候选方式是固定摘要的 Node 测试 preload，在导入未改 Gate 之前记录真实 child_process/fs 调用的返回/异常，只为指定 race 提供 barrier。不得 mock、替换返回、吞异常、改参数/stdin/输出/重试或重算密码算法。测试 preload、transport、观察覆盖和无副作用证明尚不存在，所以不能作为当前兼容性证据；若不能安全观察，保留缺口，不修改生产 Gate 来配合。

guard child 当前将非零执行视为 CHILD_FAILED 并压制输出；future trusted collector 必须单独保存 Gate 实际 exit/signal/error，collector 自己成功不等于 Gate 成功，不能用 guard 返回成功推断 oldDecision。未运行 collector 或任意 Gate 命令。

## 8. old vs Policy 的比较契约

1. 同一次真实受控执行产生不可变内存 observation，保留实际 process exit/signal/error。先按未修改 Gate 原有进程成功/失败确定 oldDecision。
2. 同一 observation 传给现有 `sopsFacts`/`sopsDecision`，再由现有 baseline-v1/standard 路径消费，不另造一个 policy 计算器。禁止二次扫描或重放 API 后用不同事实比较。
3. 明确记录 manifest/Lease/tools/credential/source 的实际检查观察；未执行部分保留 absent，不能一律填 true。现有 adapter 按第一个失败检查短路，所以后续 absent 不是补造数据的理由。
4. targets 输入有固定 expected scope/count=4；解密正文和 actual/after 仅内存保留。前后 canonical hash + deep equality 验证 adapter 没有变更对象；磁盘只输出检查 ID/boolean、真实退出状态、failureKind、scope/UID/摘要和脱敏证据分类。
5. 完整事实产生的 adapter 顶层 status=success 仅表示事实处理完成；checks 中 false 决定 FAIL。`not_configured` / decision=null 不等于 PASS，应保留 NOT_TESTED/缺证据。
6. TOOL_MISSING 的旧执行是 fs prerequisite 异常，现有 adapter 将 tools=false 的 failureKind 标为 `validation failure`。保留两者原始分类，不重命名旧错误，不修改 adapter；PASS/FAIL 必须相同。若后续要求错误分类也完全一致，应另行报告此差异，不能隐藏。
7. spawn status=null（超时/信号/启动错误）必须原样保留；当前 adapter 的 decrypt.exitStatus 要求整数，该类意外执行不能转写为 1。对应样本应停止并报告缺口，不算计划中的 real nonzero decrypt 样本。
8. 每个适用场景必须 oldDecision==policyDecision，同时 raw facts 和 baseline ciphertext 摘要不变；任何不一致立即停止。不生成 severity；现有 adapter severity=null。

后续证据标签使用 **REAL_CONTROLLED_EXECUTION**，不是历史生产事故。此前单元样本仍为 SYNTHETIC_UNIT_ONLY，历史归档仍为 HISTORICAL_ARCHIVE。本轮只有 DESIGN_ONLY，真实执行数=0。

## 9. 工具来源、架构与校验计划

官方 HTTPS release JSON 中已取得 arm64 artifact digest；没有下载二进制、解包或运行签名验证。原始过滤元数据及计划见 `sops-official-release-metadata.json`、`age-official-release-metadata.json`、`toolchain-plan.json`。

| 工具 | 官方版本 / 精确 Linux arm64 artifact | 官方资产 SHA256 |
| --- | --- | --- |
| SOPS | [v3.13.3](https://github.com/getsops/sops/releases/tag/v3.13.3) / `sops-v3.13.3.linux.arm64` | `53b0abacd38ef1b12a66d6c100956691b9cefce018d91f81e73ddf7438b94d77` |
| age | [v1.3.2](https://github.com/FiloSottile/age/releases/tag/v1.3.2) / `age-v1.3.2-linux-arm64.tar.gz` | `6b8dc4333c53a5a57c9e5834e3a48f92605d7154014cd07269ff3327db5d37f4` |

SOPS 摘要与生产 scanner-tools 锁一致。age archive 摘要不等于内部 executable 摘要，解包后还必须分别匹配冻结值：age=`41b072352f4561018949623c674d16ef704019b9108a9bbdbd21292efebfc94f`；age-keygen=`00b549cebf68302893fc489830f37e706712689ca877f84d85439d700d2997c7`。**尚未声称两者本地匹配。**

未来下载必须先获对应阶段授权，仅从上述官方 release；SOPS 验证官方 checksums.txt 的 Sigstore bundle（按发布者 issuer/identity），age 验证官方 `.proof`（按该版本官方 SIGSUM.md 信任策略）。不能把同一服务器上的 hash 当作已经完成独立签名验证。解包检查路径穿越/绝对路径/链接，仅提取 age/age-keygen；随后要求官方摘要、冻结生产锁、ELF arm64 和版本均一致，任一不符立即停止，不更新 lock 来迁就下载结果。

本轮官方摘要来源已确认，因此“尚未查到 upstream checksum”不再是 blocker；实际下载后校验与签名验证仍是未来执行的前置检查。

## 10. 清理顺序、所有权和验证

每条 Kubernetes 清理请求仍须经批准 guard，重新确认精确测试 config/CA/server/kube-system UID、对象 ns/name/记录的 UID/ownership；DeleteOptions 使用 UID precondition，拒绝替换对象。名称相同不够。发现外来对象则停止，不强删、不移 finalizer。

先停止所有 Gate/decrypt/collector/mutator 进程，完成脱敏证据索引和摘要快照，再按以下顺序；**这不是当前已执行的清理**：

1. 删除 case 中 generated reports/temp outputs；先归档脱敏证据，不拷贝 decrypted stdout。仅操作私有根下的登记文件，不清理真实 Jenkins workspace。
2. 删除四个 encrypted fixture 及 negative copies，核对路径和登记摘要；不访问生产 encrypted credentials。
3. 删除 synthetic private/public key、临时 TLS client key/config 和 mount；确认文件不存在、无打开句柄、无残余 volume。CSR 签发证据捕获后可提前删除，但证书权限须在后面移除。
4. 恢复或消除测试 mutation：Role rules、Lease holder、DB data/type 依据纯合成 canonical ledger，而非重新读取已删除的私钥；记录当前 UID。单个 case 之间则必须先恢复基线，再进入下一 case。
5. 删除精确 `data-infra/platform-heavy`。
6. 删除七个 fixture RoleBinding 及一个 identity ClusterRoleBinding；确认不存在。先撤销 actor 权限，不能以 CSR 删除代替撤权。
7. 删除七个 fixture Role 及一个 identity ClusterRole；确认不存在。仅 manager 经 guard 清理，不能扩大 executor 权限。
8. 删除两个精确 ServiceAccount；不删除任何其他 SA。
9. 删除四个精确 Secret，确认不存在；禁止生产 Secret/PVC/数据库操作。
10. Namespace 删除前列举该测试 scope 的所有资源并验证独占和 UID，包含自动 default SA/root-CA ConfigMap 的台账；若有未知工作负载，不删除 namespace，报告残留。无 namespace-wide/broad wipe；确认为专用且资源清理完成才删除三者并确认不存在。

所有精确资源缺席后移除 executor 临时容器/volume，确认无新高权限资源。没有 privileged fixture。kind cluster 保留至完整 SOPS 兼容性执行和证据捕获结束，本轮不删除 kind。

清理由后续 guarded fixture manager 负责；容器退出不足以证明 API 资源清理。任何 guard 身份不符时，先停止清理、报告残留，不能回退默认 context 或放宽权限。

## 11. DNS/runtime 与重启边界

本设计不要求 VM、Colima 或 Docker restart；后续可在既有独立 runtime 内准备镜像/工具和一次性执行器。DNS restart persistence 仍未测试，不声称已修复或持久化。未来只读 preflight 若发现 runtime/DNS 不再可用，应停止重新评估；不自动重启。当前没有执行 Docker/kind API，也没有查询生产网络。

## 12. 最终 26 项映射

| # | 项目 | 本轮结论 |
| --- | --- | --- |
| 1 | approved guard reuse | 唯一批准入口保留，源码不改；此前 18/18 不重复冒充本轮新验收 |
| 2 | executor | 形态/目录/mount/env/output/owner 已设计；最小权限 Linux 对接 NOT_READY |
| 3 | namespaces | 三个精确名字已列；创建 0 |
| 4 | Secrets | 四个精确名字/type/data 已列；创建/读取生产值 0 |
| 5 | Lease | platform-heavy/holder/check 语义已设计；创建 0 |
| 6 | SAs | 两个 impersonated SA，无 token/mount；创建 0 |
| 7 | RBAC | 7 Role+7 binding，1 限定 namespace identity ClusterRole+binding；无新 cluster-admin |
| 8 | synthetic schema | 完成；没有 base64/生成凭据 |
| 9 | UID/value model | 实际 API UID 和数据比较，真实 mutation，不伪造响应 |
| 10 | age lifecycle | 完成；第二个 valid wrong-key 身份需明确追加范围 |
| 11 | encrypted mapping | 四条固定路径与四个测试 Secret 一一对应，未加密 |
| 12 | matrix | 12 个计划 case，全部执行状态 NOT_TESTED |
| 13 | old expected | PASS 1 / FAIL 11，均为预期而非运行结果 |
| 14 | policy expected | standard 同为 PASS 1 / FAIL 11，未差分 |
| 15 | NOT_APPLICABLE | 12 必需场景无 N/A；额外非现有语义已明确排除 |
| 16 | SOPS | 官方版本/arm64 artifact/digest 确认；签名/本地字节验证未执行 |
| 17 | age | 官方 archive digest 确认；提取后双 binary 锁验证待执行 |
| 18 | cleanup | 10 步、UID/ownership/absence 检查，kind 保留 |
| 19 | restart | 无 restart dependency；本轮 restart=0 |
| 20 | production API | 本轮请求 0；本轮测试 Kubernetes API 也为 0 |
| 21 | production Secret/credential | 值提取/解析/打印/使用 0；见下方对配置摘要读取的区分 |
| 22 | resources | Kubernetes/容器/namespace/Secret/Lease/RBAC/CSR/key 均创建 0 |
| 23 | files/config | 仅本证据目录新增/完善设计与元数据文件；已有项目/guard/宿主配置完整性见 post-protection.json |
| 24 | readiness | NOT_READY |
| 25 | blockers | B1/B2/B3 如下；不得自动生成 fixture |
| 26 | next permitted action | READY 条件未满足，因此没有自动 fixture 步骤；下一轮需单独明确 test-only 对接范围及第二 key，仍不触及生产 Gate |

配置访问计数须准确区分：本轮基线对 `.kube/config`、`.docker/config.json` 等受保护配置做了字节 SHA256 完整性计算，未解析、导出或使用其中 credential，未挂载给 executor。**不能把“凭据值提取 0”写成“从未读取过任何配置文件字节”**。测试 kubeconfig 只用于既有身份元数据的离线检查，未调用 API；未读取/导出生产 age key。受保护文件清单与前后 hash 见 pre/post-protection JSON。

## 13. 阻塞与最小下一步

| Blocker | 证据 | 最小下一步（本轮未实施） |
| --- | --- | --- |
| B1：guard 到 restricted Linux executor 尚无兼容路径 | 固定 admin config SHA、host kubectl/loopback、fixture env 被清理；完整源码索引 | 单独审批并验证同一 test-only guard 的 restricted identity / transport / typed fixture input 对接；保持 fail-closed，不加旁路、不挂 admin config、不改生产 Gate/runtime |
| B2：真实事实捕获及 race 同步尚无验证 | Gate report 缺 pre-try failure 事实，写失败可覆盖 success；guard child 非零抑制输出；当前只有设计 | 后续先以不含 Secret 的 sentinel 验证固定 collector/transport 对退出/异常/环境的保真及拒绝路径，再进入 fixture；本轮不实现、不运行 |
| B3：一对 baseline key 不足以覆盖有效 wrong-key 负例 | WRONG_AGE_KEY 必须是合法但不同的 identity；无现有可安全复用的 disposable key | 明确允许额外一对一次性非生产测试 key；若坚持总共一对，保留该 case NOT_TESTED，不伪造为错误 key 验证完成 |

Readiness 不是因为缺少生产 Secret、缺历史事故或要更改 Gate。无需生产权限。也不把官方 hash 已确认误报成缺失。当前仅设计可审阅，未满足无旁路执行前提，故停止，不自动创建任何 fixture。
