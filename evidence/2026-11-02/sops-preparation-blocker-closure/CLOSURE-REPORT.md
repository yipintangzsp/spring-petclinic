# SOPS preparation blockers — 2026-11-02

```text
SOPS_PREPARATION_BLOCKERS =
CLOSED

SOPS_FIXTURE_PREPARATION_READINESS =
READY
```

结论限定为 **preparation/harness readiness**。真实 SOPS fixture、生产 prerequisite/Gate 执行及 Policy differential 均为 0；SOPS production compatibility 状态没有提升。本轮没有修改生产安全逻辑、Summary、发布流程或 Kubernetes 资源。下一步仍需进入用户明确授权的 fixture 阶段；本轮到此停止。

## B1 — 同一 guard 泛化完成

修改原入口 `infra/security/testing/isolated_sops_executor.py`，没有另建 Kubernetes 入口。

- `Binding` 不再含默认路径、server、CA、UID 或 admin config digest；所有配置必须由可信测试调用者显式提供。
- 新增显式 `Profile`：`ADMIN_VALIDATION`、`MIN_RBAC_EXECUTOR`。缺少/未知 profile 直接拒绝；没有自动发现或 min→admin fallback。
- profile 明确绑定 config path/hash、context/cluster、HTTPS server、CA SHA、kube-system UID、身份及 groups、kubectl path/hash、私有 temp parent、允许工作目录。min 另绑定 namespace UID、SA name/UID、token issuer/audience。
- 不再固定 `/opt/homebrew`、macOS HOME 或某个 localhost 端口。HTTPS 使用 profile 中的确切 hostname/port，验证 CA/证书 hostname；不使用环境代理，不跟随重定向。
- ADMIN 仅接受固定摘要的 client certificate/key 配置；min 仅接受静态嵌入的短时 SA JWT。cross-use、exec plugin、tokenFile、外部 auth、默认 kubeconfig 与连接覆盖均拒绝。
- min 的离线 JWT 检查包含 sub/issuer/audience/expiry/SA namespace/name/UID，**不声称离线检查能验证签名**。在线 SelfSubjectReview 由 API 验证实际 credential，username/UID/groups 必须匹配，再核对 kube-system 和 executor namespace UID；未通过不得启动 child。
- clean HOME、私有 0400 kubeconfig snapshot、独立 cache/tmp、PATH 首位同一 guard 的 kubectl shim 保留。fixture 参数由 profile 的专用类型字段注入，绝不继承宿主 BUSINESS_AGE_FILE/HEAVY_HOLDER/代理或云凭据。
- ADMIN profile 不能启动一般 protected child；最终 Gate child 必须 min profile。CLI 仍只有 check/sentinel，不增加 Gate CLI 命令。
- 观察器调用同一模块的 `validate_execution_environment`，检查 profile/context/config snapshot/hash/env/tool pin，不能凭几个伪造环境变量启动 child。它不是另一个 Kubernetes 客户端。

已有测试文件只做显式 profile 的适配，保留原来 18 项拒绝条件、reason、网络/child traps。旧具体路径仅出现在明确的 legacy 测试样本中，不是 guard 的缺省行为。

### 实际 Linux 与真实 admin 验证

1. 原有 18/18 regression PASS。
2. 新增 66/66 host harness tests PASS：29 guard、33 observation、4 preparation contract。
3. 同一 66/66 在 **Linux aarch64 / Python 3.11.2** 原生 PASS，不只是 Linux 风格目录模拟。
4. 复用专用 runtime 已有镜像 `sha256:452d707d4862f52530247495d180205e029056831160e22870e37e3f6c1ac31f`。无下载/构建镜像。PyYAML 只复制已有纯 Python 源文件及许可，未复制宿主原生扩展。
5. 原生测试容器：UID/GID 65532、无网络、只读 rootfs、drop ALL、no-new-privileges、512Mi/1CPU/64PIDs；只通过 stdin 输入无凭据测试包到临时 tmpfs，**没有 host mount**。所有临时容器退出删除。
6. 第一次 bind 尝试因 VM 未挂载宿主路径而失败，未启动测试；没有修改 Colima mounts。随后 tmpfs 默认执行限制导致两项脚本测试失败，保留失败报告；仅为该临时容器显式设置 exec tmpfs 后通过。未通过的尝试不计为成功证据。
7. 对既有 dedicated kind 实际执行同一 guard 的 ADMIN_VALIDATION：SelfSubjectReview + kube-system UID 共 **2 次测试身份 API 请求**，随后无害 sentinel 成功、临时目录删除。不是生产 API，也没有持久 Kubernetes 对象创建。

min 认证响应测试使用明确标记的 synthetic JWT/HTTPS response。**没有签发真实 SA token、创建 SA 或声称 min-RBAC 已在实际集群完成业务执行**。真实签名/授权证明将在下一轮 fixture 存在后由同一 fail-closed guard 完成，不能以 unit response 代替。

## B2 — 真实观察机制完成

新增 `infra/security/testing/sops_observation.py`，不 import 生产 Gate/Policy、不计算 PASS/WARN/FAIL。

### prerequisite

`observe_prerequisite` 实际执行本地 stat 或由调用者提供的受控 reader/check，记录存在、缺失、不可执行、kubeconfig boundary reject、对象不可用、Lease holder missing/mismatch、RBAC allowed/denied/PermissionError。检查不执行时没有 true 占位；返回 None 是 unavailable。

本轮 Kubernetes 相关 reader 是明确的无害 shim/内存对象，记录 source=`supplied-check-callable`，不是伪造 API 结果。未来只能接入同一 guard 下的真实 API 观察；这里没有实现第二条 API 访问路径。

### child exit

`observe_child` 在同一 guard snapshot/env 验证后，通过真实子进程收集：

- absolute command identity + argv SHA（不保存任意 argv 内容）；
- normal exit code、signal、timedOut、outputLimitExceeded；
- stdout/stderr 字节数/SHA/contentStored=false；
- 实际执行错误类型、evidence reference。

无 shell，无继承 HOME/env；输出流在内存增量计数/哈希，超时或输出超限杀进程组并回收；不写输出正文。测试覆盖 exit0、exit7、SIGTERM、timeout、双输出、无输出失败、缺失 executable 和输出上限。

另有真实 guarded collector 测试：collector 自身 exit0，但它观察到的内部 child exit7 原样保留。**guard/collector 成功不是 Gate 成功**。测试只运行 Python sentinel，没有 Gate。

### UID/value

`observe_uid_values` 使用合成内存对象，保留 namespace/name、真实传入 UID、type、data 存在/shape/equality，区分同 UID、变 UID、同值、变值、缺值、损坏值；不修改输入、不虚构 Kubernetes UID。JSON 字段比较不把 boolean 与 number 混同。shape 描述不升级为新的生产失败规则。

本轮测试的是观察机制，不是 Kubernetes 删除/重建 race。后续 UID/value 负例仍必须在真实 fixture 两次读取之间完成受控 mutation 并记录实际时序，不能将这里的 LOCAL_SYNTHETIC_UID 当作真实 API UID。

### raw contract

`raw-fact.schema.json` 与 runtime `validate_record` 定义：

- `PREREQUISITE_FACT` / `CHILD_EXIT_FACT` / `UID_VALUE_FACT`；
- schemaVersion、source、identity、expectedTarget、observedTarget、status、errorClass、evidenceRef；
- 各 family 的 prerequisite、exit、output metadata、uid、value-preservation 元数据。

原始状态仅 OBSERVED / EXECUTION_ERROR / UNAVAILABLE / MISMATCH / DENIED / INCOMPLETE；递归拒绝 decision/policyDecision/oldDecision/expectedGateDecision/severity/blocking 等字段。expected old/policy 判定只放在独立未来矩阵，不能写入 raw fact。正式 JSON Schema 与 runtime schema 均已验证归档 raw records；故意损坏 schema 的测试只损坏副本，不污染实际观察归档。

这不表示已经把真实 Node Gate 的每个调用收集成 `sopsFacts` 输入。下一轮须将同一实际执行的 prerequisite/解密/API/最终 write 观察接入现有 adapter，并证明 raw 不变及差分一致；当前不得把本地 shim 归类为 REAL_CONTROLLED_SOPS_EXECUTION。

## B3 — 两对测试 key 范围正式修订

`age-key-lifecycle.json` 为当前附件明确批准的模型：

| 用途 | future private file | 使用范围 |
| --- | --- | --- |
| BASELINE_AGE_KEYPAIR | keys/baseline.agekey | 四个 ciphertext 的 recipient、正例及其他需要正常解密的 case |
| WRONG_KEY_NEGATIVE_KEYPAIR | keys/negative-wrong-key.agekey | 仅 WRONG_AGE_KEY |

两对均独立生成、一次性、0600、executor RO0400、私有 isolated temporary scope、不得 production path/commit/reuse。只记录 public recipient 及 recipient SHA256，不记录 private key。清理须停进程、卸载、删两组精确文件并确认 absence/handles。**本轮两者生成数均 0。**

精确语义是：ciphertext recipient=baseline；实际 decrypt key=另一对 valid private key。冻结 Gate 调用真实 sops decrypt，r.status 非零会抛错。未来原始事实必须是真实 decrypt status/error，不是人为 Policy failure；不以空文件/invalid key 文本代替 wrong valid key。没有修改生产规则。

## 最小 RBAC executor 身份

完整设计见 `minimum-rbac-identity-design.json`、`rbac-design-amendment.json`、`fixture-inventory-amendment.json`。旧 CSR/User 方案被此设计替代，未修改生产 RBAC。

- namespace=`devsecops-system`，SA=`security-fixture-executor`，username=`system:serviceaccount:devsecops-system:security-fixture-executor`，automount=false。
- 未来专用测试管理端生成 TokenRequest，单个实际 API audience、最长 3600s、精确 SA UID；实际 issuer/expiry 要从合法签发中记录。无 persistent token Secret、无 token argv/env、无自动刷新/admin fallback。
- kubeconfig 仅单 context/cluster/user，嵌入专用 CA+短时 token，0600；guard 生成 0400 snapshot。profile 单独固定摘要/issuer/audience/SA UID/ns UID，证书/admin config 不能进入 min 模式。
- executor Role：data-infra 中仅 get lease/platform-heavy；devsecops-system 中仅 impersonate 两个既有 Gate SA 名。
- 唯一 fixture identity ClusterRole：get namespaces，resourceNames=[kube-system,devsecops-system]；create authentication.k8s.io/selfsubjectreviews。cluster scope 的理由是身份/Namespace UID 检查，不用于业务 Secret。
- reconciler：petclinic 精确三个 Secret 及 devsecops-system 的 registry Secret，仅 get/patch；verifier 仅 get 自己 registry Secret。均无 create/list/其他 Secret get。
- `kubectl auth can-i` 依赖隔离集群已有 system:basic-user 自查询能力；discovery 依赖已有 system:discovery。后续 preflight 不满足则停止，不自动添加权限或修改默认绑定。
- setup、TokenRequest、mutation、cleanup 属于单独的 guarded 测试管理阶段，不把其管理 credential 挂到 executor。ADMIN_VALIDATION 不开放一般 child；未来 fixture manager 必须复用同一模块的显式 config/在线身份验证接口，不得直跑未受 guard 保护的 kubectl。

精确设计清单更新为 3 Namespace、4 Secret、1 Lease、**3 SA**（两个 Gate SA+一个 executor）、5 Role/5 RoleBinding、1 ClusterRole/1 ClusterRoleBinding；**共 23 个计划对象，当前创建 0**。取消先前两个 client CSR 及 User/mutator grant。两个测试管理 mutation 用现有隔离管理身份完成，不把 delete/create/RBAC 修改权赋给 executor。

## 全部 preparation criteria 复核

| 条件 | 证据 / 结论 |
| --- | --- |
| approved guard reused | 原文件 refactor，原 18 项全部保留；observer 复用同一边界，无旁路 |
| isolated executor design | 原设计的非特权 Linux 形态/工作目录/输出/资源限制保留；路径/server/CA/身份已参数化，Linux 原生运行通过 |
| exact inventory / RBAC | 当前 amendment 精确 23 个对象，固定名字/字段/依赖；无资源创建 |
| synthetic model / UID | 原四个 synthetic schema 保留；观察器能区分变化，原始对象不变 |
| age lifecycle | 两对范围获批并通过 consistency test，未生成 |
| encrypted mapping | 原四条 frozen relative paths 不变，实际文件未创建 |
| execution matrix | 12 case 保留，expected PASS1/FAIL11，全部真实执行状态仍 NOT_TESTED |
| old-vs-policy contract | 同一次真实事实比较 oldDecision==standard；本轮 0 differential，不能拿测试替代 |
| SOPS/age source/hash | 沿用上一轮已确认官方 arm64 digest；未来本地二进制/签名/锁值校验是执行前置，本轮下载 0 |
| cleanup | 先归档脱敏证据，再清 case outputs/ciphertext/两组 key/测试 mutations/Lease/bindings/roles/三个 SA/Secrets/ns；逐项 cluster+UID+ownership+absence。kind 保留 |
| no production credential | min 仅未来测试 SA token/测试 age identity；真实生产 credential 不参与 |
| no context fallback | 缺失/错误/cross-profile/default HOME/覆写参数/伪造观察环境均有拒绝测试 |
| no restart | 使用现有镜像和 stdin+tmpfs，无 VM/Colima/Docker restart 或挂载配置修改 |

READY 的依据是：完整前置设计、实现的 guard/observer、原生 Linux 运行、真实 admin 边界回归和受保护状态共同成立；**不是**因为 unit tests 就认定真实 SOPS/PetClinic/生产兼容完成。未来 token、工具、本地镜像依赖和 actual fixture 是下一阶段的受控准备对象，未假报为已存在或已验证。

## 30 项最终报告

| # | 要求 | 结果 |
| --- | --- | --- |
| 1 | B1 | CLOSED，portable explicit profiles，同一 guard |
| 2 | B2 | CLOSED，prerequisite/child/UID-value/schema 机制实现并测试；真实 Gate facts 仍未采集 |
| 3 | B3 | CLOSED，第二负例专用 pair 已纳入获批生命周期；生成 0 |
| 4 | guard files | 修改 isolated_sops_executor.py 与原 regression test；新增 sops_observation.py、test_sops_preparation.py |
| 5 | production files changed | NO；232 个既有 production security/Manager 文件摘要未变 |
| 6 | profiles | ADMIN_VALIDATION / MIN_RBAC_EXECUTOR，显式选择，无 fallback |
| 7 | Linux | 原生 aarch64 Python3.11.2，66/66 PASS |
| 8 | prior 18 | 18/18 PASS，原 refusal/traps 保留 |
| 9 | new guard | 29/29 PASS，host/Linux |
| 10 | prerequisite observation | 已实现，真实本地操作+明确合成 reader；不代表真实 K8s prerequisite 执行 |
| 11 | abnormal exits | 已实现，真实 sentinel 进程，保留 exit/signal/timeout/output metadata |
| 12 | UID/value | 已实现，synthetic in-memory 观察与 raw-preservation |
| 13 | raw schema | runtime validator + JSON Schema；归档 raw records 验证通过 |
| 14 | separation | raw 无 Policy/Gate decision，错误字段/状态拒绝 |
| 15 | baseline lifecycle | 0600/RO0400/temporary/no production/no commit/no reuse/cleanup |
| 16 | wrong lifecycle | 第二对独立、仅 wrong-key case，同上；未生成 |
| 17 | wrong key semantics | baseline recipient + different valid test private key → 未来实际 decrypt failure 观察 |
| 18 | min identity | devsecops-system/security-fixture-executor，短时 SA TokenRequest；无真实签发 |
| 19 | admin exclusion | min 拒绝 cert/admin，在线 identity/groups/UID，ADMIN 不允许一般 child，min 不做 fallback |
| 20 | total harness | **84 项独立测试**：18+66；最终 host84/Linux66 共150项次；另1真实 admin identity+sentinel，非 Policy 样本 |
| 21 | Policy compatibility added | **0**，不改累计计数 |
| 22 | production API | **0**；测试身份 API **2** |
| 23 | production credential values | 提取/导出/使用 **0**；配置文件字节摘要读取另记，不声称从未打开配置 |
| 24 | Kubernetes created | Namespace/Secret/Lease/SA/RBAC/Pod/CSR 均 **0** |
| 25 | keys/binaries | age/TLS key generation **0**，SOPS/age download/run **0**，镜像 pull/build **0** |
| 26 | protected state | 仅两个既有 test 文件改动；既有生产文件、用户 kubeconfig、SSH、Colima/Docker 配置、dedicated config 未变；global context=default |
| 27 | preparation blockers | CLOSED |
| 28 | fixture preparation | READY，限本轮结构性准备 |
| 29 | remaining preparation blocker | 无；真实 fixture/SA token/工具核验/执行与差分仍待下一阶段，不能宣称 production compatibility VERIFIED |
| 30 | next permitted action | 下一轮明确授权后，按 amendment 通过同一 guard 做隔离 fixture 预检/创建和实际执行；本轮禁止自动开始 |

受保护字节摘要读取（包括用户 kubeconfig/Docker 配置）不等于凭据值提取；没有解析、输出或把这些配置挂入容器。计数边界与完整性证据见 `protected-after.json`。

证据：`guard-regression-18.json`、`harness-tests-host.json`、`harness-tests-linux.json`、`admin-readonly-identity-sentinel.json`、`raw-schema-validation.json`、`test-counts.json`、`readiness.json`。失败尝试记录保留在 linux-attempt1/2 文件中，没有隐藏为最终 PASS。

无提交、无 Jenkins 构建、无 rollout。停止，不创建 fixture，不输出全 Policy Engine VERIFIED 标记。
