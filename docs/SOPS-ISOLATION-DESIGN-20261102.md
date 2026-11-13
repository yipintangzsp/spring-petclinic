# SOPS/age 隔离执行环境设计与就绪判定（2026-11-02）

**SOPS_ISOLATED_EXECUTION_READINESS = NOT_READY**。

本轮仅只读盘点与设计，没有运行SOPS compatibility，没有生成key/Secret/密文，没有启动或安装runtime，没有创建cluster/namespace/RBAC，也没有使用现有Kubernetes context发起API请求。此前SOPS状态保持 **NOT_TESTED / ENVIRONMENT_BLOCKED**，其他已验收来源及最终总盘点不变。

## 1：实际可用的隔离技术

| 技术 | 本轮只读观察 | 判定 |
| --- | --- | --- |
| Docker | CLI29.7.2可用；default与desktop-linux均指向本地Unix socket；`/var/run/docker.sock`指向不存在的用户socket，显式local Docker info报ENOENT | CLI存在，daemon不可用 |
| kind | CLI0.31.0可用；强制本地Docker endpoint后的get clusters失败 | 没有已证明可用的kind集群 |
| Colima | CLI可用；首次list显示default Stopped/aarch64/2CPU/2GiB；归档重查10秒超时；其Docker socket也不存在 | 不宣称状态稳定，也未证明可运行 |
| Lima | CLI可用，默认实例列表为空；同时有只读sysctl权限告警 | 未找到已证明可用的默认实例；不扩大为所有VM都不存在 |
| OrbStack | orb不在PATH，常见系统/用户Applications位置无app、socket不存在 | kube context名字不证明应用或隔离runtime存在 |
| Docker Desktop | common Applications位置无app；保留desktop-linux context | context残留不证明daemon存在 |
| k3d / 本地k3s | 不在PATH；宿主Darwin arm64 | 当前无已证明运行能力，不安装 |
| sops / age / age-keygen | 不在PATH；冻结Linux工具路径也不存在 | 无当前可执行的加解密夹具工具链 |

没有启动Colima/Docker/OrbStack、安装kind/k3d/k3s、拉取镜像或访问remote Docker endpoint。kind/daemon只读检查显式固定本地Unix endpoint，不按默认远程context猜测。

## 2–3：候选环境及身份核验

**当前精确可运行候选：无。** 条件设计候选是新建单control-plane disposable kind集群，以及同一fixture专属隔离网络中的Linux executor。这只是未来设计，未创建，也不视为已获执行认证。

本地kubeconfig仅提取context/server/TLS配置是否存在等元数据，未保存users、证书、token或私钥字段，未执行auth插件或use-context：

| context | server | 身份结论 |
| --- | --- | --- |
| kind-my-multi-node-cluster | https://127.0.0.1:63731 | 未观察到本地监听；Docker不可达，无法取得新cluster/namespace UID；身份未证明 |
| orbstack（当前默认） | https://127.0.0.1:26443 | 本地监听进程为ssh；不能据loopback推断为本地集群 |

既有 `sops-controlled/acceptance.json` 保存的可信历史核对表明orbstack与生产devops的kube-system UID相同：`639e5426-bc1f-4d37-a844-6a31b7685744`。本轮未刷新该UID，不把历史记录称为当前实时证明；但它已足以排除此context作为安全fixture候选。

**本轮Kubernetes API请求0，namespace UID查询0，Secret读取0。** 没有为“确认是否生产”而连接不可信context。

未来必须依次证明：本地runtime归属 → 新fixture container/VM/network IDs及API映射 → fixture kubeconfig server/CA确实属于该实例 → 仅在此前提成立后读取其新kube-system/fixture namespace UID和run sentinel，并排除已知生产UID。context名称、127.0.0.1、systemd/CLI存在均不是充分证明。

## 4–5：生产硬编码与可配置输入

原 `infra/security/secrets-gate.mjs` 调用共享runtime的import校验、requireLease、verifyTools(['sops'])、read/kube，**不调用withScanner**，因此无需建立devops命名节点或额外scanner Pod。

| 项目 | 当前实现与可配置性 |
| --- | --- |
| API/context | 未写死API Server或--context；真正kubectl继承KUBECONFIG，可用独立文件指定全新fixture cluster |
| Secret目标 | 写死四个namespace/name，无环境覆盖 |
| 密文文件 | 写死相对路径 `infra/security/secrets/<name>.enc.json`；可在独立fixture CWD提供合成文件，不改原生产文件 |
| age key | BUSINESS_AGE_FILE可指定；子SOPS进程以它设置SOPS_AGE_KEY_FILE |
| 身份 | 两个固定ServiceAccount impersonation identity，不可配置 |
| Lease | data-infra/platform-heavy固定；holder可用HEAVY_HOLDER或BUILD_NUMBER fallback |
| 工具 | scanner-tools.json固定root `/var/jenkins_home/platform-security/20261027`；manifest与工具SHA受锁定，不是环境变量覆盖 |
| source/output | CWD内.git-sha与.devsecops/secrets-gate.json固定相对路径 |
| readOnly | 只关闭apply，仍解密并两次读取Secret data；绝不能用于证明生产读取安全 |

固定目标：

- petclinic/petclinic-db
- petclinic/rabbitmq-client
- petclinic/petclinic-harbor-pull
- devsecops-system/kyverno-registry-pull

固定身份是devsecops-system下的platform-secret-reconciler和kyverno-admission-controller。负向权限检查还涉及data-infra中的名称，但不需要创建该负向Secret；data-infra本身需要存在以容纳真实prerequisite Lease。

## 6：最小synthetic fixture的实际规模

**严格的“一个namespace、一个Secret、一个密文文件”无法覆盖未修改Gate。** 原循环总会访问四个目标；截断循环、重写namespace或kubectl stub都不能声称真实原路径兼容。

若未来允许按真实最小依赖搭建，所需规模是：

- 1个新的、独立且可丢弃集群；3个仅属于该集群的测试namespace：petclinic、devsecops-system、data-infra。名称与生产相同不代表它们是生产对象，必须先证明整个cluster隔离。
- 4个synthetic Secret、4份对应synthetic SOPS密文、1份synthetic age keypair。
- 2个测试ServiceAccount；仅必要的named Secret读取权限；若后续验证原apply分支，再配置原检查允许范围内的named patch。禁止list/create/foreign访问，verifier仅自身拉取凭据可读。
- 1个测试Lease，holder绑定当前fixture；executor只需原Lease读取及两身份impersonation的测试域权限。
- 1个临时workspace/evidence目录，以及fixture专属kubeconfig、工具和key文件。

所有RBAC仅可在新隔离信任域中按原检查建立；不借用生产管理员、不扩大现有IAM或生产权限。实际fixture权限尚未创建/验证，不把设计权限当成已具备。

## 7：能否零修改复用production path

**源码上有条件可行，当前未实际证明可执行。** 因为Gate无固定API Server，独立KUBECONFIG可使同样的kubectl/read/RBAC请求全部落到新fixture cluster；同名目标、Lease与密文位于该环境中。

executor须在受控Linux环境内提供原manifest/root和**完全匹配锁定SHA的SOPS工具**。保留原生产工具路径是在容器内部，不要求扩大macOS `/var`权限或写宿主工具目录。当前没有可用daemon、工具bytes或缓存镜像证明，不能假定拉一个新image就成功。

fixture workspace只allowlist复制原Gate/runtime/manifest/lock等必要代码，保持SHA；不得复制生产密文、真实age key、默认.kube、云凭据、SSH agent或整个HOME。相对路径下放置新synthetic密文；BUSINESS_AGE_FILE只指向fixture key。child env清理其他SOPS/cloud/SSH凭据，synthetic密文只含age recipient，不依赖外部KMS。

未来真实验证链必须是：

```text
真实隔离环境中的scanner-runtime prerequisite
→ 原secrets-gate.mjs真实SOPS解密与真实Kubernetes/RBAC
→ 原parent exit/decision
→ 同一执行事实在内存中送入现有SOPS adapter
→ baseline-v1 / standard差分
```

若要采集缺失的prerequisite/比较观察，只能另行评审不改变原参数、返回值或错误传播的观察机制；不得另写假的SOPS validator，不用VM/mock回填真实正例。任何解密stdout、data或key只可为synthetic且在受控内存中处理，不纳入公开归档。本轮未实现采集器，也未运行上链任何步骤。

## 8–10：cleanup、暴露风险与代码变更

Cleanup设计为先记录且复核owned cluster/container/network/volume IDs，再只删除这些fixture对象；移除synthetic key、kubeconfig、明文/密文目录，保留脱敏证据与哈希。不能按宽泛名称删除cluster，不能触碰default context或现有生产对象。当前没创建资源，实际cleanup不适用，无待删key或高权限对象。

主要风险是错误kubeconfig、SSH转发被误认本地、默认配置合并、挂载生产HOME/凭据、环境继承外部KMS，以及把测试密文放进原checkout覆盖生产文件。设计用专用单context kubeconfig、真实CA/server映射、empty HOME、专用internal network、无host socket/SSH agent/云凭据挂载及独立workspace防止这些路径。当前尚未证明这些实际隔离属性，因此不执行。

完整同名synthetic mirror预计**无需修改生产Gate行为**；这只是源码可行性，不是执行验收。若坚持1namespace/1Secret，则必须改targets/namespace参数或跳过原循环，违反本轮边界，故不建议也不实施该改动。纯本地假kubectl/Secret服务器不能替代当前要求的真实prerequisite/RBAC兼容证明。

## 11–13：NO-GO、blocker和下一步

判定为 **NOT_READY**，四个明确阻塞：

1. Docker daemon不可达；Colima首次Stopped后重查超时，没有可用本地运行底座。
2. 没有新隔离cluster的container/network/CA/namespace UID证明；旧kind入口不可证明，orbstack必须排除。
3. 锁定Linux SOPS/age工具链不在本机可执行位置，合规缓存镜像/工具来源尚未证明。
4. 1namespace/1Secret的夹具规格与原完整硬编码路径不兼容；必须先接受真实最小同名隔离fixture规模，不能改Gate掩盖。

下一安全阶段只能先在另行限定范围内恢复/启动既有本地可丢弃runtime，然后只读核对daemon归属和已有node/tool镜像；再复核上述完整隔离身份与fixture规模。**本报告本身不授权或执行启动、安装、cluster/key/Secret创建。** 当前不能运行SOPS compatibility，也不能进入Summary。

本轮到此停止。没有新增或重跑Policy tests，没有改变SOPS或其他来源验收结论，没有重建总盘点。

证据：`evidence/2026-11-02/sops-isolation-design/` 下的 `capability-inventory.json`、`context-metadata.json`、`identity-assessment.json`、`hardcoded-dependencies.json`、`fixture-design.json`、`initial-colima-observation.json`、`readiness.json` 与完整性记录。
