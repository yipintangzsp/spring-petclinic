# SOPS authoritative baseline — sm-sops-20261102-02

```text
SOPS_FIXTURE_INSTANCE_READINESS = READY
AUTHORITATIVE_BASELINE = sm-sops-20261102-02
STOP
```

这是新隔离 fixture 基线，不是 SOPS compatibility VERIFIED。已按授权顺序完成 Node 复验、工具重建、两对key生成、namespace/真实SA/RBAC/token/kubeconfig/auth检查、Lease/Secrets/密文与解密验证。Gate执行0、Policy差分0、Summary接入0、rollout0。

## 执行结果

| 步骤 | 结果与证据 |
| --- | --- |
| Node executor | 固定22.23.3官方archive及1967runtime文件摘要重新匹配；原生Linux/aarch64 node -e和.mjs probe exit0，Gate只解析/链接、body不执行；5/5guard sanity。 |
| SOPS/age | 官方固定SOPS3.13.3、age/age-keygen1.3.2重新下载于新私有目录，官方资产SHA、冻结binary SHA、ELF64 AArch64与实际版本全部匹配。无全局安装、无镜像源或浮动版本。 |
| 两对key | 在真实SA创建之前，于专用非root/无网络容器独立生成。baseline与negative recipient不同，私钥0600、目录0700。未打印/归档private value。 |
| namespace/SA/RBAC | 3namespace、3SA、5Role+5RoleBinding+限定identity ClusterRole/Binding。23个新对象，全部UID与已清理-01不同。automount=false，无cluster-admin grant/通配权限。 |
| 短时token | isolated TokenRequest签发，单API audience，真实SelfSubjectReview检查username/groups/SA UID，核对namespace及cluster UID。独立min kubeconfig0600，仅private root保存，不输出token，无admin执行fallback。 |
| auth can-i | 使用真实MIN_RBAC guard child/实际kubectl逐条检查，10项允许yes、17项拒绝no，共27/27匹配；不以synthetic reader代替。 |
| Lease | data-infra/platform-heavy，holder=sm-sops-20261102-02。只用合成holder，不复制production值。 |
| Secrets | 四个固定名字、既定类型和合成data key；get/create/解密结果的canonical data指纹一致，不输出原值。 |
| SOPS fixtures | 四条固定relative path均以本轮baseline recipient加密。加密时未重新生成key。真实MIN_RBAC guard先校验本轮身份后，才启动credential-free crypto容器。 |
| 正向/负向 | 4/4真实解密exit0，type/data/scope结构完全一致；wrong-key真实exit128、stdout0，无baseline/production key fallback。 |
| authoritative baseline | authoritative-baseline.json+独立SHA文件；完整对象UID/creation time/RV/规则、Secret type/keysets/data hash、ciphertext/publicrecipient/tool/source hash与Node证据链。 |
| STOP/保留 | 4临时明文删除、临时helper容器全部--rm；保留23对象、两对私钥/recipient、密文、工具、private min kubeconfig及安全证据。原kind保留。 |

## 新 authoritative source

后续只以 **本目录 authoritative-baseline.json** 为当前baseline，-01与历史manifest仅是历史证据，不得复用其UID或说旧已删除fixture仍READY。当前root：

`/private/tmp/sm-sops-20261102-02-oc3es03e`

baseline SHA256：`da0261941e7e96d9e9f7433668d40f7e3c5d39db4b5a6224f45ecbf4c1005bd8`。private root以0700隔离，无生产路径重叠。安全baseline副本亦存root/evidence，不含private age key、token、kubeconfig credentials或plaintext Secret values。

真实MIN token到期（Asia/Shanghai）：**2026-11-02T17:03:13+08:00**。这个到期值是实际签发记录，不是永久有效。下轮先重验有效期；过期则停止，通过授权的隔离管理端重新签发并固定新的config hash，不回退admin执行Gate。

## 对象身份

| Kind | Namespace/name | 新 UID |
| --- | --- | --- |
| Namespace | petclinic | 2e500275-bc08-4366-a2cd-40abf5708446 |
| Namespace | devsecops-system | c1fc488a-9ba9-44df-9db6-c41525bbce89 |
| Namespace | data-infra | 6a39bd35-b7f0-4795-b8cc-b2d4c3607525 |
| ServiceAccount | devsecops-system/platform-secret-reconciler | 84356ecc-4e2e-4ab5-a47e-322a7fac58ef |
| ServiceAccount | devsecops-system/kyverno-admission-controller | 7ec5d538-7a81-4ef6-bac0-7d73b0fc7e13 |
| ServiceAccount | devsecops-system/security-fixture-executor | feb5c628-5e3a-4bcc-ac9c-06e621536c1d |
| Role | petclinic/sops-fixture-reconciler-business | 5f8bd9e2-e686-41da-84f9-abea1417a114 |
| RoleBinding | petclinic/sops-fixture-reconciler-business-binding | c2ce7b6c-51da-4717-b675-8ff034898d92 |
| Role | devsecops-system/sops-fixture-reconciler-registry | a2812987-efb4-43d7-b186-4d25f8d5108d |
| RoleBinding | devsecops-system/sops-fixture-reconciler-registry-binding | 147e3598-02ae-432d-80fd-e41b06d567ae |
| Role | devsecops-system/sops-fixture-verifier-registry | 87201509-2879-4d3e-9028-24af2ac494ee |
| RoleBinding | devsecops-system/sops-fixture-verifier-registry-binding | d4b98fd8-36b0-4c0f-b030-2879559367a8 |
| Role | data-infra/sops-fixture-executor-lease | 37ef0791-b069-4075-b4c3-fccf72e8c515 |
| RoleBinding | data-infra/sops-fixture-executor-lease-binding | 01633737-6bc7-42a2-a7a8-8d878a333b9b |
| Role | devsecops-system/sops-fixture-executor-impersonation | 806bbdd7-776e-4ae6-8d59-c5feba3eb4e2 |
| RoleBinding | devsecops-system/sops-fixture-executor-impersonation-binding | 3e81d47b-ac3f-4c65-9efc-8f347b3d54b5 |
| ClusterRole | sops-fixture-executor-identity | 0332d206-6f54-4db5-a491-510b4e036b60 |
| ClusterRoleBinding | sops-fixture-executor-identity-binding | 42710a41-8bcc-474a-8a7f-f11f982edf08 |
| Lease | data-infra/platform-heavy | ff5e9671-9b22-4a88-892c-64eeac8307cb |
| Secret | petclinic/petclinic-db | 2e650994-d040-4298-92e2-c4e4c50969ad |
| Secret | petclinic/rabbitmq-client | be0dae34-d534-44fe-ad83-0fc278873db5 |
| Secret | petclinic/petclinic-harbor-pull | c16e5234-f79a-4559-a19a-f275d7ca4122 |
| Secret | devsecops-system/kyverno-registry-pull | 7eb84227-e1d8-4d79-8269-5d8f4b1e49ca |

Namespace控制器的default SA/root-CA ConfigMap为自动资源，不冒充手工创建的第四个SA；后续清理必须识别自动资源与外来对象，不能批量强删。

## 基线完整性

23对象在末尾重新读回，UID与本轮create响应一致；RBAC rules/subjects、Lease holder、Secret type/data hash、加解密数据指纹、四密文SHA均一致。两publicrecipient SHA及完整工具SHA留档。明文仅private staging暂存，计算hash后删除。私钥未作为artifact复制，密文/工具/基线按本轮STOP要求保留。

SOPS --version在network=none环境尝试upstream版本检查而被拒绝，不影响已验证的固定3.13.3版本；没有因为该警告打开网络或选latest。官方完整性验证是固定官方HTTPS SHA+生产锁+ELF/版本验证，本轮没有宣称GPG/Sigstore/Sigsum签名验证完成。

## 保护与范围

- 4043个本轮前已存在仓库文件摘要全部未变，包括production Gate/runtime/adapter/Policy/Summary/Manager/guard和历史evidence。
- 用户kubeconfig、SSH、default/security-test Colima及Docker配置摘要未变，globalDockerContext=default。配置仅按字节算SHA，不声称从未打开任何配置文件；production credential value的提取/解析/使用为0。
- production API0、productionSecret/credential value0、productionagekey0。只访问经同一guard固定的测试cluster。无k3s/CNI/production业务更改。
- Node无害启动探针沿用上轮获批synthetic live-verifier单元方式；**此轮fixture的MIN身份认证和27auth检查是真实API/token，并非synthetic**。两种证据清楚分开。
- 当前Node容器启动验证不构成真实Node Gate kubectl transport或逐调用观察采集完成。后续兼容性仍须先解决并验证这一接线，不能用mock live-verifier或Python单元观察当真实Gate事实。

## 证据入口

- authoritative-baseline.json / authoritative-baseline.sha256：唯一当前baseline与安全元数据。
- node-runtime-integrity.json、node-revalidation/startup-result.json：Node完整性与实际原生启动。
- cluster-preflight.json、min-identity.json、rbac-verification.json：真实隔离身份与27条授权检查。
- toolchain-download.json、tool-versions.json、key-evidence.json、crypto-evidence.json：工具/publickey/解密事实。
- object-ledger.json、baseline-snapshot.json、plaintext-cleanup.json：对象身份和恢复依据。
- protected-after.json、runtime-after.txt：保护与临时资源清理。
- evidence-index.json、index-validation.json：引用存在与hash验证。

已STOP。没有自动执行Gate、Policy differential或其他结构性升级。
