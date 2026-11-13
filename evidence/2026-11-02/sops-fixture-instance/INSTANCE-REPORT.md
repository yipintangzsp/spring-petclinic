# SOPS isolated fixture instance — 2026-11-02

```text
SOPS_FIXTURE_INSTANCE_READINESS =
READY
```

**范围仅 fixture 实例验证，不代表 Gate 或 Policy compatibility VERIFIED。** 本轮 Gate、old-vs-policy、Summary 集成及 rollout 均为 0。用户已明确将附件中的两个 SA 修正为最终设计的三个；未擅自合并身份或扩权。

## 32 项验收

| # | 项目 | 真实结果 |
| --- | --- | --- |
| 1 | isolated identity | security-test Colima / explicit Docker endpoint / kind security-test-sops；guard 验证 CA、kube-system UID，唯一 node Ready arm64 |
| 2 | SOPS version | 3.13.3，Linux ELF64 AArch64 实际运行 |
| 3 | SOPS source/hash | 官方固定 release asset；实际 SHA256 53b0abacd38ef1b12a66d6c100956691b9cefce018d91f81e73ddf7438b94d77，与审核值及生产文件锁一致 |
| 4 | age version | age / age-keygen 1.3.2，Linux ELF64 AArch64 实际运行 |
| 5 | age source/hash | 官方 age-v1.3.2-linux-arm64.tar.gz SHA256 6b8dc4333c53a5a57c9e5834e3a48f92605d7154014cd07269ff3327db5d37f4；两个解包 executable 均匹配冻结文件锁 |
| 6 | fixture root | /private/tmp/sops-fixture-sm-sops-20261102-01-ewum52al |
| 7 | baseline recipient | age1x22zauqwrc95g96jjk8yuky7465a2ltjwcznszday4xsp0wr2e6s82xu6n |
| 8 | wrong-key recipient | age1wyyxujzg9020nphxhkgp7d3w2vx5eduezpmsdwv5rzhrreph5sqqpsvp3p；与 baseline 不同 |
| 9 | namespaces | 3 个，具体 UID 见下表及 identity manifest |
| 10 | ServiceAccounts | 3 个：两个 Gate 身份 + security-fixture-executor；automount=false，UID 见下表 |
| 11 | RBAC allowed | 10 项预期允许全部 yes |
| 12 | RBAC denied | 17 项预期拒绝全部 no；只执行 auth can-i，不读 Secret 值 |
| 13 | Lease | data-infra/platform-heavy，holder=sm-sops-20261102-01，UID 见下表 |
| 14 | Secrets | 4 个 synthetic Secret，type/keyNames/UID/值指纹已记录，未在日志或报告输出值 |
| 15 | value fingerprints | SHA256(canonical JSON of synthetic base64 data map, sorted keys, compact separators)；API create/read、原始 fixture、解密结果一致 |
| 16 | encrypted fixtures | 4 个 encrypted/infra/security/secrets/<name>.enc.json；均只含 baseline recipient；加密 SHA 见下表 |
| 17 | positive decrypt | 4/4 exit0，JSON structure、type、data 完全一致 |
| 18 | wrong-key decrypt | 真实 SOPS decrypt exit128，stdoutBytes=0；stderr 只记录长度/摘要；无 Policy 判定 |
| 19 | identity manifest | fixture-identity-manifest.json；专用 root/evidence 中亦保留副本；不含 private keys、token、kubeconfig credentials 或明文值 |
| 20 | 12-case preconditions | 12 个 READY_TO_EXECUTE（仅 fixture 前置条件），无 NOT_APPLICABLE/BLOCKED；本轮所有 mutation/Gate/Policy cases 均 NOT_RUN |
| 21 | immutability snapshot | 23 个手工对象 UID 与创建记录相同；RBAC rules/subjects、Lease holder、Secret 类型/值指纹复核一致；4 密文 SHA 不变；public recipient 指纹及工具 SHA 留档 |
| 22 | production files modified | NO；3933 个既有仓库文件全部摘要未变，含 Gate/runtime/Manager/Summary/guard |
| 23 | user kubeconfig unchanged | YES，仅完整性字节摘要对照；不解析/导出或使用生产 credential 值 |
| 24 | protected configuration unchanged | YES，SSH、default/security-test Colima、Docker config、dedicated config 全部未变；global Docker context=default |
| 25 | production API access | 0 |
| 26 | production Secret/credential value reads | 0 值提取/使用；本轮只读/写隔离 synthetic Secrets 和专用 test credential。配置文件 hash 是字节访问，不能写成从未打开配置文件。 |
| 27 | production age key reads | 0 |
| 28 | resources/files created | 23 个手工 K8s 对象、2 对 age key、4 密文；3 个 namespace 控制器自动 default SA/CA ConfigMap 不冒充额外手工身份。工具、私有 test kubeconfig/profile 与 helper/evidence 均限专用 scope。 |
| 29 | plaintext cleanup | 4/4 transient plaintext 删除，plaintext 目录为空；两个 tool/helper 容器 --rm，最终仅原有 kind control-plane 容器 |
| 30 | instance readiness | READY（当前身份/工具/资源/crypto 状态，不是生产兼容性结论） |
| 31 | blocker | 无当前 fixture blocker；下一阶段必须重新检查短时 token、guard、对象 UID 与 baseline hash |
| 32 | next permitted action | 等待下一轮明确授权后，先重验身份/有效期与 baseline，再执行真实 frozen Gate/standard differential；本轮已 STOP，不自动运行 |

## 对象身份（安全元数据）

| Kind | Namespace/name | UID |
| --- | --- | --- |
| Namespace | petclinic | 0d37edab-4263-4086-b06e-de61554afba8 |
| Namespace | devsecops-system | 6c629647-ec82-4645-a6d0-d7318c5bb711 |
| Namespace | data-infra | 90a85471-a80b-430d-8b6e-f8c4b43f16ac |
| ServiceAccount | devsecops-system/platform-secret-reconciler | fe1a412f-ea21-46f6-8c9c-116b5c56996a |
| ServiceAccount | devsecops-system/kyverno-admission-controller | 4bf66f2c-29f0-45f8-a49a-75b31bbbf11c |
| ServiceAccount | devsecops-system/security-fixture-executor | ffed62de-e3a1-4125-b981-4280d8af745a |
| Role | petclinic/sops-fixture-reconciler-business | a83228d1-bba7-41a4-89eb-277918dfacec |
| RoleBinding | petclinic/sops-fixture-reconciler-business-binding | 9ed85b1e-dedc-479a-864a-601f2c50bf7c |
| Role | devsecops-system/sops-fixture-reconciler-registry | 380c79cb-4a50-4287-af02-0b355eab2018 |
| RoleBinding | devsecops-system/sops-fixture-reconciler-registry-binding | 10239d8d-38e2-4b12-ae6d-0a8ddcee2a46 |
| Role | devsecops-system/sops-fixture-verifier-registry | 9b2030a2-84a7-400e-b9a1-0f266d504714 |
| RoleBinding | devsecops-system/sops-fixture-verifier-registry-binding | e8a0fe36-6252-4418-a3a7-92f6516688aa |
| Role | data-infra/sops-fixture-executor-lease | d462ff87-2593-45bc-8cd6-64c58a3e2090 |
| RoleBinding | data-infra/sops-fixture-executor-lease-binding | db4424e0-22d4-4d4a-ba89-4bab4e3856c0 |
| Role | devsecops-system/sops-fixture-executor-impersonation | eec9d9c8-93c4-489d-9370-8570ae138271 |
| RoleBinding | devsecops-system/sops-fixture-executor-impersonation-binding | 0834e6de-ae3d-4460-84fb-2d34e67f80cc |
| ClusterRole | sops-fixture-executor-identity | 16630222-7eae-442a-8e36-0ed26630a1af |
| ClusterRoleBinding | sops-fixture-executor-identity-binding | bea0f4f0-7989-4aa3-a854-6ab261fb3b83 |
| Lease | data-infra/platform-heavy | 665bee9b-245e-4d2f-984f-5824ae214c6c |
| Secret | petclinic/petclinic-db | 591417e3-c18b-4b55-b479-408df8ecf6f4 |
| Secret | petclinic/rabbitmq-client | aa37e76e-df05-4946-a952-901d4d5d6021 |
| Secret | petclinic/petclinic-harbor-pull | d81aa83f-3413-435c-81e2-4bbd8b233a65 |
| Secret | devsecops-system/kyverno-registry-pull | 9bc7bea0-8c89-469a-94a0-b621d9f5459b |

## 密文与值指纹

| Secret | Type / keys | Ciphertext SHA256 |
| --- | --- | --- |
| devsecops-system/kyverno-registry-pull | kubernetes.io/dockerconfigjson / .dockerconfigjson | 2312418ff0ecfe038de34830276c4ad5526d33806c72c6a93879d11e6d0ff0fc |
| petclinic/petclinic-db | Opaque / password, username | f76858589228801f37dc9d9adf063f797b78296db2762b10b3a5148646b21140 |
| petclinic/petclinic-harbor-pull | kubernetes.io/dockerconfigjson / .dockerconfigjson | b68f95d1da2747b5e64b9536368d2092b68a4210ff3bf547e9baa4d09b53a29a |
| petclinic/rabbitmq-client | Opaque / password, username | 0ca85148a0cabc4dcb4d9884eb1f81d4445ab983e485e5b88e63936dd148bccc |

## 执行与安全边界

- 资源管理 helper 每次 API 操作均重新调用原 guard validate + verify_live，以固定 test-admin profile 完成 namespace/对象 bootstrap；没有另选 context。最终 crypto child 由真实 MIN_RBAC_EXECUTOR 的 guard.execute 启动，管理凭据没有交给 executor。
- 最小权限 token 由隔离 API TokenRequest 签发；真实 SelfSubjectReview 匹配 username/SA UID/groups，namespace UID/cluster UID 匹配。只保存 private scope 0600 kubeconfig；报告中仅 path/hash/issuer/audience/expiry。
- Crypto 容器非 root UID65532，无网络、无 host mount、只读 rootfs、drop ALL、临时 tmpfs。stdin 仅传 test tools、synthetic plaintext/keys；metadata 中的 kubeconfig/profile/token 被显式排除。输出 tar 仅限 keys/ciphertext/安全 crypto metadata，均写回唯一私有 root。
- 解密时 HOME 为空，每次只指定该次 test identity 文件，无 host HOME/生产 key 路径/SSH/AWS/registry credential；wrong-key 无基线 key fallback。两对 private key 均 0600，keys 目录 0700；不进 git、不在证据目录拷贝私钥。
- SOPS --version 试图查询 upstream latest 的请求在无网络容器中被拒绝，版本本身已确认；没有使用 latest asset、没有更改 DNS/网络或放开出口。下载只用固定官方 URL，首轮 timeout 后续传，完整文件 SHA 匹配才执行。
- 此轮完成的是已审核官方 SHA + frozen binary locks + ELF + 版本校验。未运行 Sigstore/Sigsum 签名验证，不宣称完成独立签名/发布者证明。

## 保留与下一阶段时效

两个 private key、四份密文、23 个对象、工具均保留，未清理 baseline。fixture root 为私有临时目录，不是永久密钥库。

当前 executor token 到期时间（Asia/Shanghai）：**2026-11-02T15:52:49+08:00**。后续若已过期必须 fail closed，在授权范围内重新签发并重新固定配置；不能回退 admin 执行 Gate，也不能声称永久有效。Lease duration 不是冻结 Gate 的 expiry 判断；本轮只设置 approved holder，不改其语义。

矩阵 READY_TO_EXECUTE 只说明 fixture 中存在可供各 case 使用的工具、密文、目标 UID/值和管理恢复权限。实际 Gate 观察接线、UID/value mutation 时序、失败恢复与 old-vs-policy 一致性必须在下一阶段用真实执行验证，不以本轮密码学检查代替。

证据索引：toolchain-download.json、tool-versions.json、cluster-preflight.json、min-identity.json、rbac-verification.json、object-ledger.json、crypto-evidence.json、guarded-crypto-execution.json、fixture-identity-manifest.json、baseline-snapshot.json、future-matrix-readiness.json、plaintext-cleanup.json、protected-after.json、runtime-after.txt。

没有修改 production Gate/runtime/Manager/Summary 或任何发布流程，没有触发 Jenkins/rollout，没有新增 Policy compatibility 样本。
