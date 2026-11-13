# Cosign frozen production compatibility · 2026-11-01

结论：**Cosign = VERIFIED，限当前冻结实现的 baseline-v1 / standard 决策兼容性。** 260 个完整冻结输入，旧实现与独立 adapter 全部一致，drift=0；Policy tests 676/676 PASS。本轮不代表在线密码学验证、registry/admission 实时健康或新版本发布认证。

没有执行真实签名、解密或 registry/Kubernetes 请求，没有读取生产私钥、密码或 age key。没有修改原 Gate、Jenkinsfile、发布流程、Summary、Argo CD 或集群。没有开始下一来源。SOPS/age = NOT_TESTED / ENVIRONMENT_BLOCKED、Sonar negative = DEFERRED_REAL_NEGATIVE_EVIDENCE 保留。

## 当前实现与边界

| 入口 | 当前实现 | 本轮覆盖 |
| --- | --- | --- |
| Security Manager production Cosign Admission | `resources/security-manager/petclinic-adapter.json` → `node infra/security/signing.mjs admission`；`vars/securityManager.groovy` 按退出码记录成功/失败 | 完整 signing admission 脚本；104 个冻结差分 |
| Signature Admission Gate | `Jenkinsfile:246` 附近调用同一 admission 脚本 | 同上；没有运行 Jenkins |
| Sign Existing Release Baselines | `Jenkinsfile` → `signing.mjs bootstrap` | bootstrap 签名后验证、当前/回滚 image 去重及错误路径；54 个差分 |
| DevSecOps Release Evidence | `Jenkinsfile` → `signing.mjs release` | 仅该 Cosign 脚本已有 source/digest/scan 收据、image/证据签名后验证路径；71 个差分。未处理 Promotion、Provenance 或发布逻辑 |
| 通用插件 | `infra/security/manager/tool.mjs cosign` | 完整 Cosign 分支与脚本异常/报告/退出处理；30 个差分 |
| 非法显式 mode | `signing.mjs` 前置校验 | 1 个差分 |

依赖：`scanner-runtime.mjs` 的原 manifest hash、Lease、verifyTools/run 逻辑，以及 `cosign-verification.mjs` 原分类函数。工具清单锁定 Cosign 3.1.4、SOPS 3.13.3。本轮原 runtime 函数也在 oracle 内执行，实际系统调用全部替换为冻结观察。没有用一个手写 oldDecision 常量代替旧 Gate。

`registry-dns.mjs` 是 bootstrap 前独立的共享 DNS 配置管理步骤，会写 ConfigMap；已只读盘点，**没有执行或适配该配置管理步骤**。这里证明 Cosign 验证脚本的兼容性，不宣称整个 Jenkins、DNS 管理或发布链路已重验。网络/DNS/registry 故障以它们传入 Cosign/registry 调用的现有失败事实覆盖。

## 输入与真实 binding

- image 必须按当前脚本使用 `@sha256:<64 hex>` 固定。signImage 进一步限定 `core.harbor.domain/petclinic/<repo>@digest`；没有扩大镜像域/项目范围。
- admission 为 signed / unsigned / wrong-key 构造已有 OCI config/manifest。registry 返回的 `docker-content-digest` 必须等于该 manifest 字节的 SHA256。fixture 中重建的是当前代码原有字节，不假设 tag 指向何处。
- 默认私钥签名后，原 `cosign verify` 必须成功，JSON 非空，**每一条** `critical.image.docker-manifest-digest` 必须等于被验证 image 的 digest。一条正确、一条错误也 FAIL。
- release 原有 built.source、Harbor index digest / Success / 两个 scan 收据、artifact.source / imageDigest 比较全部保留。index 和子 digest 去重后逐一验证；任一失败则整体失败。
- artifact `sign-blob` / `verify-blob` 的结果来自原 Cosign 命令事实；adapter 不实现签名算法，不重算漏洞或构造签名有效性。
- 通用插件只接受 digest ref 和 checkout 内 public-key 路径；依赖 Cosign exit=0 与非空 JSON。原通用分支没有额外的 claim digest 比较，本轮没有增加该规则或声称已经存在。另一 digest 的签名由 Cosign 拒绝的事实仍 FAIL。

身份是 **key-based**：`infra/security/cosign.pub`；解密 bundle 对应的 `cosign public-key` 输出必须与可信公钥文本 trim 后完全相同。没有证书/OIDC issuer/subject 规则。当前 CLI 原有 `--insecure-ignore-tlog=true`、`--allow-http-registry` 保持，未设计新策略。

只读盘点 `integration-resources.json`：现有 `devsecops-signed-images` 为 Enforce、failurePolicy Fail；固定公钥、required/verifyDigest/mutateDigest=true，匹配既有 Harbor 范围。adapter 消费实际/冻结 admission allowed/denied 和 policy diagnostic，**不实现 Kyverno engine**，也不假设本轮在线 policy 状态与仓库一致。

## 判定与错误语义

默认签名验证失败、缺签名、错误 key、错误 digest、畸形输出、命令异常、registry HTTP/网络异常、报告写失败都保持原 FAIL。当前这些路径没有 WARN。generic audit 中执行错误仍 FAIL。

admission 是正反例自检：signed 必须 CLI 成功且 admission 接受；unsigned / wrong-key 必须由现有签名失败 diagnostic 拒绝，且 admission 拒绝 diagnostic 包含 `devsecops-signed-images`。**预期负例被拒绝意味着整个自检可 PASS**，绝非把无签名候选镜像放行。负例的连接超时、UNAUTHORIZED、未知错误不能充当成功的签名拒绝；原分类器会阻止 stage PASS。

原样保留的非新增规则：

1. 清理操作抛错会 FAIL；但 rm 后 exists=true 只令 `temporaryPrivateFilesRemoved=false`，原脚本不会据此 FAIL。3 个差分保留该行为，未悄悄收紧。
2. registry token JSON 的 `.token` 被读取，但没有独立的 token 非空 Gate；缺 upload Location 时 URL 构造也有现成回退语义。冻结测试保留，不把模拟成功响应解释为真实 registry 会接受无 token。
3. 空/缺失观察不是扫描成功。adapter 返回 NOT_CONFIGURED 或 NOT_TESTED、decision=null。6 个缺证测试与完整输入差分分开计数。

## Adapter / oracle

新增：`infra/security/policy/cosign-parent.mjs`、`cosign-observations.mjs`、`cosign-parent.test.mjs`、`versions/cosign-parent-baseline-v1.json`。仅在尚未生产接入的 Policy `evaluate` 增加 cosign 分派。

adapter 独立执行当前分支的既有校验谓词，消费原始 exit/status/stdout/stderr、image/digest、public-key 参考、registry/admission、前置/IO 事实，输出独立 Policy decision。rawEvidence 保留不变；normalizedFacts 单独列出验证命令、image/artifact ref、key reference、退出状态、executionError 和原输出，不凭空生成 severity。

oracle 在 Node VM 中执行**未改写控制流的完整原脚本**（只移除 import 声明并注入依赖），包括真实 scanner-runtime 前置函数和原 checkCosignVerification。共享的 observation reader 仅提供冻结数据，不包含 Gate 谓词。所有网络/进程/文件写/临时目录都是内存模拟。old 与 adapter 的命令参数、image/ref 和外部观察顺序也逐项比较。

每个输入同时通过 old 与 adapter → baseline-v1/standard；断言 decision 相同、默认 standard、raw 字节序列不变、PASS 报告 images/cases/verification/cleanup 字段一致。所有 260 个输入还从已写入 JSON 重新加载，核对输入 SHA256、decision 和 raw 不变。low/override/audit 不会软化 frozen Cosign FAIL。

版本锁绑定当前 8 个实现/信任源 SHA256，原实现变化即 POLICY_ERROR，必须重新冻结。108 个既有原安全源文件哈希均未改变。

## 证据分类与数量

| 分类 | 数量 | 可证明内容 |
| --- | ---: | --- |
| HISTORICAL_ARCHIVE | 1 份 Jenkins petclinic-ci #270 收据，3 个子结果 | signed 接受、unsigned/wrong-key 拒绝；具体 digest refs、source、时间、清理标记 |
| 历史完整 execution transcript 差分 | 0 | 收据没有完整 CLI stdout/stderr/前置观察，未伪装成完整历史重放 |
| REAL_CONTROLLED_EXECUTION | 0 | 本轮没有真实 Cosign/registry/signing 执行 |
| SYNTHETIC_FROZEN_COMPLETE_STAGE | 260 | 完整原脚本 frozen-decision 兼容性；不冒称生产事故或密码学验证 |
| Parser/unit-only 用例 | 不计入以上 260 | 另有缺证、override、receipt 对应测试；原分类器 2/2 单独通过 |

历史索引见 `evidence/2026-11-01/cosign-parent/historical-receipt-index.json`。原归档未修改。重建 build270 config/manifest 产生的三个 digest 与历史收据逐一相同；这证明引用字节的对应，不补造缺失的 CLI 输出。

260 个差分中：PASS=18，FAIL=242，WARN=0；old / standard 完全一致。分类计数：

- 明确缺签名：4；明确错误 key 拒绝：4；可信公钥 mismatch：3。
- digest-binding：18；artifact tamper：1；另有 release/artifact 绑定和聚合分支，详见 acceptance.json。
- infrastructure：61；registry 分支：13；IO/cleanup：33；prerequisite：60。
- 各类不是 260 个全部分类的简化加总；完整互斥 branch 明细在 differential.json / acceptance.json。每个完整 admission 正例还包含 unsigned / wrong-key 两次预期拒绝。

## 本轮验收（21 项）

| 项 | 结果 |
| --- | --- |
| 1 production locations | 上述 signing/manager/runtime/CLI classifier、生产映射与 Jenkins 入口 |
| 2 inputs | 固定 image/digest、CLI/registry/admission/前置/IO 事实 |
| 3 digest binding | 原 manifest header、所有 claim digest、release index/child 与 artifact/source 保留 |
| 4 signer identity | 当前可信公钥；无新增 identity 或范围 |
| 5 adapter implemented | YES |
| 6 historical samples | #270 收据1份/子结果3个；完整历史差分0 |
| 7 real controlled samples | 0 |
| 8 synthetic frozen samples | 260 完整差分 |
| 9 missing signature | 4 个专门样本；其余 admission 自检也包含预期拒绝 |
| 10 wrong signer/key | 4 个拒绝样本，另3个 public-key mismatch |
| 11 digest/replacement/tamper | digest-binding18，tamper1，另见 binding/aggregation 分类 |
| 12 execution/infra | infrastructure61、registry13、IO/cleanup33，详见逐样本记录 |
| 13 old decisions | PASS18 / FAIL242 / WARN0 |
| 14 standard decisions | PASS18 / FAIL242 / WARN0 |
| 15 complete differential | 260 |
| 16 match / mismatch | 260 / 0 |
| 17 raw preserved | YES；磁盘重载 SHA/decision/raw 再验260个 |
| 18 gaps | 缺历史完整 CLI/前置 transcript、自然 parent FAIL 事故；实时健康未验证。这些不冒充已通过，也不阻塞本次 frozen compatibility |
| 19 final Cosign | VERIFIED（限定上述 frozen-source 范围） |
| 20 Policy tests | 676/676 PASS；比408基线新增268。原 Cosign 分类测试另2/2 PASS |
| 21 leave compatibility | YES，仅 Cosign。全平台仍未验收，不开始下一来源 |

关键证据：`acceptance.json`、`differential.json`、`fixtures/`、`artifact-sha256.json`、`persisted-fixture-check.json`、`source-preservation.json`、`policy-tests.log` 与 `production-coverage-update.json`，均在 `evidence/2026-11-01/cosign-parent/`。

复核：从仓库根执行 `node --test infra/security/policy/*.test.mjs`，以及 `node --test infra/security/cosign-verification.test.mjs`。测试仅更新专用冻结 evidence，不创建真实签名/Pod/临时私钥，不写 actual security-summary.json。生产私钥绝不能作为这些测试 fixture 输入；这里使用的 bundle 值是显式无效的 synthetic 占位符。
