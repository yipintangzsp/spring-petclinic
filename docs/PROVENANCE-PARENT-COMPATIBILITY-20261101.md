# Provenance frozen production compatibility · 2026-11-01

**Provenance = VERIFIED**，范围仅为当前冻结 `security-validation/v1` 生产代码与 Policy Engine baseline-v1 / standard 的兼容性。181/181 MATCH，drift=0；其中176个有 PASS/WARN/FAIL 判定，5个是原有 off/disabled 的 SKIPPED，未计为 PASS。Policy tests **864/864 PASS**（676基线 +188本轮测试）。

本轮停止于 Provenance。没有开始 Build Provenance、Summary、Router 或其他来源；未修改生产生成/签名、Gate、Jenkins 发布流程、Argo CD 或集群，没有 rollout。没有 SLSA 认证声明。SOPS/age = NOT_TESTED / ENVIRONMENT_BLOCKED 仍阻塞最终全平台验收；Sonar negative = DEFERRED_REAL_NEGATIVE_EVIDENCE 保留。

## 1. 当前实现盘点

| 实现 | 当前行为与本轮范围 |
| --- | --- |
| `vars/securityManager.groovy` | 调用既有 `securityProvenance`；既有 per-module disable/opt-in 不改 |
| `vars/securityProvenance.groovy` | mode、opt-in、Git 来源、candidate 优先级，generate → create → verify，非零退出的 audit/enforce 映射，前序失败跳过、status 报告；执行未修改 Groovy 原文件作对照 |
| `Jenkinsfile.security-audit` | `ENABLE_PROVENANCE` 默认 false；提供 audit candidate 并调用现有 Manager。只读盘点，未执行流水线或后续发布 |
| `infra/security/provenance/plugin.mjs` | 完整 generate/create/verify 与错误、IO、cleanup、非法 action 分支；在 VM 中执行未修改原脚本控制流 |
| `infra/security/provenance/contract.mjs` | 原 `verifyEnvelope` 和 `validate` 为唯一签名/身份验证实现；adapter 与 old script 都复用，不重写算法 |
| `infra/security/scanner-runtime.mjs` | 原 tool manifest 锁、工具 hash/symlink 检查、create Lease；在 old oracle 中执行原函数，外部操作均由 frozen observation 替代 |

没有适用 AGENTS.md。已读取既有 Security Manager contract、production gate inventory、Capability Matrix 及最新 Cosign coverage。旧 contract 是历史检查快照，未重写成新验收结论。

## 2. 格式、身份与关联

- `provenance.json`：当前 security-validation build 的 repository、commit、buildNumber、builderIdentity、pipelineIdentity、candidateImage、buildTimestamp、buildType 和 limitation。明确**不是历史镜像编译证明**。
- attestation：现有 Cosign 产生的 DSSE envelope（payloadType、base64 payload、signatures）；payload 为 in-toto statement，predicateType 固定 `https://devops.local/attestation/security-validation/v1`。历史 statement `_type` 为 in-toto v0.1；不凭此新增 schema/SLSA Gate。
- candidate：固定 `core.harbor.domain/...@sha256:<64小写hex>`。`.git-sha` trim 后必须等于 `PROVENANCE_COMMIT`，且为40位小写hex。
- subject：原 validate 要求恰好1个 subject，`digest.sha256` 等于 expected image 的 digest；predicate.candidateImage 严格等于完整 candidate ref，不能只匹配 digest 忽略 image 名称。
- source：predicate.repository / commit 与当前 expected repository / revision 严格相等。
- builder：`JENKINS_URL + 'job/' + JOB_NAME`；pipelineIdentity 为 JOB_NAME；buildNumber 为当前 BUILD_NUMBER 的 Number 值。生成阶段要求 repository、JENKINS_URL 存在且 buildNumber 为整数。
- metadata：验证原有 buildType=`candidate-security-validation`，buildTimestamp 可被 Date.parse 解析。没有新增 freshness、hermeticity、依赖清单或 invocation 参数要求。
- attestation linkage：原 Cosign `verify-attestation --key infra/security/cosign.pub --insecure-ignore-tlog=true --allow-http-registry --type <既有predicateType> <candidate>`；随后原 verifyEnvelope 验证 DSSE，再由原 validate 检查当前身份。公钥及原 CLI 选项未变。

当前 verifier 不独立检查 subject.name、statement._type 或 timestamp 新鲜度；adapter 没有发明这些规则。subject.name 改变且其他事实有效、旧 timestamp 可解析时，原 Gate 与 standard 都保持原行为，不能把它们写成新增安全保证。

## 3. 完整 Gate 控制流

### generate / create

generate 使用当前 expected 身份产生 predicate，写 `.devsecops/provenance.json`。create 保留既有 Lease、Cosign/SOPS tool check、临时文件权限、解密输出解析、Docker auth、attest 命令、报告与 finally cleanup。没有新增 bundle schema/password Gate；缺 privateKey 导致不可写的既有 fs 错误依然 FAIL。

本轮 create 的 decrypt/attest 是冻结命令观察，值均为不可用 synthetic 占位符。未执行 SOPS/Cosign、未读取真实 signing bundle/age key、未在生产生成签名或修改 signing behavior。

### verify

1. 原 tool manifest 锁、输出目录、auth 临时目录/配置、Cosign tool hash 验证。
2. 原 verify-attestation 命令必须 exit=0；否则抛错，敏感输出仍 suppressed。网络/UNAUTHORIZED/timeout/exec 失败不当作安全负例通过。
3. 保存 raw envelope，再按原算法解析：JSON 对象包成数组；支持数组；JSON parse 失败时按 JSONL 每行解析。坏行不会被偷偷过滤。
4. 原 expected source/candidate 与可信公钥读取。
5. 按原顺序逐个 envelope 调用**未修改的 verifyEnvelope/validate**，找到第一个匹配当前完整身份的 envelope 即停止；全部不匹配则 FAIL。坏 envelope 在有效 envelope 前可跳过；不要求每条都通过。
6. 原 digest、commit、tampered 三个 negative controls 必须被拒绝，随后报告 success。零 commit 与 commit negative control 重合而 FAIL 的既有边界也有冻结样本。
7. finally 先清理 auth 临时目录，再写 verification report；任一步失败均让原脚本失败。报告写入/清理错误不被转换成 PASS。

verify 原分支没有 requireLease，也不检查 SOPS 工具；只有 create 需要。专门对照保留这一事实，没有机械增添前置 FAIL。独立 verify 也不读取本地 provenance.json，而读取远端 attestation 的 CLI 输出；缺本地文件的 create 失败通过其实际命令失败事实表达，不给 verify 发明一个本地文件 Gate。

### Shared Library

原有优先级原样冻结：params 显式 ENABLE_PROVENANCE 布尔值 → env 字符串 `true` → cfg.enableProvenance 布尔值。disabled/off 返回 skipped、无后续操作。没有改变 opt-in。

candidate 优先 cfg.candidateImage → params.AUDIT_CANDIDATE_IMAGE → cfg.image。repository 显式配置优先，否则读取 Git；revision 从当前 Git 获取。原 Groovy build integer 转换及失败行为纳入对照。

- 操作脚本非零：enforce FAIL；audit WARN；后续操作跳过。
- Git/withEnv/凭据绑定/stage/writeJSON 等 Jenkins 步骤异常：按原未捕获异常 FAIL，**不能一律用 audit 降为 WARN**。
- SKIPPED 的 decision=null，与缺证的 NOT_TESTED/NOT_CONFIGURED 明确区分。

## 4. Adapter 与独立对照

新增 `provenance-parent.mjs`、`provenance-workflow.mjs`、`provenance-observations.mjs` 及版本锁；仅在未生产接入的 Policy evaluate 分派 provenance。版本锁绑定原 plugin/contract/runtime/tool manifest/public key 与 Shared Library。原文件漂移需重新冻结，不能继续声称旧兼容。

adapter 消费现有外部命令和文件/IO 观察，调用原验证函数，输出独立 normalizedFacts 与 decision；不实现新签名算法、来源解析规则或接受身份。normalizedFacts 保留 expectedIdentity、逐 envelope 结果/选择位置、验证命令结果、artifact 输入和 runtime 事实；不虚构 severity。原 rawEvidence 不变。

old oracle：执行完整原 plugin 与原 runtime 函数；fs/process/CLI 由只读冻结数据/内存写替身提供。对照命令、image/identity 参数、外部操作顺序以及 PASS 报告内容。

Shared Library oracle：临时本地 JVM + 固定 Groovy 2.4.21，**直接执行原 vars/securityProvenance.groovy**；Jenkins DSL 使用 inert harness。每个 sh 返回值取自同一输入的原 plugin oracle，核对实际 withEnv 身份和被调用 action 列表。不是在测试中手写一个 Groovy oldDecision，不接触真实 Jenkins/凭据库，不声称验证了 Jenkins CPS。

本地运行器仅测试用途，没有安装服务。下载来源、公开发布 checksum 核对及本地 SHA256 见 `local-groovy-runner.json`。历史 Maven artifact 未提供 .sha256，本轮通过 TLS 从 Maven Central 获取并核对其 .sha1，再固定本地 SHA256；不将这项描述为新的生产供应链验收。

## 5. 分类与完整差分

| 分类 | 数量 | 边界 |
| --- | ---: | --- |
| REAL_HISTORICAL | #270 的3份 artifact；1份签名 envelope 本地重验 | 原 predicate / envelope / report 未改；历史报告含 digest/commit/tampered 拒绝。不是新生产调用 |
| 真实历史完整 CLI/前置 transcript 差分 | 0 | 归档没有全部原始执行观察；不补造历史 |
| CONTROLLED_REPLAY：原 JS script | 130 | generate18 / create31 / verify80 / invalid1 |
| CONTROLLED_REPLAY：原 Groovy workflow | 51 | 46个实际判定 +5个显式SKIPPED |
| disposable-key synthetic artifact 输入 | 22 | 上述130的子集；临时内存测试 key，公钥/合成签名可落盘，私钥不导出、不落盘；不是生产 key 或历史事件 |
| SYNTHETIC_UNIT_ONLY 缺证用例 | 6 | 不计完整差分，不把缺证算 PASS |

总完整冻结输入 **181**，old / standard 均为 **PASS30 / WARN4 / FAIL142 / SKIPPED5**，匹配181、漂移0。有决定的 Gate 样本176；5个跳过单独报告。

专门分支：missing1、malformed8、digest6、source8、builder4、其他identity12、tamper/replacement7、infrastructure9、execution2、IO20、prerequisite24、aggregation9。另有 workflow 的全部模式/步骤失败与跳过样本，详见逐条 differential；类别不作历史事故计数。

所有181份落盘 JSON 重载后重新核对输入SHA、standard、decision与raw不变。raw predicate/envelope、subject、source/revision、builder、attestation metadata、命令结果及既有 archive 均未修改。

## 6. 22项最终验收

| 项 | 结果 |
| --- | --- |
| 1 locations | 上述 Shared Library / Manager / audit entry / plugin / contract / scanner-runtime |
| 2 format | 既有 provenance predicate + DSSE/in-toto envelope；原报告结构 |
| 3 subject/digest | 单subject、digest与完整candidateImage双绑定，原 verifier 不变 |
| 4 source identity | repository / revision / checkout commit 严格原比较 |
| 5 builder identity | Jenkins URL/job、pipelineIdentity、当前buildNumber原比较 |
| 6 adapter implemented | YES |
| 7 historical | #270 artifacts3份；真实 envelope 本地重验1份；历史完整执行差分0 |
| 8 controlled | 181完整 replay：JS130 + Groovy51 |
| 9 synthetic | 22个 disposable-key artifact 输入（replay子集）；另6个缺证 unit-only |
| 10 missing/malformed | 1 / 8 个专门样本 |
| 11 digest/source/builder | 6 / 8 / 4，其他identity12 |
| 12 tamper/replacement | 7 |
| 13 execution/infra | execution2、infrastructure9、IO20、prerequisite24；另含workflow异常 |
| 14 old decisions | PASS30 / WARN4 / FAIL142 / SKIPPED5 |
| 15 standard decisions | PASS30 / WARN4 / FAIL142 / SKIPPED5 |
| 16 complete differential | 181（176决定 +5显式跳过） |
| 17 match/mismatch | 181 / 0 |
| 18 raw unchanged | YES；181落盘重验；108原安全源和264份已接受Cosign artifacts无漂移 |
| 19 gaps | 历史完整CLI/前置 transcript、自然 parent FAIL、实时生产/CPS验收未补；不冒充历史或在线证明，不构成本次冻结兼容 blocker |
| 20 final status | VERIFIED，仅 frozen production source baseline-v1 / standard compatibility |
| 21 Policy tests | 864 PASS / 0 FAIL；新188，原676保留 |
| 22 leave phase | YES，仅Provenance；本轮停止 |

## 7. 证据与复核

证据目录 `evidence/2026-11-01/provenance-parent/`：

- `acceptance.json`、`differential.json`、`workflow-differential.json`、`fixtures/`；
- `historical-evidence-index.json`、`source-preservation.json`、`before-sha256.json`；
- `persisted-fixture-check.json`、`artifact-safety-check.json`、`artifact-sha256.json`；
- `local-groovy-runner.json`、`policy-tests.log`、`production-coverage-update.json`。

复核从仓库根运行 `node --test infra/security/policy/*.test.mjs`。原 JS oracle 和本地 Groovy oracle 都不访问 registry/Jenkins/cluster。Groovy jar 默认位于 `/tmp/provenance-policy-groovy/groovy-all-2.4.21.jar`，可通过 `PROVENANCE_GROOVY_JAR` 指定本地副本，SHA256 固定为 `de65260cf2070442e99882f2f3d72e7531725c1e6a257446cc0cea525c607bd0`。缺依赖或 hash 不符明确失败，不自动联网、不偷偷跳过测试。运行器来源见其 JSON 索引。

仅适配/证据文件有新增；原 tracked 用户文档修改保留。11个本轮保护文件与HEAD一致，108个原安全源文件哈希不变，已接受Cosign证据264项哈希全部不变。测试用临时workflow输入目录已在finally删除；没有生成真实临时私钥文件，没有读取或导出生产Secret。没有实际 Summary 接入。
