# Policy 求值粒度与预审批结果范围

POLICY_EVALUATION_SCOPE = RESOLVED

PRE_APPROVAL_SUMMARY_SCOPE = RESOLVED

SUMMARY_VERSION_MIGRATION_READINESS = READY

以上仅为**设计就绪**。生产仍未接入新版 Policy Engine；POLICY_METADATA_SUMMARY_INTEGRATION 仍为 INCOMPLETE。本轮没有实现 V2、结果生产器、聚合器或消费器，没有修改生产代码、既有证据、Gate 或 accepted hash。

最新附件明确采用 PER_SOURCE_SINGLE_EVALUATION，不再要求 GLOBAL_SINGLE_EVALUATION。上一轮“现有 API 不支持全流水线一次求值”的取证仍正确，旧 NOT_READY 报告保留。本轮通过更正不变量及固定时间边界解除B1/B2，不改写历史。

证据目录：evidence/2026-11-02/policy-evaluation-scope-design/。本设计补充上一轮 SUMMARY-VERSION-MIGRATION-DESIGN-20261102.md，版本化完整性契约及旧哈希保全方案继续沿用。

## 1. 实际粒度、调用者和原有 Gate

现有 evaluate(facts,config) / evaluateAsync(facts,config) 每次接受一个含 component/status/raw 的事实对象。component 选择已有 classifier/frozen adapter；status 支持 success/error/not_configured/disabled/skipped。完整的原 parent 失败观察通常使用外层 status=success、raw 内保存原 exit/failure；外层 success 不代表旧 Gate PASS。

config 经 resolvePolicy 解析，默认 baseline-v1 / standard / java-web；low/strict、Profile、Component/Project Overrides 和错误语义不变。没有 multi-source 数组 API 或 global final-status reducer。

共同输出：policyVersion、securityLevel、profile、effectivePolicy、appliedOverrides、status、decision。来源扩展包括 evaluations/rawEvidence/normalizedFacts/checks 等，不能假定每项都存在。POLICY_ERROR 是抛错，owner 只能捕获为错误回执，不能再调用 resolvePolicy 补假 metadata。

**当前生产调用者为零。** Manager、原 scanner/Gate、Summary 都不调用新 Engine。真实调用来自 compatibility tests / provenance-test-harness；测试对同一来源的多个样本/等级重复调用，不等于生产已保证一次。

当前 Gate 聚合责任：

- 原工具和脚本决定自己的报告/异常/退出码；Sonar权威 Gate 不由新核心重算。
- vars/securityManager.groovy:58-62：code0=success，仅generic audit的code10=warn；其他非零=failed。PetClinic生产adapter强制enforce。
- Manager:70-72 对generic enforce的not_configured报失败，写security-manager.json。局部promotionAllowed不包括后续只读业务验证，不能独自作为可审批凭证。
- Snapshot Before、Read Only Release Verification的gate.sh/enforce和Jenkins currentBuild.currentResult也会阻止后续阶段。
- 当前没有生产“Engine source decisions→aggregate”接线。Promotion读取gateEvidence中的原报告、Summary已知字段及SECURITY_GATE_RESULT，再经validateGate检查source/build/candidate、双架构C/H=0、报告成功、runtime稳定、candidate SBOM；不是单读Policy PASS就批准。

## 2. Source owner、别名和正确不变量

未来 owner 选择现有 Security Manager orchestration，每个规范来源由单一Node边界调用现有Engine。Gate和Summary交接同一个不可变引用。保留Manager现有返回results List的契约；新增引用须走显式辅助接口，不偷换返回类型。

18个inventory标签的实际分区：

| 范围 | 标签/计算单元 |
|---|---|
| 预审批16个规范单元 | sbom、regression、falco-baseline、kyverno、kubescape、gitleaks、sops、trivy、cosign、sonarqube、zap、falco-final、defectdojo、provenance、build-provenance、semgrep-command-audit |
| 预审批别名 | semgrep的aggregateAliasOf为semgrep-command-audit，已冻结的是command-audit && semgrep组合parent；不得重复求值/计数 |
| 后续独立范围 | security-approval-promotion；其原验证及兼容证据保留，结果不属于PRE_APPROVAL artifact |

Kyverno在这里是RBAC && admission的冻结组合parent，不额外创建两次全局求值。&&短路时后续操作仍未执行，不能补造报告；完整组合阶段失败可由原adapter正确评估。

不变量：

    K = job/build/project + canonical source ID + phase/fact scope
        + source revision + target identity + raw-fact digest + config digest
    每个已有完整事实集合K:
      Engine一次求值尝试 → 唯一SourceResolvedPolicyResult
                         ├→ Gate aggregation引用
                         └→ Summary serialize引用
    Engine evaluations(K)=1
    Aggregator evaluations(K)=0
    Summary evaluations(K)=0

同K重试/并发复用已有结果/digest；不同来源各自一次是合法N次，不伪称全局一次。evaluateAsync内部委托evaluate属于同一次。

没有原事实/未观察到完成时，不得宣称已求值：记录未观察/未求值capture receipt，artifact INCOMPLETE，禁止进入Promotion。合法skipped/not_configured选择事实可经现有Engine相应状态求值一次；扫描次数仍为0，结果不变成PASS。

expected set和别名表来自固定可信plan，不从“收到了多少结果”反推，禁止缩减集合隐藏失败。

## 3. SourceResolvedPolicyResult身份

每项绑定canonical source ID、实际Engine component及固定scope；别名只指向规范项。复用JOB_NAME、BUILD_NUMBER、project、.git-sha/checkout revision、candidate/live/project targetScope与适用的完整image@sha256。

policyVersion/securityLevel/profile来自该次真实Engine输出；config digest、raw-fact digest、adapter/报告引用与精确hash绑定实际输入。错误回执不能以请求值冒充已成功应用的策略。result digest对不含自身digest的payload求SHA256，expected digest由可信owner context持有，不信文件自报hash。

当前Engine没有evaluation timestamp/sequence，本轮不发明新生产时钟身份。原报告若有startedAt/finishedAt可按原值保留，不冒充evaluatedAt。appliedOverrides/effectivePolicy/status/decision按原值交接，不新增overrideSource。

相同project/run的共同策略元数据必须由真实输出一致性证明，不能挑一个成功来源静默补齐其他错误来源。不同policyVersion/securityLevel的结果不可混成成功的共同配置。

## 4. AggregateSecurityDecision单独建模

现有责任仍属Manager/Jenkins；未来由Manager收集source结果，Jenkins在Read Only Release Verification后提供固定Gate context，纯finalizer聚合。finalizer不调用Engine、resolvePolicy、classifier或scanner，不重新计算severity。

输入是唯一canonical source结果集合、对应原wrapper completion和已有非source Gate/阶段事实。建议结果字段分开：

    sourcePolicyResults: 原status/decision，不改值
    aggregate:
      gateResult: 既有Gate/Jenkins在seal时结果
      pipelineResultAtSeal: currentBuild.currentResult原值
      inputResultDigests: 唯一source引用
      promotionStageSelected: 原when条件的观察结果
      eligibleToRunPromotionChecks: 完整性通过且原选择条件允许

gateResult沿用SUCCESS/FAILURE等已观察构建语义，不是假造全局Policy PASS/WARN/FAIL。原Semgrep普通告警可保留且组合阶段exit0，pipeline Gate SUCCESS不把source WARN改成PASS；不能新增“所有source必须PASS”的规则。

聚合必须复用冻结wrapper语义：

- 原enforce非零/抛错继续失败，不因low/audit metadata放宽。
- 原generic audit exit10保留warn，不将该规则移植来放宽生产。
- 原可选Provenance合法skip保留，不新增mandatory FAIL；强制模块不能伪造skip。
- not_configured/enforce规则照旧；adapter缺证据的NOT_TESTED/null不是通过。
- Snapshot Before或Read Only Release Verification失败，即使Manager局部promotionAllowed=true，也不得产出可进入检查的SUCCESS回执。
- standard source与同输入旧Gate不一致必须报告DRIFT并停止，不能由finalizer“修正”decision。

Gate观察与transport完整性分开：缺结果/POLICY_ERROR时保留原已观察Gate事实，handoff失败并禁止当eligibility消费；不改写scanner事实，也不从currentBuild=SUCCESS推断缺失source PASS。

eligibleToRunPromotionChecks仅表示可进入原检查，绝不是APPROVED、签名成功或部署成功。approvedRelease、Cosign及validateGate的原责任不可省略。

## 5. 真实时序与封存边界

当前链没有新Policy调用：

~~~mermaid
flowchart TD
  A[Checkout / target validation] --> B[Snapshot Before]
  B --> C[Acquire existing lease]
  C --> D[Original source modules]
  D --> E[Optional Provenance / Manager Gate]
  E --> F[Read Only Release Verification]
  F --> G[Candidate Approval Evidence: Summary]
  G --> H[Extract candidate image SBOM]
  H --> I[Sign and Approve: validate/sign/verify]
  I --> J[Verify approval / dry-run or deploy]
  J --> K[Post always: cleanup/archive/final Summary]
~~~

G/H/I/J仅在action!=audit-only且currentBuild.currentResult==SUCCESS时按原when进入。未来的数据交接在不改原操作顺序的前提下：

~~~mermaid
flowchart LR
  A[Source facts] --> B[Engine once per source]
  B --> C[Pure aggregate + original Gate context]
  C --> D[Seal PRE_APPROVAL artifact after read-only verification]
  D --> E[Summary read-only view]
  D --> F[Promotion-specific checks]
  G[Candidate SBOM extracted after Summary] --> F
  F --> H[Real signing/approval/promotion]
  H --> I[Separate PromotionResult]
~~~

没有I→D或I→F边。generic Manager的Summary在其自身事实/Gate完成后使用对应scope封存，不借用尚未执行的外部PetClinic阶段；本轮不实现generic lifecycle。

| seal前可用，须本次真实存在 | 尚未发生，禁止提前宣称 |
|---|---|
| 原source/native/gate报告、执行/cleanup观察 | 本次final approval、approvedDigest已批准状态 |
| 原Package SBOM阶段的产物/计数 | candidate image SBOM尚未在H提取，不能在G谎称已验证 |
| candidate/live/source/build身份、已有signing admission事实 | admission Cosign成功不等于本次Candidate Sign and Approve成功 |
| 未来once-per-source outputs、Gate及只读业务verification | 本次approval signature、APPROVED release record |
| 原when允许进入后续检查 | promotion commit/runtimeAfter/Argo结果、post cleanup及最终构建状态 |

Jenkinsfile:48先Summary，后evidence.mjs sbom。早先Package SBOM与后面的candidate-bound双架构镜像SBOM不是同一个完成事实。

## 6. Summary phase比较与选择

| 模型 | 安全/循环风险 | 回滚/兼容 | 审计/范围/Router |
|---|---|---|---|
| A 仅pre-approval Summary | 可无环，但不表达后续失败/回滚事实 | 简单，遗漏既有Promotion结果职责 | 不选 |
| B pre view + separate PromotionResult | 输入封存，后续输出不能改写输入 | 复用原approved-release/approval-signing/promotion-result，整包回滚 | 最小；未来Router可分别消费两个scope |
| C pre view +新增post Summary V2 enrichment phase | 独立只读引用时也可无环，覆盖审批输入则危险 | 多阶段/版本/恢复责任 | 本轮无须新增，不选 |

**选择B。** 权威Policy artifact不可变，Summary是投影视图，PromotionResult是后续操作事实。本轮不新增post-promotion V2 enrichment。

当前V1 post always原本重写security-summary.json并附带已存在promotion字段，现在不改它，也不假称此路径已immutable。未来迁移须保留旧字段兼容：最终视图若继续展示已发生的Promotion字段，只能是既有展示，不能写回PRE_APPROVAL artifact或成为审批输入。B界定权威输入/输出分离，不授权新增enrichment生命周期。

## 7. immutable artifact结构与completeness

概念policy-results.json，未来落点沿用受约束的.devsecops/policy-result/current-run目录；**本轮不生成**：

    {
      schema:1, scope:"PRE_APPROVAL",
      producerIntegrity:{...},
      binding:{job,build,project,source,targetScope,auditTargetImage},
      policyVersion,securityLevel,profile,
      expectedSources:[...], aliases:{"semgrep":"semgrep-command-audit"},
      sources:[{
        sourceId,component,scope,rawFactDigest,configDigest,evidenceReferences,
        result:{policyVersion,securityLevel,profile,effectivePolicy,
                appliedOverrides,status,decision},
        error:null, resultDigest
      }],
      aggregate:{...},
      completeness:{status,issues}
    }

schema是传输schema，不是Summary schema。producerIntegrity绑定本artifact owner/Engine/contract；Summary producer身份由versioned integrity contract单独绑定，不能混淆。顶层策略共同值来自真实成功解析的一致结果，无成功解析时null并保留错误，不填假standard。artifact摘要存于可信context/独立回执；resultDigest不参与自身hash。

COMPLETE必须同时满足：

1. expected set来自固定plan，18标签正确归属16规范单元、1别名和独立post scope。
2. 每个规范单元恰好一个本次结果或有真实求值尝试的终结错误回执；无重复/未知/混scope/stale/tamper。
3. SKIPPED/NOT_CONFIGURED/ERROR/POLICY_ERROR显式存在，并有真实选择/错误观察，不因没跑过滤掉。
4. binding/摘要/原事实完整；没有未完成求值或adapter因缺证据NOT_TESTED而导致的决策未知。
5. aggregate已依据对应sources和seal前Gate context固定，未偷读Promotion输出。

COMPLETE只表示收集结束，**不等于PASS**。完整FAIL/ERROR/POLICY_ERROR诊断快照可COMPLETE，但不能进入审批。合法NOT_CONFIGURED是否阻止Gate仍依原enforce/audit/选择条件，不新增一律PASS/FAIL。

缺source、没有合法skip的未执行、证据不足NOT_TESTED均INCOMPLETE；diagnostics可列capture receipt（未观察/未求值），result=null，不冒充Engine输出。部分/全部POLICY_ERROR保留真实错误，不以请求策略填“已应用”成功metadata。

原子no-replace、跨stage retry/crash不确定时fail closed及same-UID威胁边界沿用上一轮设计；本轮不宣称已实现或真实IO验证。

## 8. Summary与Promotion权威输入

Summary V2未来只允许read artifact→验证可信identity/digest/binding/completeness→serialize。不能evaluate/resolvePolicy、改severity/decision、静默补source、降级错误或生成PromotionResult。INCOMPLETE/error诊断必须显式，不能声称eligible。

**Promotion的Policy权威输入选择immutable artifact，不选择Summary V2。** Summary展示文件可能被post重写，不能让两文件成为双Policy truth。

Promotion仍消费职责不同的原补充证据：H产生的candidate SBOM、native reports、真正的approved-release、签名、GitOps/runtime约束。读取原报告时核对artifact固定的source/build/candidate/摘要。H的SBOM是后续Promotion-specific check，不重求值先前Package SBOM。

未来evidence loader可从immutable snapshot适配原validateGate同义字段（target/build/source/Trivy C/H等），保留原helper/报告计数及全部原检查；不能从Summary自报eligibility授权。真实loader/consumer差分留到获准实施后，本轮不改。

anti-self-approval硬规则：

- pre输入白名单排除本次approved-release、approval-signing、promotion-result及未来runtimeAfter等。
- 固定输入closure/phase，禁止任意path/ref把post输出偷渡成pre evidence。
- Promotion不读取Summary自报promotionApproved等标签作为授权。
- eligibility只允许进入原检查，不签发APPROVED、不替代Cosign或source/build/candidate/runtime验证。
- post输出只引用pre digest，不覆盖input；失败/rollback保留历史pre快照并单独报告失败。

这是单向输入→操作→输出，不存在本次未来PromotionResult批准自己的反向边。

## 9. PromotionResult与Regression

PromotionResult优先复用原独立事实：

- approval-signing.json：真实执行status/images/temporaryPrivateFilesRemoved。
- approved-release.json + .sig：仅原真实sign/verify成功后rename产生，保留build/source/candidate/approvedDigest等。
- promotion-result.json：原mode、securitySourceCommit、jenkinsBuild、candidateDigest、approvedDigest、runtimeBefore/After、gitOpsCommit、promotionResult、argoSyncResult/Health、rollback、error等。

未来引用层可追加pre artifact digest和原run/candidate绑定；不能从eligibility生成操作事实，不将DRY_RUN_PASS称为DEPLOYED。某些原前置异常在try/finally之前发生，可能没有native report；保留缺报告/异常观察，不能为填表编成功。未选择阶段与执行失败也须区分。

Regression当前是top-level Node suite退出码Gate。**frozen compatibility adapter**核对regression-baseline-v1.json的producer SHA，保护旧oracle/source快照，不是生产新scanner历史结果比较框架。

V2后原测试Gate/退出码职责不变；compatibility adapter在明确新bundle/source root下验证producer/owner/consumer exact identity，V1锁保留。新artifact contract tests可独立添加，不能自动塞入原生产Regression glob或新增历史drift算法。

## 10. 20项未来测试设计

test-matrix.design.json逐项记录，全部implementationExecution=NOT_EXECUTED。不是20项已通过runtime测试：

| # | 场景 | 预期 |
|---|---|---|
| 1 | one canonical source/fact set | 实际Engine一次，同K复用 |
| 2 | Gate消费 | 同result digest，Aggregator Engine calls=0 |
| 3 | Summary消费 | 同digest、字段原值 |
| 4 | Summary尝试求值 | 依赖/计数拒绝，Summary calls=0 |
| 5 | missing expected result | INCOMPLETE，不补PASS |
| 6 | duplicate/alias重复求值 | 拒绝，别名只引用 |
| 7 | wrong source/component/scope | POLICY_ERROR/reject |
| 8 | stale run/source/config/raw digest | 拒绝重放 |
| 9 | 全部终结且完整 | 允许纯aggregate，可成功也可失败 |
| 10 | 缺expected source | 无完整eligibility |
| 11 | source POLICY_ERROR | 显式保留，禁止Promotion |
| 12 | 合法optional SKIPPED | 原值/选择证明，不虚构scan或新增FAIL |
| 13 | NOT_CONFIGURED | 原值/原enforce-audit语义，无默认PASS |
| 14 | pre Summary白名单 | 只有切点前事实，拒绝post refs |
| 15 | Promotion未执行 | 无假approval/signature/runtimeAfter |
| 16 | 注入未来结果/自批准标签 | 无授权，无反向依赖 |
| 17 | candidate mismatch | artifact/report/approval不一致即拒绝 |
| 18 | 后续Promotion输出 | 独立native artifact/诊断，不覆盖input |
| 19 | post candidate/run/source | 绑定same pre，错误目标拒绝 |
| 20 | Promotion FAIL/rollback | post错误保留，pre digest不变，不因曾eligible掩盖失败 |

后续实际差分还须覆盖WARN并存原Gate SUCCESS、optional skip、&&短路、前置/只读检查失败、native Promotion报告缺失、原签名/双架构/回滚条件。Sonar真实负例deferred规则不变。

## 11. 原迁移策略与未来changeset

保留VERSIONED INTEGRITY CONTRACT + IMMUTABLE POLICY RESULT ARTIFACT。artifact改为per-source results +独立aggregate，不是假造全局Engine输出。V1源码/锁/历史证据不覆盖；V2 exact tuple独立固定，未知/混合版本拒绝，不auto-allowlist/wildcard/self-selection。显式整包回滚V1，Summary schema仍建议1，producer/transport version与文档schema分离。

未来提案（本轮均未应用）：

| 类别/文件 | 后续动作 | 最小责任 |
|---|---|---|
| infra/security/policy/resolved-result.mjs | CREATE | per-source原值、identity/digest/transport |
| infra/security/policy/evaluation-owner.mjs | CREATE | once-per-canonical-source、别名复用、错误回执 |
| infra/security/policy/collect-existing-evidence.mjs | CREATE | 固定输入白名单、完整原事实；无scanner/lifecycle变更 |
| infra/security/policy/finalize-preapproval.mjs | CREATE | 原wrapper/Jenkins context纯aggregate，零Engine调用 |
| infra/security/policy/write-resolved-artifact.mjs | CREATE | binding/completeness、独占原子no-replace、可信摘要 |
| vars/securityManager.groovy | MODIFY新代际 | source capture/ref，保留返回List/退出码/Gate语义 |
| Jenkinsfile.security-audit | MODIFY新代际 | 只读验证后、Summary前seal；原操作阶段和发布条件不改 |
| infra/security/security-summary.mjs | MODIFY为后续受审V2 | 仅验证/序列化，旧字段/错误语义保留 |
| resources/security-manager/summary.mjs、infra/security/manager/summary.mjs | MODIFY为同契约V2 | generic也禁止求值 |
| infra/security/summary/contracts/summary-producer-v1.json、summary-producer-v2.json、verify-producer-contract.mjs | CREATE | 显式exact tuple，真实V2产生后才填hash |
| infra/security/summary/baselines/summary-v1/source-index.json与source/镜像树 | CREATE | V1原件/传递依赖固定归档，原hash不改 |
| infra/security/promotion/evidence.mjs | MODIFY新代际 | artifact为Policy authority，原Gate事实适配 |
| infra/security/promotion/contract.mjs | 条件MODIFY新代际绑定层 | 保留原资格/签名/事实检查，实际差分另验收 |
| infra/security/promotion/sign-approve.mjs、promote.mjs | UNCHANGED原算法 | loader迁移；若需改frozen操作语义则另停另审 |
| infra/security/policy/promotion-evidence.mjs、regression-evidence.mjs | MODIFY新代际绑定 | 显式version/root，保留V1 |
| infra/security/policy/versions/*-baseline-v1.json | UNCHANGED | 历史hash/oracle原样 |
| infra/security/policy/versions/{promotion,regression,command-parent,gitleaks-parent,sbom-parent,trivy-parent,zap-parent}-summary-v2.json及对应parent integrity resolver | 按已证依赖CREATE/条件MODIFY | owner涉及六份锁、Jenkins涉及四份锁，不只改Summary两锁 |
| infra/security/policy/evaluation-scope.test.mjs、preapproval-scope.test.mjs、summary-version-migration.test.mjs | CREATE | 上述20项及原消费者差分，独立于原Regression glob |
| infra/security/policy/engine.mjs、versions/baseline-v1.json | UNCHANGED | 不需batch API/global reducer，不改策略语义 |
| evidence/<date>/policy-handoff-acceptance/ | CREATE | 后续真实验收，不计入旧2128样本 |

涉及锁定文件必须先固定V1，再在独立新代际契约下实施，不能先原地改源码再更新旧hash。未设计/实施其他结构性阻塞。

## 12. 最终34项报告

| # | 要求 | 结果 |
|---|---|---|
| 1 | actual granularity | 单component/fact set，无global Engine API |
| 2 | sources invoking Policy | 生产0；compatibility tests/harness多来源调用，不假称生产once已生效 |
| 3 | source owner | 未来Manager +唯一Node边界，规范/别名见第2节 |
| 4 | aggregate owner | Manager/Jenkins，未来只读验证后纯finalizer |
| 5 | invariant | PER_SOURCE_SINGLE_EVALUATION；Aggregator/Summary=0 |
| 6 | source identity | 原run/source/target/policy + fact/config/result digest |
| 7 | aggregate | 原Gate/Jenkins结果与source decisions分开 |
| 8 | timeline | 第5节区分当前真实链和未来插入点 |
| 9 | available | seal前source事实/decisions、Gate context、candidate身份 |
| 10 | forbidden | 本次approval/signature、尚未提取的candidate SBOM、发布结果 |
| 11 | PromotionResult | 第9节原真实输出/独立诊断 |
| 12 | anti-self-approval | 无post→pre授权边，原签名/检查不可省略 |
| 13 | phase models | A/B/C比较，第6节 |
| 14 | selected | B：pre view + separate PromotionResult |
| 15 | artifact | 第7节规范source集合+aggregate，本轮不生产文件 |
| 16 | completeness | 固定集合、唯一绑定、终结结果、aggregate finalized；COMPLETE≠PASS |
| 17 | Summary | 只验证/序列化，零求值 |
| 18 | Promotion authority | immutable artifact，Summary仅view；原native/signature职责不同 |
| 19 | Promotion output | same candidate/run/pre digest，失败/缺报告原事实保留 |
| 20 | Regression | 原suite exit-code Gate；hash guard属于compatibility oracle |
| 21 | scope tests | 第10节1–13设计，implementation NOT_EXECUTED |
| 22 | pre/post tests | 第10节14–20设计，implementation NOT_EXECUTED |
| 23 | integrity | 保留显式版本化exact bundle |
| 24 | artifact decision | 保留，采用per-source集合+纯aggregate |
| 25 | future changeset | 第11节，未应用 |
| 26 | production changed | **NO**，只有本轮新文档/evidence |
| 27 | accepted hashes changed | **NO**，旧V1/证据不改 |
| 28 | Policy core | **5/5 PASS**，本轮独立重跑 |
| 29 | source hashes | **455引用/229文件，失败0**，final-validation.json |
| 30 | evaluation scope | **POLICY_EVALUATION_SCOPE = RESOLVED** |
| 31 | pre scope | **PRE_APPROVAL_SUMMARY_SCOPE = RESOLVED** |
| 32 | readiness | **SUMMARY_VERSION_MIGRATION_READINESS = READY（设计）** |
| 33 | blocker if not ready | B1/B2设计阻塞均解除；不宣称V2实现通过 |
| 34 | next permitted if ready | 本轮STOP；后续明确授权实施versioned迁移及per-source handoff，再做真实consumer/Summary差分；当前不自动实施 |

STOP。没有开始unified plugin contract、Result Router或其他结构性工作。
