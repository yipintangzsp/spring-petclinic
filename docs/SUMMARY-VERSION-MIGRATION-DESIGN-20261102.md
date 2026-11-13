# Summary 版本迁移与单次 Policy 求值交接设计

SUMMARY_VERSION_MIGRATION_READINESS = NOT_READY

范围：仅仓库只读追踪、设计、隔离契约原型。未修改生产 Summary、Generic Summary、Promotion、Regression、Policy Engine、Jenkins、scanner、Gate、Loki/Grafana；没有生成 V2 producer、注册新 hash、发布、审批、签名或 rollout。

版本迁移和单来源交接已有可检验设计；尚不能批准实施完整迁移。附件要求一次 Pipeline execution 内 Policy evaluation count=1，而现有 Engine 的一次调用只能评估一个 component；它没有多来源求值或全流水线 final status API。不能把 N 次 evaluate 包装成一次 owner 调用，再声称 Engine 仅求值一次。另有前置 Summary 与后续 Promotion 结果的时序边界必须明确，不能形成自批准依赖。

证据目录：evidence/2026-11-02/summary-version-migration-design/。32/32 设计/只读契约测试通过，Policy core 5/5 通过；这些不是实际 V2 集成或新增 parent-stage scanner 兼容样本。

## 1. 真实调用图与当前缺失的边

当前生产链为：

    Jenkinsfile.security-audit:33
      → vars/securityManager.groovy call(cfg)
      → resources/security-manager/petclinic-adapter.json 的 module.command
      → 原 scanner / prerequisite / Gate / cleanup 脚本
      → 报告、异常、进程退出码
      → securityManager:58-62 收集并判定 success / warn / failed
      → securityManager:70-73 写 security-manager.json
      → 原有 Jenkins currentBuild / stage selection
      → security-summary.mjs（approval evidence 前和 post always）
      → Promotion evidence / contract；归档与 Loki 发布

当前 Policy compatibility 链是另一条链：

    本地 frozen compatibility tests / provenance-test-harness
      → evaluate(facts, config) 或 evaluateAsync(facts, config)
      → resolvePolicy(config)
      → 现有 classifier 或 frozen parent/evidence adapter
      → Policy 返回值
      → 测试比较旧 Gate、保存差分证据

两条链尚未在生产相连。不存在已经生效的“生产 Gate 消费 Engine 输出”，也不存在 Summary 正在第二次求值的情况。readiness 已证明冻结兼容，不等于新 Engine 已成为生产 Gate。

具体依据：

- Engine 定义：infra/security/policy/engine.mjs:37、71、140。
- Engine 只接受单个 facts.component，不能接受事实数组；evaluateAsync 只在 DefectDojo success 分支走异步 parent，其余委托 evaluate，最终 resolvePolicy 每次调用一次。
- vars/securityManager.groovy:58-62：code=0 → success；只有 generic audit 且 code=10 才 warn；其他非零记录 failed 并使 Jenkins FAILURE。生产 PetClinic adapter 不允许 audit/off，不能借 cfg 更改门禁。
- Semgrep 在 semgrep-gate.mjs:43-44 内运行 classifySemgrep，发现 blocking 即抛错；withScanner 写原报告并传播异常。source-gate、Trivy、Sonar 等各走自己的原始判断，不消费 Engine 的 decision。
- generic infra/security/manager/tool.mjs:41-42 根据原 r.blocking/mode 产生 exit20/10；它也不调用新版 Engine。
- securityManager 返回 results；保存的 security-manager.json 是 module execution 事实，不是 ResolvedPolicyResult。不能给它换个名字就说求值已完成。
- compatibility adapter 中的 Promotion/Regression 原操作 completion 是观察事实；Engine 不执行审批、签名、promote 或 Regression runner。保留该边界。

当前可复用身份与输入：

| 对象 | 当前内容 | 能否作为已求值结果 |
|---|---|---|
| .git-sha / Git SCM revision | source commit；需与可信 checkout context 核对 | 否，仅身份 |
| BUILD_NUMBER + JOB_NAME | run/build identity；不能只使用 build number 防止跨 job 重放 | 否，仅身份 |
| AUDIT_CANDIDATE_IMAGE / trivy-audit.json | pinned candidate 或 runtime image、targetScope | 否，仅目标绑定 |
| security-manager.json / results | mode、profile、modules 的运行状态/退出码等 | 否；可交接已观察事实 |
| 各 scanner/gate/native 报告 | 原事实、原判断、cleanup/执行信息 | 否；只读适配输入 |
| compatibility differential 文件 | 历史/受控旧决策与 Policy 决策 | 否；不得拿旧测试结果当新构建结果 |
| manager-config.json | generic 配置、project、build、sourceRoot、可选 sourceCommit | 否；需独立核实配置和当前 run |

Summary 当前数据来源、参数与可用 orchestration：

- production producer 的输入是固定 .devsecops 文件、.git-sha、BUILD_NUMBER / SECURITY_BUILD_RESULT 等环境变量及 Sonar 当前项目 HTTP 查询。它没有参数解析、额外 result argument 或 resolved-result input。WRITE_ONLY 只控制是否发送 Loki。
- Generic Summary 读取 security-manager.json、manager-config.json 和固定模块报告，通过 libraryResource 写成独立 Node 脚本运行，不与 Manager 共享 JS 对象内存。
- 当前中间 orchestration 是 vars/securityManager.groovy；Jenkinsfile 在 Manager 外运行 release verification、pre-approval Summary 与 post Summary。未来 owner 选 Security Manager orchestration，具体 Node evaluator 在新 helper 内；Jenkins context 仅持有不可变引用，不求值。
- 生产当前没有 authoritative Policy evaluation owner；上述 owner 是明确的未来设计选择，未伪报为现存实现。

## 2. 一个真实、可绑定的 ResolvedPolicyResult

现有正常返回的共同字段：

    policyVersion, securityLevel, profile, effectivePolicy,
    appliedOverrides, status, decision

其他输出按来源不同：evaluations、rawEvidence、normalizedFacts、frozenEvidence、sonarEvidence、sopsFacts、checks、failureKind、reason 等。不能假定 evaluations 对所有 adapter 都存在，也不能用它重新计算来源自己的结果。

POLICY_ERROR 是抛出的 Error，不是现有正常返回对象里的字段。未来 owner 在唯一求值边界捕获该明确错误，产生错误回执；不能伪造已经成功 resolved 的 policyVersion/securityLevel/effectivePolicy，也不能 catch 后再次调用 resolvePolicy 来“补 metadata”。

建议 transport envelope（字段名是传输/绑定契约，不是新增 Policy 语义）：

    {
      schema: 1,
      binding: {
        job, build, project, source,
        targetScope, auditTargetImage, policyVersion
      },
      factsSha256,
      configSha256,
      result: {
        policyVersion, securityLevel, profile, effectivePolicy,
        appliedOverrides, status, decision
      },
      error: null
    }

result 为同一次 Engine 输出中这些字段的原值投影，不能重算或填充缺失字段。profile 与 decision 是已有真实输出，必须保留给消费者；不新增 overrideSource。

错误回执：result=null，error={status:POLICY_ERROR,message:原错误信息的安全表示}。binding.policyVersion 是请求版本身份，不能解释为已成功应用的版本。其他未知运行异常同样阻止使用该结果；不得伪装成成功回执。

原 scanner report 不写入 Summary 或新建的凭据载体。结果只交付必要的已有 Policy 字段，raw facts 保留在既有报告中，通过白名单输入引用及摘要绑定；执行材料中有敏感内容时不复制到 envelope。不同来源的附加事实仍由各自既有消费者读取，不能强行压成 vulnerability severity。

原型只覆盖上述单来源 envelope。**多来源 result 与全流水线 final status 尚无原有实现可引用，本设计不发明一个 worst-of 聚合规则。**

## 3. handoff 方案比较与选择

| 方案 | 一次求值/一致性 | 生命周期、原子性与 schema | stage/并行/replay | 安全、测试与兼容 |
|---|---|---|---|---|
| A 内存对象 | 同进程可共享 deep-frozen object；天然避免落盘错读 | 进程结束即失效；Groovy CPS/JS 进程间不能保留同一对象 | 不能跨现有 sh/Node 边界；重启丢失 | 易单测，但要把 Summary/owner 合并进程；不适合当前链 |
| B 显式 function argument | 同一次调用最清晰，可注入只读 result | 要把当前 top-level executable 拆为函数 | 现有 Jenkins 多次独立进程调用仍需额外交接；只解决末端接口 | 适合作为 V2 内部 serializer API，不作为整体 handoff |
| C 不可变中间 JSON artifact | owner 唯一写入，Gate 与 Summary 读取同一摘要身份 | 严格 envelope schema；独占创建、原子发布；归档可追溯 | 适配当前进程/stage边界；并行归并后 seal；拒绝跨 run 重放 | 需可信 context 中保存 expected digest，不能只信文件自带 hash；可独立测试、可兼容旧 Summary |
| D 现有 orchestration/context | Manager 的 results 与 CPS context 可协调 owner、保存引用 | 现有对象不是 Policy result，不能直接当成已求值 | 可跨 stage 保存小引用；不适合保存大量 native/result map | 选作控制面，不选作结果载荷；不改造成新 plugin lifecycle |

**首选 C，D 仅作为当前已有的控制面，B 可作为 V2 内部纯序列化函数。** 不是三种并行真相源：唯一载荷是 C；可信 owner context 存的是路径、精确 digest、独立当前身份，不是第二份可修改的决策。

未来暂定位置：.devsecops/policy-result/<current job+build 的受约束本地路径>/resolved.json。跨 job 的字符串需要安全编码，禁止调用者提供任意输出路径；禁止软链接、路径穿越和从旧 archive 目录自动搜索。可避免将 job 原名直接作为路径，run identity 仍使用原 JOB_NAME/BUILD_NUMBER。

发布过程：owner 收齐固定输入，固定配置和身份 → 求值 → 序列化一次 → 在同目录 exclusive 临时文件写入、fsync → 以 no-replace 语义发布（例如同文件系统 link 到最终名后 unlink 临时文件；不能用可覆盖旧文件的普通 rename 假装 write-once）→ 同步目录 → owner context 记录 exact bytes digest。对同一输入的 stage retry 只复用已封存对象；若执行曾开始但没有完整可信回执，标记 INCOMPLETE/POLICY_ERROR，不能悄悄重新求值凑“一次”。Jenkins durable task 不提供跨崩溃 exactly-once 保证，状态不确定时 fail closed。

并行模块不写该文件；先 join/确认输入集合，再由 owner 单写。预审批和 post Summary 重用同一 resolved snapshot，不能为了补充新结果而重写同一路径。超出封存时间点的新事实只能保留在原有非 Policy Summary 字段，或等待另行定义的阶段契约；不能偷偷再次求值。

生命周期：输入齐全后发布；归档后按现有构建 workspace 清理生命周期回收；消费不得回退去历史 archive 找“最近一次成功”。清理失败显式报告，不能触发第二次求值。当前安全边界不为此新增组件、密钥、权限或网络入口。

防篡改边界：digest 存于受信任的 Jenkins owner context/固定 SCM release descriptor，消费者不能从同一个可写文件同时取得载荷和“期望 hash”。0700/0400、原子发布与摘要能防误写、并行覆盖和回放，不证明能抵御已控制 Jenkins agent 同 UID、控制整个 job 或 SCM 信任根的攻击者；若要求抵御该威胁，当前权限和无新增 signer 条件不足，必须另外评审，不能宣称 JSON 文件具有密码学不可伪造性。

## 4. 结果 identity、失败语义与单次求值不变量

独立当前身份来自 owner SCM/build context，而不是待验证的 result 或 Summary：

- JOB_NAME + BUILD_NUMBER + project；source 为当前 .git-sha 并与 checkout revision 核对。
- candidate 模式：使用现有 AUDIT_CANDIDATE_IMAGE 与 trivy 的 auditTargetImage/targetScope 做精确一致性检查，必须为既有固定 digest；live 模式绑定观察到的 runtime image 和 live scope。generic 纯源码场景显式 project scope + 无 image，不能把缺 candidate 当 candidate 模式成功。
- policyVersion 复用请求的现有 baseline-v1；factsSha256/configSha256 固定实际输入与配置。后两者是证据摘要，不是新的业务身份体系。
- generic 项目 source 与 runtimeRevision 分开：项目代码身份不等于 Shared Library/runtime checkout 身份；后者受 producer integrity bundle 的精确 source hash/revision 约束。

消费者每次读：可信 context 中的路径/摘要 → 文件不可替换的完整读取 → 验证 digest → schema → 逐项身份 → 输入/配置摘要 → result metadata 的既有字段。不同 build/job/source/candidate/scope/version/输入均拒绝。不要只看 recorded_at/AGE，不引入当前未定义的任意 TTL。

| 情况 | handoff 消费语义 | Summary 未来语义 | Gate 边界 |
|---|---|---|---|
| 正常 resolved result | 保留原 status/decision | 仅追加 metadata 投影 | 消费原 decision/status，不能用 metadata 当批准凭证 |
| missing / malformed / binding mismatch / tampered | POLICY_ERROR；无已解析结果 | 保留原 scanner 字段，policy.status=POLICY_ERROR，不填假 standard/low/PASS | V2 完整性失败，不能继续作为已验证 candidate；不是改变原扫描发现 |
| Engine POLICY_ERROR | 保留错误回执 | 显式 POLICY_ERROR | 不将错误变成 WARN/PASS |
| SKIPPED / NOT_CONFIGURED / NOT_TESTED | 保留原 status 与 decision=null | 同值展示 | 不能从 null 推断 PASS；原 enforce/capability 判定不由 Summary 改写 |
| Engine operational ERROR / FAIL | 原值保留 | 同值展示 | 不因 audit metadata 抹掉原强制失败 |

期望的不变量：

    owner single evaluation
      → one immutable resolved identity
          ├─ Gate reads same digest
          └─ Summary pure serialization, evaluator imports/calls = 0

原型实证：对一个来源，重复/并发 owner 调用只触发实际 evaluateAsync 一次；Gate 与 metadata 视图读取同一 digest；Summary 视图没有求值入口；元数据和 facts 不变。

**尚未满足的字面不变量：整条 Pipeline Engine call count=1。** 两个来源通过现有 API 要调用两次；数组被 POLICY_ERROR 拒绝。不能将它改名为“一次 batch session”抹去内部两次求值。也不能只调用 resolvePolicy（无 decision）来冒充实际 evaluation，或挑一个 Semgrep 结果作为全来源 final status。

## 5. producer hash 契约的实际含义

| 对象 | 定义/读取 | 行为 |
|---|---|---|
| Promotion compatibility | versions/promotion-baseline-v1.json:19；promotion-evidence.mjs:4-5 | sourceHashes 中每个 path 只对应一个 exact SHA；在消费 evidence 前读取当前文件比较；不符抛 POLICY_ERROR: frozen Promotion source changed |
| Regression compatibility | versions/regression-baseline-v1.json:60；regression-evidence.mjs:5-6 | 同样逐项 exact SHA；不符抛 POLICY_ERROR: frozen Regression source changed |
| Generic 仓库副本 | regression-baseline-v1.json:111 | infra/security/manager/summary.mjs 的 SHA 被锁定 |
| Generic libraryResource | resources/security-manager/summary.mjs | 目前这些 sourceHashes 中未直接锁此路径；它与仓库副本字节相同不等于执行时校验了该路径；已有证据索引的 SHA 也不是 production enforcement |

这首先是**兼容性 oracle 的 source-integrity guard**，以 baseline-v1 锁文件承载版本身份。它保护“仍在比较同一套原生产逻辑”，防止实现变动后拿旧证据冒充通过。它不是现有 production Promotion 签名规则中的一个新增 hash Gate。原 Promotion contract.mjs 仅选择 Summary 的已知字段，不验证 producer SHA；原生产 Regression 也不把整个 sourceHashes 清单当新运行身份 Gate。

因此上一轮内存模拟的 POLICY_ERROR 属于 compatibility adapter 的完整性检查，不应描述为已经在线执行的生产拒绝。未来需要在迁移 bundle 的选择/验证层拒绝错误组合；不能谎称旧 runtime parser 本来会拒绝额外字段。

其他同类 guards：SBOM、Gitleaks、Command、Trivy、ZAP、Falco、Kyverno、Kubescape、Dojo、Cosign、Provenance、Build Provenance 的 adapter 也锁各自原源码。inspection.json 完整记录 455 个引用与影响关系。尤其 vars/securityManager.groovy 被 Command/Gitleaks/Regression/SBOM/Trivy/ZAP 六份锁引用，Jenkinsfile.security-audit 被 Gitleaks/Promotion/Trivy/ZAP 四份锁引用；改变未来 owner/wiring 时不能只考虑两个 Summary 锁。

V1 当前 identity 是设计中的标签 SUMMARY_PRODUCER_V1，**不是已有 Summary 字段**。精确源文件身份：

    path: infra/security/security-summary.mjs
    sha256: 038320f04c67fb1fe5ff711c11d445c2de88cc50b2230eb4c971bf46142f5b34
    document schema: 1

## 6. 版本迁移策略比较与首选

| 策略 | 安全/降级 | 原子性与回滚 | 维护/审计 | 对冻结证据与消费者的影响 |
|---|---|---|---|---|
| A 原地 atomic producer + consumer update | 若完整部署原子可强，但必须把所有关联 guard 一起迁移，不能直接改旧 SHA | 一个受审 commit 有助一致；执行中 workspace/Shared Library 混合仍有风险；需整包回滚 | 简单，但容易把旧 baseline 锁覆盖 | 不能独自保留 V1 oracle 的当前路径契约；只改两个锁还会遗漏 owner 依赖 |
| B 显式 V1/V2 hash allowlist | 有限集合优于通配；若任意挑中一个即接受，会无声降级至 V1/遗漏 metadata | 回滚方便，但选择规则若来自 producer 自报就危险 | 小规模简单，未来分支语义膨胀 | 不能把 V1/V2 当同一完整契约；保留旧 hash 不等于保留旧 oracle |
| C 版本化 integrity manifest/contract | 精确绑定 producer+consumer+owner+Engine/config，受信 context 显式选择版本；默认拒绝未知/混合 | 整包切换和回滚，固定 SCM/library revision；禁止运行中改变选择 | 明确长期维护、可追溯版本；需要实现独立 verifier/包验证 | V1 锁/证据不重写，V2 独立建立；Promotion/Regression 新代际与旧代际分离 |
| D repo 已有 pinned SCM/Shared Library revision + 隔离 checkout | 可提供整包固定身份，但当前 Policy 多为 untracked，不能仅拿 HEAD 宣称涵盖现有基线 | 复用已有 checkout 能力，旧包/新包分开，整 revision 回滚 | 自然支持 C 的载体；单靠 revision 不提供 producer/consumer 兼容规则 | 仍需冻结当前工作树的真实文件集合和 C 的 tuple 校验 |

**首选 C，以现有固定 SCM/library checkout 作为交付载体；不采用自动 hash allowlist。**

未来契约文件暂定 summary-producer-v1.json / summary-producer-v2.json，各自包含 contract identity、producer path/hash、对应 consumer/owner/Engine/config hash、Summary schema、是否必须有 policy metadata、完整包输入列表。合同 version 是传输/完整性契约版本，policyVersion 仍指原策略语义，不应从 baseline-v1 改成“策略 v2”来绕开原冻结证明。

V2 本轮未创建，因此没有真实 V2 hash，不能在 active manifest 预填占位 hash。contract-model 的 MODEL_ONLY_NO_REAL_V2_HASH 是隔离测试符号，不是可接受值，不被注册到仓库执行链。

选择规则：仅由固定、可信 SCM/release descriptor 选择一个明确 contract。验证 manifest 的根信任来自该固定 revision/受审 descriptor，不信同一可写 workspace 中自报的“manifest hash”。先核对整个 producer/consumer/owner bundle，再运行对应版本；不遍历到哪个 hash 碰巧匹配就自动切换。不使用 wildcard、不取消校验、不接受任意 future producer。

V1 保全：当前锁、209 份 Regression 原 source/test/config 绑定、Promotion 原锁、历史 #250 相关基线及后续已冻结证据保留原字节和归属；不把当前 HEAD 等同于所有冻结文件的 Git identity。当前 Policy 代码/证据存在 untracked，未来需要经过授权将精确快照作为可验证版本归档/提交，不能仅引用 HEAD。旧 oracle 应在固定 V1 树中运行，其相对 import/path 继续指向 V1；禁止将旧锁指向被覆盖的 V2 目录然后宣称 V1 仍能原样复验。

V2 单独建立新包的精确 contract/source lock 和新验收证据。任何会更改 owner、Jenkins wiring 或 parent adapter guard 的新代际都必须纳入 bundle；新文件不能悄悄绕过历史 FAIL。新/旧 source-root 的选择不能由扫描发现或 result 自报决定。

## 7. 混合版本、降级、回滚

| 组合 | 未来迁移 verifier 的要求 | 当前实现的真实限制 |
|---|---|---|
| V1 producer + V1 consumers | ACCEPT，保持原行为；无 metadata 不是 V1 的新失败条件 | 当前旧契约可复验；本轮没有在线发布测试 |
| V2 producer + 显式 V2 bundle | ACCEPT，仅在真实 V2 hash/metadata/binding/消费者验收通过后 | 本轮仅 model；没有真实 V2 |
| V2 producer + old consumer | REJECT / POLICY_ERROR：不匹配选定 tuple | 旧 frozen adapter 会因 source hash 拒绝；旧 runtime JSON parser 自身可能接受，必须由新 bundle preflight 阻断，不能假报已保护 |
| V1 producer + V2-selected consumer | REJECT / POLICY_ERROR，不自动退回 legacy | 若显式授权选 V1 整包，则属于上一行 V1/V1；不是混用 |
| 未知 producer hash | REJECT / POLICY_ERROR | 不加 wildcard 或“未来版本”分支 |
| 缺失 producer identity | V2 选择/可信上下文身份缺失则 POLICY_ERROR | V1 JSON 本来没有 version 字段；V1身份来自已知源 SHA，不追溯新增必需 JSON 字段 |
| producer 被篡改 | 精确 SHA 不符则 POLICY_ERROR，先于 payload 消费 | 不得运行后才检测 |
| 正确 V2 producer、malformed policy metadata | POLICY_ERROR，不能因 producer hash 正确就信任任意 result | producer identity 与 document validation 两项都必须过 |

回滚必须显式选择完整 V1 bundle：停止该 run 使用 V2，使用隔离的新/恢复 workspace、固定 V1 producer/consumer/owner/Engine/config、核对 V1 SHA、重新运行 V1 只读验收。不能在同一 run 中换 producer 后继续复用 V2 policy result。历史发布批准/签名不能因回滚被自动重新签发。本轮不执行回滚或 rollout；model 仅验证显式版本选择语义。

## 8. schema 与 producer version 分开

建议未来保留 Summary schema=1。实际 JSON 消费者只读已知字段；metadata 追加到独立 policy 对象，不改原字段、status、counts、路径。上一轮纯 validateGate additive 检查已通过，但这不足以替代真实 V2 producer 及全部消费者回归。

producer version/完整性 contract 需要升级，因为执行来源、必需 Policy input 和验证责任发生变化；这与文档 JSON schema 是不同维度。通过 bundle identity 绑定 V2 metadata 必需性，不把 Summary schema=1 当 producer 身份，不把旧 schema=1 全部视为必须包含 metadata。

不在原 schema=1 的已知顶层字段上新增必需含义，也不把 null/error/skipped 改成 PASS。若未来发现外部封闭 schema 或为了消费 policy 而实际改变旧字段含义，必须重新评审 schema 2，不能自动升级或强行维持 1。

## 9. 未来测试与本轮模型证据

Handoff 验收必须包含：

1. 在真实 owner wiring 统计实际 Engine 求值入口及 resolve/classify 路径，不只数 orchestration wrapper。evaluateAsync 向 evaluate 的一次内部委托属于同一求值，不额外算第二次；对不同 component 分别调用则是多次，不能称为一次。完整执行范围恰为已批准次数；Summary 调用为 0。
2. Gate 与两次 Summary invocation 收到同一 owner 记录的 digest/identity；不能从 artifact 自报 expected context。
3. Missing、malformed、stale job/build/source、wrong candidate、wrong policyVersion、tamper、facts/config mismatch 全部明确拒绝。
4. Engine POLICY_ERROR 无假默认 metadata；SKIPPED、NOT_CONFIGURED、NOT_TESTED、ERROR 与 FAIL/WARN 原义保留。
5. default standard、显式 low/strict、Component/Project Override 与 appliedOverrides 顺序原值保留，raw facts 不变。
6. 独占创建、无覆盖原子发布、并行 writer、Jenkins stage retry/restart 中不确定状态、workspace 清理、目录/软链接/路径越界，做真正受控 IO 验证；本轮纯 model 不冒充已完成。
7. 输入 snapshot 的来源/白名单/完整性与全部生产来源的接入映射；不能把历史 test output 当本次事实。

Migration 验收：

- V1 原 producer + 原 consumers 在固定 V1 树中复验，历史 evidence 不改写。
- 真实 V2 + migrated bundle + 新输出 PASS，剥离唯一批准新增路径后旧字段语义相同。
- tampered/unknown producer、混合 owner/consumer/config/revision、missing identity、malformed metadata 明确拒绝。
- V2→完整 V1 显式回滚后旧契约恢复；不是替换一个文件或重启即宣称恢复。
- 同时覆盖 Promotion 和 Regression 实际消费者与 frozen compatibility guard；所有因 owner/Jenkins 变动受影响的其他 source locks 一并版本化验收。

本轮 32/32：21 项单来源交接/API边界检查 + 2 项 V1 frozen adapter 只读复核 + 9 项符号化版本选择检查。每项名称与分类见 model-test-results.json；Policy core 另计 5/5。V1 复核只消费保留输入，不重新执行 Promotion 或 Regression 原操作。只有调用现有 Engine 的相关用例属于实际未修改 Engine 的受控执行；version 模型不是真实 V2，没有 atomic IO、Jenkins、production consumer、审批、发布或 scanner 重跑。

## 10. 精确未来 changeset（仅提案，未应用）

以下路径为未来实施边界，不是本轮已创建的 production 文件。NOT_READY 未解除前不得开始：

| 路径 | 未来动作 | 目的/约束 |
|---|---|---|
| infra/security/policy/resolved-result.mjs | CREATE | 结果投影、严格 envelope/binding、不可变传输；不包含 Policy 决策算法 |
| infra/security/policy/evaluation-owner.mjs | CREATE（前置契约待明确） | 唯一求值 owner；不能用 N 次现有 evaluate 冒充流水线一次 |
| infra/security/policy/collect-existing-evidence.mjs | CREATE（需完整输入映射验收） | 只读现有报告/执行观察，不新增 scanner、Gate 或 plugin 生命周期 |
| vars/securityManager.groovy | MODIFY，需对应新代际 bundle | 在现有 orchestration 保管 owner 引用/事实；不改原生产 enforce 或退出码语义；涉及六份 source locks |
| Jenkinsfile.security-audit | MODIFY，仅在后续显式授权 wiring 时 | 固定 owner 时序、两次 Summary 重用同一引用；不改发布策略、审批条件或 rollout；涉及四份 source locks |
| infra/security/security-summary.mjs | MODIFY 为受控 V2，V1 树另存 | 仅消费已求值结果、追加 metadata/显式错误，不 import evaluator |
| resources/security-manager/summary.mjs | MODIFY 为同契约 V2 | Generic serializer；不从 cfg 新建策略真相 |
| infra/security/manager/summary.mjs | MODIFY 同步副本 | 受 Regression source guard 约束，不静默更新旧锁 |
| infra/security/summary/contracts/summary-producer-v1.json | CREATE | 新建契约描述旧 hash/完整 V1 bundle；不更改旧源或历史锁 |
| infra/security/summary/contracts/summary-producer-v2.json | CREATE，真实 V2 完成后才填 hash | 独立 exact tuple；禁止当前占位注册 |
| infra/security/summary/verify-producer-contract.mjs | CREATE | 显式固定 contract 选择/校验；没有 allow-any/fallback |
| infra/security/promotion/contract.mjs、evidence.mjs | MODIFY 新代际，仅绑定/输入兼容 | 保留全部原 approval/签名/已知字段验证，新增完整性前置验证不得伪造批准 |
| infra/security/policy/promotion-evidence.mjs、regression-evidence.mjs | MODIFY 新代际 dispatch；V1 原件保留 | 从明确 bundle/source root 消费对应锁，不覆盖旧 expected SHA |
| infra/security/policy/versions/promotion-baseline-v1.json、regression-baseline-v1.json | UNCHANGED | 历史 oracle/source hashes 原样 |
| infra/security/policy/versions/promotion-summary-v2.json、regression-summary-v2.json | CREATE | 新 integrity contract，不声称改变 baseline-v1 策略 |
| infra/security/policy/{command-parent,gitleaks-parent,sbom-parent,trivy-parent,zap-parent}.mjs | 条件 MODIFY 新代际 guard dispatch，须另验收 | 若 owner/Jenkins 变化，不能继续拿原路径 V1 锁验证 V2；只变版本/根绑定，不变决策算法 |
| infra/security/policy/versions/{command-parent,gitleaks-parent,sbom-parent,trivy-parent,zap-parent}-baseline-v1.json | UNCHANGED | 不覆盖五份旧 baseline；Regression 的旧清单同上保留 |
| infra/security/policy/versions/{command-parent,gitleaks-parent,sbom-parent,trivy-parent,zap-parent}-summary-v2.json | 条件 CREATE | 对应 owner/Jenkins 影响的精确新包约束 |
| infra/security/policy/engine.mjs | 当前 UNCHANGED；未来 API 是否扩展是阻塞项 | 单来源语义不变；不能在未评审多来源契约时先实现 batch/reducer |
| infra/security/policy/versions/baseline-v1.json | UNCHANGED | 原标准/等级/override 含义保持 |
| infra/security/promotion/sign-approve.mjs、promote.mjs | UNCHANGED 决策/业务逻辑 | 仍经 checked evidence 入口；若需要直接改其 frozen 行为，停止另立范围 |
| infra/security/policy/resolved-result.test.mjs、summary-version-migration.test.mjs | CREATE | 仅新契约 tests，不自动扩大原 Regression glob/门禁 |
| evidence/<date>/summary-v2-acceptance/ | CREATE | 新旧差分/消费者/版本回滚证据，与旧 parent 样本分开计数 |
| infra/security/summary/baselines/summary-v1/source-index.json 及 source/ 下的镜像目录树 | CREATE 固定 V1 归档 | 索引明确枚举 229 份冻结源文件及运行旧 Engine/oracle 所需的额外传递依赖，保持原相对布局；不能以不包含 untracked Policy 的 HEAD 替代，不递归打包归档自身 |
| 原 scanner / secrets / Gate / Dojo / Loki / Grafana / PetClinic / Deployment | UNCHANGED | 不借迁移扩大功能 |

该集合不是“只改一个 Summary 文件”的承诺。特别是整流水线求值契约和冻结 source-root 包归属仍未解决，不能批准一个隐含多来源生命周期/新 Gate 的大补丁。

## 11. 后续架构兼容与 readiness

仅设计 Policy Engine → resolved result → Summary 这一条清晰交接边。未来 SECURITY_ENABLED、globalMode、securityLevel、switches、capabilities、plugin execution、normalize、Router 可在各自授权轮次演进；本轮没有实施这些开关、契约、路由或 Dojo 解耦。

未满足 readiness：

1. **单次求值范围/接口**：附件要求整 Pipeline 仅调用一次，但现有 API 单 component，且没有统一 final status。原型证明数组拒绝、两个独立来源需两次。需要先明确如何通过现有语义实现真正多来源的一次求值，或明确批准每来源一次/不重复的契约；本轮不擅自改义或实现新 batch/reducer。
2. **时序与 scope**：pre-approval Summary 在 Promotion 操作前产生；Promotion frozen adapter 又依赖原 approval/promote 的 completion/report。若“一次完整 Pipeline 结果”包含这些下游来源，不能在 pre-approval 时封存该结果，更不能让 Promotion 使用包含自身成功结果的 Policy 作为批准依据。需要明确预审批 snapshot 范围、后续非审批 outcome 的报告方式，不能靠二次求值或自批准补齐。

版本选择策略、单来源 envelope、绑定、错误/回放拒绝、schema 与 rollback 已形成可测试设计，但尚不足以声称**一个可落地的全流水线一次求值方案已完整定义**。最小下一步仅是解决以上接口/时序设计边界，仍不实施迁移、不接 Summary、不改生产。

## 12. 最终 35 项交付映射

| # | 项目 | 本轮结论/位置 |
|---|---|---|
| 1 | real Policy call graph | 第1节，两条链分开，生产无 Engine 调用 |
| 2 | authoritative owner | 生产当前无；未来选择 Security Manager orchestration + 唯一 Node owner |
| 3 | current return shape | 第2节，共同七字段、来源扩展、POLICY_ERROR 抛错 |
| 4 | Gate consumption | 当前为原 classifier/退出码；未来才读 resolved decision/status |
| 5 | Summary input | 原固定 reports/env/HTTP；无 result 参数 |
| 6 | handoff | C immutable artifact；现有 D 仅控制引用 |
| 7 | ResolvedPolicyResult | 第2节单来源 envelope；不伪造多来源 final status |
| 8 | single evaluation | 单来源原型成立；整流水线字面要求未满足 |
| 9 | binding | job/build/project/source/targetScope/image/policyVersion + facts/config摘要 |
| 10 | stale | 独立当前 context 不匹配 → POLICY_ERROR |
| 11 | missing | POLICY_ERROR，不找历史成功结果 |
| 12 | malformed | POLICY_ERROR，保留原事实，不重求值 |
| 13 | hash locations | 第5节；inspection.json 保存完整关系 |
| 14 | Promotion | frozen adapter exact SHA，不符 POLICY_ERROR；不是旧运行 Gate 新规则 |
| 15 | Regression | 同上，209项原快照与单 hash 精确匹配 |
| 16 | other guards | Generic副本、六份 owner 锁、四份 Jenkins 锁及其他 adapter，见第5节 |
| 17 | V1 identity/hash | 第5节固定 SHA；SUMMARY_PRODUCER_V1 为设计标签 |
| 18 | V2 identity | 独立 manifest + exact tuple，真实 hash 未产生/未注册 |
| 19 | strategies | 第6节 A/B/C/D 比较 |
| 20 | selected strategy | C explicit versioned integrity contract + pinned包载体 |
| 21 | downgrade | trusted context 显式选择整包，禁止 self-selection/fallback |
| 22 | mixed matrix | 第7节8种组合，区分未来 verifier 与当前 runtime 能力 |
| 23 | rollback | 完整 V1 bundle + 新隔离 run/context；不复用 V2 receipt |
| 24 | schema | 建议保留 Summary schema1，待真实 V2消费者验证 |
| 25 | producer vs schema | producer integrity contract 与文档 schema 分离 |
| 26 | handoff tests | 第9节；32项设计/只读契约用例，含单来源实调用，非生产集成 |
| 27 | migration tests | 9项符号化模型 + 未来真实V1/V2/rollback验收设计 |
| 28 | future files | 第10节 exact proposals；V1归档目录和索引路径明确，传递依赖必须纳入精确索引 |
| 29 | production files changed | **NO**；本轮仅新设计文档/evidence |
| 30 | source preservation | final-validation.json：455引用、229源文件均匹配；4209既有文件无变化 |
| 31 | Policy core | **5/5 PASS**；无全量重跑或旧样本新增 |
| 32 | blocker status | 源码迁移方向已定义；全流水线求值接口/时序尚未闭合 |
| 33 | readiness | **SUMMARY_VERSION_MIGRATION_READINESS = NOT_READY** |
| 34 | exact blocker | 第11节两项；没有把“不实施”本身当阻塞 |
| 35 | next permitted if READY | 不适用；未 READY。只允许继续最小接口/时序设计，不能自动实施迁移 |

STOP。本轮不开始统一插件契约或其他结构性阻塞。
