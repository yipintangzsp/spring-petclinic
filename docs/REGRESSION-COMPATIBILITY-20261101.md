# Regression compatibility · 2026-11-01

**Regression = VERIFIED**，仅当前冻结生产Regression命令及所选父Gate与Policy Engine baseline-v1 / standard的兼容性。**38/38 MATCH，drift=0；old/standard均为PASS9 / FAIL29**。不是新全局测试框架，不是新Jenkins发布验收。

原生产命令在临时复制仓库执行：**147/147 PASS**。本轮新Policy测试 **46/46 PASS**；此前全量基线1413通过，累计已验证1459项。**本轮没有重跑全套1459或所有已验收adapter**，遵从用户范围限制。

本轮停止，不开始command analysis、Promotion、Summary或插件生命周期。SOPS/age=NOT_TESTED/ENVIRONMENT_BLOCKED仍阻塞全平台验收，Sonar real negative=DEFERRED_REAL_NEGATIVE_EVIDENCE保留。原Gate、原测试、发布、actual Summary与集群均未修改，没有rollout。

## 当前Regression究竟是什么

精确生产命令：

```sh
node --test --test-concurrency=1 infra/observability/*.test.mjs infra/security/*.test.mjs
```

入口是`resources/security-manager/petclinic-adapter.json`中id=regression、stage=Regression、platform=true；`vars/securityManager.groovy`执行该模块命令、归档日志并按退出码维护模块与构建结果。`Jenkinsfile`的Test stage也调用同一行；该stage后面的terraform-sandbox-tests、Maven和messaging命令**不是本Security Regression的组成部分**，本轮没有执行它们。

两个glob均只匹配各目录顶层，当前35份文件、147项测试。**不包括infra/security/policy/*.test.mjs**，也不包括provenance子目录其他测试。没有递归匹配、新扫描器运行或既有Policy兼容报告聚合。

它是现有Node单元/契约/纯函数及受控IO测试集合：

- 预期正反例断言，包括已有签名拒绝分类、扫描结果分类、runtime持续性、UID/身份/策略配置约束等；
- 读取checked-in policy/config/manifest/reference文件做结构和锁定hash断言；
- 已有构建/发布辅助函数的fixture行为、临时缓存、mock kubectl、临时loopback HTTP测试。

包含Terraform/Promotion等既有测试，是**原Regression命令本来直接选择的测试文件**；本轮没有处理这些来源的adapter、生产操作或新功能。

完整35文件/hash、导入、已有测试名称与排除范围见production-test-inventory.json。没有适用AGENTS.md；已读取既有Security Manager契约、Capability Matrix与production-gate-inventory。本轮更新另存coverage，不覆盖历史检查快照。

## 比较、身份与聚合语义

这里没有一个“读取前次scanner findings → 比较当前scanner findings”的引擎，也没有stage级baseline revision/current revision/build/image digest绑定或独立Regression JSON schema。所谓baseline/reference是**原测试代码里的预期值和被断言的checked-in文件/fixture**。

一些测试本身校验具体的UID、image、source、owner、manifest hash、predicate/分类结果；这些规则由原测试/原函数判断。Policy不复制或重新推断它们。缺reference、缺manifest或损坏JSON只在实际原测试消费该文件时失败，不给未被消费的live scanner报告发明必需条件。

Node串行运行被选文件，任一未处理断言/模块加载/语法/基础设施故障通常导致进程非零。**Gate消费进程退出结果，不解析TAP summary或severity。** 当前Gate没有WARN分支；生产adapter仅允许enforce。

父wrapper原文为：

```sh
set +e
<原Regression命令> > .devsecops/gates/regression.log 2>&1
rc=$?
cat .devsecops/gates/regression.log
exit "$rc"
```

模块退出非零（包括10）保持failed、构建失败；stage/credentials/writeJSON/archive等异常仍失败。没有Regression专属SKIPPED/NOT_CONFIGURED生产路径；generic profiles也没有regression ID，不能宣称实现了独立生命周期。传生产audit/off或试图禁用unknown regression模块会按原Manager规则失败，未改成跳过。

### 原实现的可见边界

1. **没有固定35文件/147项完整性Gate。** 在受控副本删除一份原`.test.mjs`后，glob仍找到其余文件，原命令145/145通过，旧/new都PASS。没有为baseline-v1新增“必须147”规则。
2. `.devsecops/current-scan.json`从来不是此stage输入。它不存在时，原测试仍147/147通过；不冒充“缺当前扫描结果仍安全”的证明，只说明不消费它。
3. 原wrapper显式`exit "$rc"`，所以cat读回失败不能覆盖前面退出0；redirection失败会进入非零rc并FAIL。两者均实测原shell表达式。
4. 为证明Gate不解析日志，inert node fixture曾输出TAP样式FAIL文本但exit0，旧/new均PASS；另一个输出PASS文本却exit1则均FAIL。**这不是原Node测试发生断言失败后仍PASS**，只是有明确标记的synthetic命令输出重放。真实原断言失败的受控执行均exit1。
5. 版本锁hash是本轮兼容性证据漂移检查，不是给生产新增baseline/build identity Gate。它绑定当前209份原测试/代码/config/reference；不含新Policy目录。

## 证据与执行

### REAL_HISTORICAL

#270日志保存完整Regression段：实际展开的35文件node命令、TAP footer tests147/pass147/fail0、rc=0以及显式exit0。限定摘录在historical-270-regression.log，原console路径/hash与行号见historical-evidence-index.json。它足以冻结该退出码Gate正例，不补造主机全部prerequisite transcript。历史自然失败构建样本没有取得，未伪造。

### CONTROLLED_REPLAY

共37个完整样本，加1个历史样本=38：

- command类13：11次隔离受控原完整suite、首次受限沙箱执行、#270历史观察；
- shell类12：执行原父wrapper，node/cat为临时inert可控替身，验证退出/日志IO聚合；
- wrapper类13：本地Groovy2.4.21直接执行未修改vars/securityManager.groovy，Jenkins DSL不访问外部系统，resource plan仅筛选原Regression项用于所选模块证明。不是全Manager其他模块总验收。

11次受控原suite中未新增生产测试文件，没有运行Policy目录；故障仅修改临时复制目录，finally恢复/删除：

| 场景 | 原结果 |
| --- | --- |
| 原仓库副本、不改任何输入 | PASS，147/147 |
| missing-frozen-reference | FAIL |
| malformed-frozen-reference | FAIL |
| enforcement-regression（副本Enforce→Audit） | FAIL |
| exception-identity-mismatch（副本owner UID缺失） | FAIL |
| missing-current-manifest | FAIL |
| runtime-evidence-source-mismatch（副本manifest hash变化） | FAIL |
| malformed-existing-test-source | FAIL |
| missing-existing-runtime-module | FAIL |
| one-test-file-absent-existing-glob-semantics | PASS，145/145；原边界保留 |
| unconsumed-live-scan-evidence-absent | PASS，147/147；不消费该输入 |

首次原命令在受限沙箱因原loopback fixture `listen EPERM 127.0.0.1`失败，完整日志保留为环境FAIL样本。随后仅为这些原临时本地fixture使用允许loopback的执行环境，原命令147/147通过；没有修改集群/IAM/firewall/host网络配置，也没有把本机EPERM称为生产安全回归。

### SYNTHETIC_UNIT_ONLY

8项辅助测试：6个缺证/未完成/错命令/unsupported输入的NOT_TESTED保护，1个low/strict/override/audit不得软化既有FAIL，1个无循环依赖检查。不计入38完整差分。

## Adapter、原事实和非循环证明

新增regression-evidence.mjs、regression-parent.test.mjs、regression-workflow-oracle.groovy与versions/regression-baseline-v1.json；Policy仅新增regression分派/已知component，不接生产Manager或Summary。

adapter只消费原执行的status/signal/error/stdout/stderr及原wrapper failed/module facts，输出独立decision和normalizedFacts。缺真实completion/退出观察、命令不匹配或未采集输出返回NOT_TESTED/decision=null；不是将其当成成功。真实ENOENT/非零与“未采集证据”分开。保留原诊断，不把infra/IO、assertion回归、缺reference等一律称为漏洞。

**circular/self-validation = PASS：**

- old来自真实原命令、实际原shell、原Groovy或历史显式exit，均不调用Policy；
- 原glob与原35测试没有导入Policy Engine；临时suite副本根本没有Policy目录；
- Policy不rerun scanner、不import这些测试、不生成历史Finding；
- 新测试比较原结果和新decision，绝非Policy输出对Policy输出。

所有38份落盘输入重载验证SHA、decision、rawEvidence不变。baseline/reference、当前manifest/fixture、身份和原比较输出只在临时副本被用于故障注入，仓库原件、历史console与原测试零修改。此前Cosign/Provenance/Build Provenance/SBOM **1037份证据**不变，108份原安全源及38份本轮保护文件保持hash/HEAD一致。

## 24项验收

| 项 | 结果 |
| --- | --- |
| 1 locations | 原资源映射、Jenkinsfile中同一node命令、Shared Library、35顶层测试 |
| 2 exact contract | 串行node:test退出码Gate，非全局扫描历史比较 |
| 3 facts consumed | 原断言、原checked-in引用/fixture、原进程与wrapper结果 |
| 4 comparison model | 预期行为/结构/hash/身份断言；没有跨扫描build baseline比较 |
| 5 identity | 仅原测试内约束；没有新stage级build/digest要求 |
| 6 aggregation | Node测试进程→原shell rc→原Manager selected module/build |
| 7 adapter | YES |
| 8 historical | 1个#270真实完整Regression段正例 |
| 9 controlled | 37完整重放 |
| 10 synthetic | inert shell/wrapper与副本故障明确标记；另8项unit-only |
| 11 regression/drift | Enforce回退、exception身份、runtime锁定hash等3个受控完整suite失败 |
| 12 missing evidence | reference、current manifest、runtime module等3个完整suite失败；不消费的live scanner输入另列 |
| 13 malformed/identity | 损坏reference JSON/原test语法2个，exception UID及原hash绑定失败如实保留 |
| 14 execution/infra/IO | 原沙箱EPERM、node缺失/非零、wrapper redirection及Jenkins步骤异常；各原始诊断保存 |
| 15 old decisions | PASS9 / FAIL29 / WARN0 / SKIPPED0 / NOT_CONFIGURED0 |
| 16 standard decisions | 完全相同 |
| 17 complete differential | 38=command13+shell12+Groovy13 |
| 18 matched/mismatched | 38 / 0 |
| 19 raw preserved | YES；38落盘复核，1037已验收artifact不变 |
| 20 circular check | PASS，old不依赖Policy |
| 21 gaps | 历史自然失败构建/完整host prerequisites、live Jenkins CPS未补；未声称生产发布验收 |
| 22 final Regression | VERIFIED，仅冻结生产source与baseline-v1/standard兼容 |
| 23 Policy tests | 本轮46 PASS/0 FAIL；此前1413基线通过，累计1459；未全套重跑 |
| 24 leave phase | YES，仅Regression；本轮停止 |

证据目录`evidence/2026-11-01/regression-parent/`包含acceptance.json、differential.json、controlled-executions.json、production-test-inventory.json、non-circular-proof.json、historical-*、actual-original-baseline.*、logs/、fixtures/、persisted-fixture-check.json、source-preservation.json、policy-tests-new.log、production-coverage-update.json、artifact-sha256.json。

本轮新对照测试可在仓库根用`node --test infra/security/policy/regression-parent.test.mjs`复核，它读取冻结执行事实并仅执行inert shell/Groovy wrapper，不会重跑scanner或147项生产suite。Groovy沿用前轮本地固定2.4.21 jar，PROVENANCE_GROOVY_JAR可指定；SHA256固定de65260cf2070442e99882f2f3d72e7531725c1e6a257446cc0cea525c607bd0，缺失/hash不符明确失败，不自动联网。没有新服务或生产权限变更。
