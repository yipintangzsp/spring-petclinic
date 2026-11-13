# Command Analysis compatibility · 2026-11-01

**Command Analysis = VERIFIED**，限定当前完整冻结生产stage与Policy Engine baseline-v1 / standard的兼容性。**136/136 MATCH，drift=0；old/standard均为PASS26 / FAIL110。** 本轮新测试145/145 PASS，累计已验证Policy用例1604（前1459+本轮145）；没有全量重跑1604或其他已验收adapter。

没有改原分析器、Semgrep rules、原Gate、发布、actual Summary或集群，没有运行被检查的危险命令、SSH、Semgrep CLI、真实scanner Pod或生产扫描。本轮停止，不开始Promotion、Summary、master switch、plugin lifecycle或其他结构性工作。SOPS/age=NOT_TESTED/ENVIRONMENT_BLOCKED、Sonar negative=DEFERRED_REAL_NEGATIVE_EVIDENCE保持。

## 生产入口与精确契约

`resources/security-manager/petclinic-adapter.json`中id为**semgrep**的生产模块实际命令是：

```sh
( node infra/security/command-audit.mjs && node --max-old-space-size=128 infra/security/semgrep-gate.mjs )
```

这不是只有Semgrep分类函数的Gate。command-audit失败会短路，不执行Semgrep。`vars/securityManager.groovy`记录组合命令退出码，生产adapter只允许enforce、禁止关Gate；非零（包括10）或Jenkins阶段/credentials/write/archive异常均FAIL。`Jenkinsfile`也调用既有Semgrep脚本；本轮完整组合范围以当前production adapter为准。

原实现位置：

- command-audit.mjs：Lease、tracked files读取、隔离Python Pod、内嵌原分析脚本、JSON报告验收、UID安全删除与wait。
- command-audit.py、script-command-policy.py、ssh-command-policy.py、interpreter-command-policy.py：库存、原静态流分析与self-tests。
- script-command-review.json、ssh-command-review.json：原审查与source hash证据。
- semgrep-gate.mjs、semgrep-policy.mjs、scan-rules.json：原Java规则、正反重复自检、native source scan与既有classification。
- scanner-runtime.mjs/scanner-tools.json/tools-lock.json：共享tool/Lease、Pod、read-only/nonroot/token、网络canary、transfer、source身份观察与cleanup。

无适用AGENTS.md。先读原来源、历史capability/production matrix；仅另存本轮coverage，历史证据不覆盖。

## 原规则族、source/sink与语言边界

| 规则族 | 原source/sink及FAIL语义 |
| --- | --- |
| Java HTTP → Runtime.exec | scan-rules的java-http-runtime-exec：getParameter到整个executable参数的既有taint规则 |
| Java HTTP → single-arg ProcessBuilder | java-http-process-builder：getParameter到new ProcessBuilder($CMD)；不扩大成所有argv调用 |
| Python shell/interpreter string | 显式input、未shadow的sys.argv、明确Flask request.args/form.get，经原局部赋值流到列出的subprocess shell=True、os.system/os.popen、eval/exec等string sink；原识别allowlist/quote和unknown_environment条件保留 |
| SSH remote command | 既有controlled.remote导入及固定host三元素ssh argv；只有原proven调用且taint集合恰为external才FAIL。一般SSH options、动态加载别名、file/env来源不提升 |
| Interpreter code/stdin | 原subprocess APIs中sh/bash/dash/python/python3 -c/-lc、node -e/--eval及原支持的解释器stdin程序；按原精确flags处理 |
| SSH nested interpreter | 原可证明remote(shlex.join([...]))、或特定outer interpreter prefix+shlex.quote(code)；外层引用不自动证明解释器code安全 |
| 非Python库存 | .sh/.mjs仅做既有保守inventory，复杂script、wrapper、env/file/message来源和跨函数分析不补造FAIL |

custom输入来自既有git ls-files列表中的.py/.sh/.mjs及Jenkinsfile名称；并非所有收集的文件都被当作支持语言：Jenkinsfile不会因此获得新Groovy污点分析。Java来源由原git archive HEAD src/main/java传输，不给custom Python analyzer添加Java支持。

Python PROCESS/SINK集合、SSH wrapper识别、interpreter literal command/flag组合及shadow/quote/allowlist均以原文件为准，没有新增模式。原静态模块通过AST解析被检查源码，**绝不执行被检查的源码或其shell/SSH调用**。

Semgrep原enforcedRules还包括java-weak-cipher，这是组合父stage原有的非command谓词。为了完整parent兼容保留它，不在本轮修改其他Semgrep规则。原判定只看既有rule ID和ERROR/HIGH/CRITICAL等severity；不因validation_state=NO_VALIDATOR或is_ignored字段自行添加/撤销FAIL。generic command规则java-runtime-exec/java-process-builder继续保留原warning事实，不当成HTTP直达证明。

## direct与complex、身份与聚合

原Python报告保留path/line、source说明、sink、action、rule、reason、分类；SSH保留wrapper/source_evidence；interpreter保留kind/source；Java保留check_id、path、start/end、extra.severity、metavars、engine/validation_state等。没有凭空给Python加column或为Java添加未经证实source关系。

原各分析器自行按既有path/line/sink、wrapper或kind去重；组合报告原样累加Python、SSH、interpreter blockingFindings。Policy不新建去重或跨报告合并规则。

**复杂/不确认流在报告中仍为WARN/审查事实，但原组合stage可能是PASS。** 这不是将原stage WARN降为PASS：生产wrapper原来就按整个脚本退出码记录success；原分析器的逐条WARN与stage decision分开。库存dangerous计数本身也不是新的阻断谓词；例如env来源可保留危险/unknown库存但无已证明直接流阻断。

custom Python exec允许0/1以便读取失败报告；随后原wrapper解析JSON并要求report.status=success，空输出/无效JSON/null/失败status保持FAIL。不能简单把每条custom调用的nonzero当作新Gate，也不能把parser崩溃填成空成功报告。

Semgrep原positive/negative/repeat、自检classification、HTTP正反repeat都必须通过；7类scan的空/超过500文件、越界路径、执行/parse失败均阻断。source scan原分类有blocking就FAIL；**findingMode=warn也不会软化原代码的blocking抛错**。

前置与结束行为同样在范围内：Lease/tool manifest/hash、create/Ready、security probe、Jenkins Pod IP、canary基线与连续拒绝、tool/source传输、native/report write、memory peak读取、UID不变、delete/wait/cleanup。失败不能由其他成功报告掩盖。未扩大全局权限或改变节点网络。

## 证据分类与完整对照

### REAL_HISTORICAL：1个完整parent接受样本

复用petclinic-ci #270的真实组合stage日志（包含两个实际调用、rc=0、exit0），以及command-audit.json、semgrep-native.json、semgrep-gate.json共3个原始artifact。source/UID/cleanup与原报告保留。原件/摘录hash见historical-index.json。

这证明历史parent接受结果，不补造每个CLI/Pod前置的完整transcript；自然生产失败事件未制造。

### CONTROLLED_REPLAY：135个完整样本

122个parent样本中1个是真历史，其余121个重放；再加14个原Groovy wrapper样本，共135个controlled。

old side运行未修改控制流的command-audit.mjs、semgrep-gate.mjs和原scanner-runtime。imports被注入冻结依赖；Semgrep动态child_process import仅改为注入同一spawn依赖，未改任何Gate谓词。fs写/Pod/kubectl/git archive/tool transfer/net canary全部为内存替身，不访问真实集群。原source/rules只读，fixture路径与报告明确标记synthetic。

custom fixtures实际调用原内嵌Python分析脚本和原四个模块，但仅解析测试文本；self-tests全部保留executed_commands=0。Java使用历史验证Finding和明确构造的frozen报告，不声称本轮重新运行Semgrep引擎或证明新Java taint结果。

每个controlled parent还在真实本地/bin/sh执行原`&&`表达式，node为inert stub，返回对应原脚本重放的状态，核对短路与最终退出结果。原Groovy直接执行未修改vars/securityManager.groovy，但resource plan仅筛选原semgrep项，Jenkins DSL无外部作用；是所选完整Gate，不是全平台总验收。

### SYNTHETIC_UNIT_ONLY：9项辅助检查

缺完整事实/错误命令/缺第二阶段/缺status/报告、不可缺少的native capture、无AST重跑与double count、被检查程序不执行、low/strict/audit/override不软化FAIL等；不计136个完整差分。

完整差分：parent122+wrapper14=**136**；PASS26 / FAIL110 / WARN0。分支计数：确认直达流18（shell6、SSH3、interpreter4、nested2、Java3）；complex/unconfirmed13；safe controls7；parser errors8、malformed10、missing13、execution16、prerequisite5、IO4、lifecycle8、isolation4等。详见acceptance.json及逐样本记录，不能将这些controlled负例称为生产事故。

## Adapter、不可变与double-counting

新增command-parent.mjs、command-parent-replay.mjs、command-parent-fixtures.mjs、两份test/Groovy harness和版本锁；仅在已有semgrep-command-audit component收到带stage事实时分派完整parent。旧command-evidence分类接口和之前5个样本保留，未改已有Semgrep adapter。

Policy只消费原operations execution/reports/observations，保留原&&短路：audit失败不允许冒出成功Semgrep操作；audit成功必须有完整后续执行。成功操作缺捕获的native/gate报告是NOT_TESTED，不伪装PASS。缺证不等于实际ENOENT，两者分开；失败操作可保留其已写或未写报告及原diagnostic。

Policy **不import/re-run** custom analyzer、AST、Semgrep分类器或collector；不推断taint、不发明rule/severity/source/sink。原报告作为独立事实进入normalizedFacts，不与Semgrep adapter再次分类或累加。**Semgrep double-counting check=PASS**。Python/SSH/interpreter原先可能重叠的Finding不在本轮重新计数或更改。

136份落盘输入已重载核对SHA、decision和raw不变；3份历史原件、原规则/17份保护文件/108份原安全源不变，此前**1114份已验收证据**无变化。版本锁发现原来源变更会POLICY_ERROR，要求重新冻结；这不是新增生产规则。

## 23项验收

| 项 | 结果 |
| --- | --- |
| 1 locations | 上述compound映射、custom4模块、Semgrep/rules/runtime、Shared Library |
| 2 exact contract | 原command-audit && Semgrep及所选production parent |
| 3 rule families | Java HTTP Runtime/单参数Builder、Python shell、SSH、direct/nested interpreter；原父stage其他谓词保留 |
| 4 source/sink | 原AST/规则定义；Policy不生成关系 |
| 5 direct/complex | 原直达阻断，unknown/复杂/审查事实保留；逐条WARN与stage PASS分开 |
| 6 adapter | YES |
| 7 historical | 1个#270 parent +3份artifact |
| 8 controlled | 135完整重放 |
| 9 synthetic | 受控源码/scan报告/外部观察，不冒充事件；另9项unit-only |
| 10 confirmed direct | 18个专门parent样本 |
| 11 complex/unconfirmed | 13 |
| 12 missing/malformed | 13 / 10；parser-error另8 |
| 13 execution/prerequisite/IO | 16 / 5 / 4；另lifecycle8、isolation4及wrapper异常 |
| 14 old decisions | PASS26 / FAIL110 |
| 15 standard | PASS26 / FAIL110 |
| 16 complete differential | 136 |
| 17 matched/mismatched | 136 / 0 |
| 18 raw preserved | YES，rule/位置/flow/validation/report原样、136落盘复核 |
| 19 double-counting | PASS；新Policy不重新调用Semgrep分类器或合并Finding |
| 20 gaps | 历史每调用前置transcript不全，未做新live Semgrep/Pod/CPS健康验收；不影响限定frozen兼容证明 |
| 21 final | VERIFIED，仅baseline-v1/standard冻结生产compatibility |
| 22 Policy tests | 本轮145 PASS/0 FAIL；此前1459，累计1604；未全量重跑 |
| 23 leave phase | YES，仅Command Analysis；本轮停止 |

证据：`evidence/2026-11-01/command-parent/`中的acceptance.json、differential.json、workflow-differential.json、fixtures、historical-*、source-preservation.json、persisted-fixture-check.json、no-double-counting-proof.json、policy-tests-new.log、production-coverage-update.json、artifact-safety-check.json、artifact-sha256.json。

复核本轮：`node --test infra/security/policy/command-parent.test.mjs infra/security/policy/command-parent-workflow.test.mjs`。仅执行原安全静态Python分析、原脚本的无I/O重放及inert shell/Groovy，不运行被检查程序。Groovy沿用本地固定2.4.21，PROVENANCE_GROOVY_JAR可指定；SHA256=de65260cf2070442e99882f2f3d72e7531725c1e6a257446cc0cea525c607bd0。没有新服务、私钥/Secret读取或权限变更。
