# ZAP 完整生产父阶段兼容性（2026-11-02）

**ZAP = VERIFIED**，限定当前冻结 `zap-gate.mjs`、共享 `scanner-runtime.mjs` 及原Security Manager所选ZAP模块的 **baseline-v1 / standard** 兼容性。

**完整parent191/191 MATCH，MISMATCH0；old / standard均为PASS34 / FAIL157。** 包括172个完整原Gate+runtime重放、19个原Manager聚合重放。全部新输入为synthetic/disposable，证据分类 **CONTROLLED_REPLAY**，不是在线ZAP扫描、生产漏洞复现、工具包认证或真实认证模型验收。

新增测试196/196 PASS，原ZAP分类器测试另2/2 PASS，本轮共198 PASS / 0 FAIL。原4个classifier-only冻结样本保留并逐项核对，没有重写或计入191个完整parent样本。其他来源未重跑。

## 1–4：生产位置、prerequisite、执行与身份

入口有两个，均使用原Gate：

- `Jenkinsfile` 的 `DAST Read-only Gate`：`node --max-old-space-size=128 infra/security/zap-gate.mjs`，外层timeout8分钟。
- `Jenkinsfile.security-audit` 调用原Security Manager；`resources/security-manager/petclinic-adapter.json` 的 `ZAP Passive` 执行 `node infra/security/zap-gate.mjs`，其environment设置 `SECURITY_CLEANUP_SCAN_HOMES=true`。

主要实现为 `infra/security/zap-gate.mjs`、`scanner-runtime.mjs`、`zap-policy.mjs`、`zap-confirmations.json`、`gate-contract.mjs`、`scanner-tools.json`、`tools-lock.json`、`ZapAuthProbe.java`、原Manager与上述入口。

五层明确分开：**prerequisite/target事实 → ZAP执行 → raw alerts → 原确认/复现证据 → 完整parent判定**。ZAP进程退出0本身不是安全PASS。

共享runtime的真实路径全部保留：

1. scanner manifest与锁定SHA匹配；读取toolchain，核对外层heavy Lease owner。
2. 检查 `zap` prefix匹配的文件SHA及symlink目标。
3. 创建原非root、无SA token、只读root临时Pod；等待Ready，执行UID10001/token/root安全探测。
4. 测量可信Jenkins Pod IP，canary基线与Pod出站拒绝须成立，再把工具归档传入Pod。
5. 调用完整ZAP action，最后执行原多层cleanup。

受控tool manifest用代表性的jar/addon/symlink条目验证原循环，合成bytes实际计算SHA，未跳过哈希算法。**不声称本轮重新认证生产全部148个ZAP文件的实际bytes**；原生产manifest、lock及Gate源码按SHA固定且未变。没有安装工具或启动真实Pod。

业务目标取自Service的clusterIP/第一个port；固定GET `/`、`/owners/find`、`/vets.html`、`/actuator/health`。读取Deployment image；仅当K8S_IMAGE存在才要求与其相同。报告与confirmation还绑定该image和业务JSON报告SHA，没有新增build/source revision attestation。

目标可用性有明确边界：loopback fixture有最多20次TCP启动探测；业务没有独立的Deployment ready或HTTP health前置Gate。ZAP requestor要求responseCode200，目标不可达由原scanner/probe非0结果体现；不能新增预检并称为旧规则。

## 5：confirmed 与 unconfirmed High

原分类器 `classifyZap` 完整复用，没有新risk引擎。业务High只有同时符合以下原条件才blocking：

- riskcode数值3，且不是ordinary信息项10020/10021/10038/10062。
- pluginid、targetImage、reportSha256、实例GET URI与confirmation精确匹配。
- category属于sql_injection、command_injection、xss、path_traversal、ssrf、auth_bypass之一。
- positiveValidated、negativeValidated、exploitConfirmed、evidenceVerified均为true。
- evidencePath非空，expiresAt可解析且在未来。

Gate在分类前将每个proof的evidenceVerified重置为false，然后要求路径在原reviewed evidence范围，读取bytes核对SHA，验证plugin/image/reportSHA/URI/category五个字段及文件内三个验证true，才设置true。输入自己声称verified不能绕过该原路径。

本轮8个明确业务confirmed High样本均FAIL；19个未确认/ordinary High或lower样本均保留WARN事实且父Gate可PASS。另1个loopback confirmed fixture自检拒绝样本单列fixture-validation，不算真实业务漏洞。

confirmation输入、证据文件、expiry和复现标记全部是受控fixture。生产 `zap-confirmations.json` 仍为空，未写入任何新的reviewed proof文件，没有攻击目标或签发真实确认。

## 6–8：exit/error、report与既有分类器

实际ZAP命令参数保持：

```text
java -Xmx384m -Djava.awt.headless=true -Djava.util.prefs.userRoot=/work/prefs
  -jar /work/tools/zap/zap-2.17.0.jar -cmd -silent
  -host 127.0.0.1 -port 18084 -dir /work/<label>-home
  -autorun /work/<label>.yaml
```

plan只有固定GET requestor、passiveScan-wait(maxDuration1)、traditional-json报告；business另traditional-xml。没有spider、forms或activeScan。

- ZAP执行只允许exit0；exit1/2/127、spawn error、signal/null、timeout均按原run抛错。不能把工具warning exit改为security PASS。
- Pod Ready请求预算190秒；默认exec90秒，ZAP150秒，auth probe240秒，tool transfer150秒；outer Jenkins仍8分钟。所有超时通过原error路径重放，不实际等待这些时长。
- 原Gate只接受GATE_ZAP=warn/enforce；即使warn，存在blocking High仍会throw，不能降级。
- 原runtime中memory peak读取允许exit1；其观察原样保留，不额外加严。

报告路径包括Pod内 `/work/{fixture,fixture-negative,business}.json`、`business.xml`；workspace里的日志、native/plan、fixture正反报告、auth-readonly、business-report与最终 `.devsecops/zap-gate.json` 均保留。

解析先JSON.parse，再检查site hostname白名单。`highAlerts` 要求非空site、risk为整数0–3；缺alerts按空处理。白名单按hostname，不新增port/path限制；confidence原样保留，但不是独立阻断条件。业务reportSha256由 `JSON.stringify(parsed report)` 计算，不冒充原JSON/XML bytes的hash。

报告缺失、损坏JSON、无site、非法risk、proof文件缺失/损坏/不匹配、读写失败均按原实现处理。Policy成功receipt还须带原native/父报告及一致的classifier/target上下文；替换或缺证返回NOT_TESTED/null，不凭不完整事实生成新判定。

## 9–10：parent aggregation与adapter完整性

collector在VM执行**完整未修改Gate和共享runtime**，只替换外部fs、socket、子进程、计时和环境观察。原classifier作为原函数调用；Policy不导入collector、VM或oracle，不消费oldDecision字段。

原Manager使用固定SHA的本地Groovy执行，资源计划只选ZAP，Jenkins DSL为inert替身；原模块返回码、credentials/stage/sh、结果写入和archive异常全部保留。没有执行实际Summary脚本、其他扫描器或Jenkins CPS。

Gate失败和scanner执行失败保留不同原观察，父进程可以均为非0。即使原report某个status字段已为success，只要后续memory/read/write/cleanup导致原进程失败，Policy仍FAIL。默认standard及完整parent强制失败floor已验证；disabled/skipped/not_configured不成为PASS。

## 11–22：样本、边界和cleanup

| 项目 | 数量 / 结果 |
| --- | --- |
| 原classifier-only冻结样本 | 4，保留并复核，不计完整parent |
| 完整原Gate+runtime | 172 CONTROLLED_REPLAY |
| 原Manager parent聚合 | 19 CONTROLLED_REPLAY |
| 完整parent合计 | **191** |
| 真实历史完整parent | **0** |
| synthetic输入 | 191；另5项unit-only契约检查不计parent |
| 业务confirmed High | 8 |
| unconfirmed High / ordinary / lower | 19 |
| proof validation | 13 |
| prerequisite | 6 |
| target identity / target readiness | 4 / 2 |
| runtime network / tool unavailable | 6 / 7 |
| execution error / timeout / transfer | 19 / 7 / 4 |
| missing / malformed report | 3 / 16 |
| report read / IO-write | 3 / 22 |
| cleanup | **15** |
| parent aggregation | 19 |

主标签互斥计数；全部类别（包括positive、selftest、configuration和existing-boundary）见acceptance.json，不把同一个fixture多次加入总数。

Cleanup是当前真实契约，**不是NOT_APPLICABLE**：同步ZAP JVM退出后先保留日志/native/plan，再按配置清session home；停止fixture server；action finally删除本地Java临时目录；runtime finally关闭canary、核对Pod UID、使用UID precondition删除原Pod，并最多45次确认消失。删除/读回/残留/替换UID/本地rm/进程停止失败均保持原FAIL。

原created UID缺失会跳过Pod删除；cleanup flag=false时不清scan homes；这些分支均按原逻辑保留，没有添加强制清理规则。所有rm/delete/kill均在in-memory替身中，未执行实际删除。

Auth probe的原Java源码已盘点且hash固定：synthetic角色/ownership自检，business只public GET及合成invalid/stale-cookie/removed观察；real identity model明确unsupported。本轮把Java工具运行作为外部执行事实提供，不运行javac、Java客户端或真实session。原父Gate仅消费结果结构/数组长度等已有字段，不因auth报告的某个status或公开GET状态字段而凭空新增Gate。

历史搜索只覆盖两个已知本地归档/runtime根目录的文件名；未找到ZAP命名归档，不声称穷尽所有账户或远程归档。真实完整parent样本保持0；构造的High/evidence输入不冒充历史漏洞或真实复现。

## 23–26：决策与raw fact不变性

| Decision | Existing parent | baseline-v1 / standard |
| --- | ---: | ---: |
| PASS | 34 | 34 |
| FAIL | 157 | 157 |
| WARN | 0 | 0 |

**MATCH191 / MISMATCH0；raw facts preserved = YES。** Parent没有独立WARN退出，不代表丢弃Finding WARN；normalized classification仍保留原warnings。

原alert ID/name、risk/confidence、URL/endpoint、confirmation验证状态、target、scanner执行及原始报告bytes不变。191份落盘fixture逐一重新读取，raw SHA191/191、decisions191/191；172份script input SHA172/172，19份wrapper另存原输入/执行事实。所有rawEvidence深比较及输入前后序列化一致。68个显式命令/IO故障注入键均确认到达原代码路径。

2981份受保护既有文件中2980份未变。唯一既有变化为Policy engine两行追加（ZAP parent import/分派），移除两行可恢复此前SHA；原Gate、classifier、runtime、production confirmations、Jenkins、Manager、release、actual Summary、其他已验收来源和最终readiness审计均未修改。

## 27–30：缺口、最终状态与停止

当前冻结production parent没有剩余standard compatibility blocker。仍未认证在线ZAP/JVM/工具包/集群/service健康、真实漏洞复现或生产认证模型；没有完整历史parent transcript，真实历史样本0。原Manager是本地Groovy/inert DSL，非Jenkins CPS。generic manager/tool.mjs ZAP分支也不在本生产parent认证范围。

最终 **ZAP = VERIFIED，可以退出本次compatibility阶段**。新测试196/196 PASS，原分类器复核2/2 PASS，本轮198 PASS / 0 FAIL，未重跑其他已验收adapter。

本轮只写ZAP自身coverage-delta，**不重建最终readiness、不接Summary、不改发布、不rollout、不开始下一来源**。Global Master Switch、统一plugin contract/lifecycle、Router等架构要求保留，本轮未实现。

机器证据位于 `evidence/2026-11-02/zap-parent/`：`production-inventory.json`、`acceptance.json`、`differential.json`、`workflow-differential.json`、`persisted-fixture-verification.json`、`classifier-preservation.json`、`fault-reachability.json`、`source-preservation.json`、`historical-evidence-search.json`、`safety-check.json`、测试日志和fixture。
