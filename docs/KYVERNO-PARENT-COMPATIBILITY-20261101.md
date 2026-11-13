# Kyverno/RBAC完整父Gate兼容性收口

**Kyverno/RBAC = VERIFIED**，范围严格限定为**当前冻结源码在baseline-v1/standard下的完整父Gate判定兼容性**。验证方法是完整旧脚本对冻结输入的隔离重放，不是一次新的生产准入验收，也不是对Kyverno策略安全性的全量认证。

本轮结束立即停止。没有生产变更、准入请求、RBAC变更、扩权、其他来源实现、Summary接入或rollout。

## 对照单位与证据分类

旧路径完整执行原 `rbac-contract.mjs && admission-gate.mjs`：只有RBAC脚本成功才执行admission脚本，保留父阶段短路。两个旧脚本只在无网络/无进程/无文件写入的VM中运行，外部command/read/write由冻结观察提供；未修改源码。新路径消费同一configuration与observations，通过parent adapter进入Policy Engine。对照不是仅调用原probe或rbac helper。

**49个新增完整父Gate样本全部分类为SYNTHETIC_COMPLETE_PARENT_WITH_HISTORICAL_PROBE_RESULTS。** 它们复用#270的35项真实准入观察、3项合法exception观察，以及已有真实只读RBAC数据；但完整父输入、异常变体、exception Pod模板等由受控fixture构建，不冒充历史完整请求或生产事故。真实完整父Gate新执行0次，新生产准入请求0次。

此前49/49子契约证据原样保留，与本轮49个完整父样本分别计数；不将子例加成98个完整父样本。

## 1. Parent policy-alignment

原Gate预期的是源码 `production-baseline.json` 的policy（metadata.name=devsecops-production-baseline），没有另设业务策略version编号。它在16项初始探测后读取live spec，按源码rule.name查找实际rule，精确深比较validate.cel、preconditions、match，并要求validationFailureAction=Enforce。

已覆盖aligned、CEL变化、preconditions变化、match变化、缺rule、非Enforce、policy不可读、JSON损坏及缺spec。全部按原逻辑PASS或FAIL，没有新增WARN分支。原Gate不比较所有metadata或spec字段；adapter没有补造更严格版本契约。

新增kyverno-parent-baseline-v1.json只锁定**已有验证器的源码摘要与原探测数量**，不是修改Kyverno策略。4个原文件hash变化时要求POLICY_ERROR及重新验证，不默默沿用旧baseline。

## 2. Exception owner/request binding

原模型仍为falco、nodeExporter、sonarInit。先按namespace读取候选Pod，查ownerReferences中是否有配置owner UID；不存在直接FAIL。允许请求使用原Pod spec/ownerReferences，后续构建wrong-owner、changed-env、extra-permission以及sonarInit脚本变更的探测。

完整旧脚本在每个成功父样本中实际构建38个dry-run请求，这些请求仅被VM记录，**不会发送**。parent-differential.json保存原构造的request/resource/owner/env/volume字段及对应结果分类，原始输入和exception定义不变。已有3个合法exception在完整父正例中仍为允许；wrong owner/owner缺失、合法请求被拒绝、无效owner/env/script/extra变体反被允许、错误策略拒绝信息均有失败对照。

没有重写Kyverno CEL或推导某个Pod应该allow/deny。冻结观察的allowed/denied始终来自输入，adapter只核实原Gate期待与所观察结果的一致性。

**原Gate边界也被保留**：负探测只要求拒绝信息包含devsecops-workload-contract或devsecops-production-baseline，不精确要求特定rule。因而“同一策略其他rule导致拒绝”在旧Gate中仍是自检PASS，新adapter也必须PASS；该样本显式记录，不误称已实现逐rule绑定。namespace查询和UID查找之外，原parent没有独立重验任意owner字段。没有新增exception expiry规则，当前实现无该语义，过期分支NOT_APPLICABLE。

## 3. WARN聚合

原Gate不是FAIL>WARN>PASS的通用聚合器：

- RBAC、对齐、预期准入/exception检查任一失败，父阶段FAIL并短路；
- workloadAudit逐资源生成mode=WARN及原findings，不据此更改最终evidence.status=success；
- 所有阻断检查通过，即使workloadAudit有多项WARN，父Gate仍PASS；
- 执行/解析/必需读取/报告写入失败仍FAIL，不被WARN掩盖。

覆盖PASS+WARN、WARN+WARN、RBAC FAIL+WARN、准入FAIL+WARN、合法exception+WARN。成功父样本还逐项比较旧脚本写入的workloadAudit与新输出，mode和findings完整相等。新audit helper从原inventory代码逐字冻结，只做原有审计映射，不充当admission engine。没有把WARN发现改为PASS发现。

## 4. Execution/error

覆盖控制器不可用、两项CRD读取被拒/查询失败、角色规则丢失/缺字段、GitOps Degraded/OutOfSync/缺健康字段、配置/源码读失败、RBAC和admission报告写失败、准入transport error、owner读取失败/JSON损坏/metadata缺失、容器/脚本volume缺失、workload读取失败/JSON损坏/缺模板/畸形volumes，以及零exit但带error的读取。

原脚本对这些实际观察抛错，adapter保持FAIL。未执行或未提供完整父证据返回NOT_CONFIGURED、decision=null，绝不PASS；不能把它描述成已运行的Gate失败。

## 5–8. 完整差分计数

- 新增完整父Gate differential：**49**。
- 总完整父Gate differential：**49**（此前子契约不计入）。
- matched **49** / mismatched **0**。
- 5个PASS/PASS、44个FAIL/FAIL。
- 分类：全部为受控完整父fixture；含38项历史准入响应、已有真实RBAC观察，不是49次生产执行。
- 本轮测试50项（另1项缺证据测试）；全部Policy tests **186/186 PASS**。

首次VM测试遗漏structuredClone导致5个预期成功fixture失败，初始日志保留。仅补齐VM运行环境后重新通过，未更改旧Gate判定或预期结果以消除失败。

## 9–13. 不变性、状态与停止

每个样本均比较evaluation前后的完整raw JSON，校验policy/rule/reason/resource/owner/exception/RBAC/GitOps/alignment输入不变。所有成功样本对workloadAudit逐项相等验证；输出的decision metadata独立追加。原Gate与policy、exception、实际Summary文件SHA同冻结清单一致。

目前没有未覆盖而已知会影响本轮**冻结父逻辑兼容证明**的结构性分支。仅缺自然历史父阶段故障的完整原始记录，保留DEFERRED_REAL_NEGATIVE_EVIDENCE；按用户最新准则，不因没有自然事故否认已完成的受控全代码路径对照。不能将此结论扩大为所有可能输入的形式化证明、生产实时健康或原策略不存在漏洞。

Kyverno/RBAC可离开本次compatibility阶段；**本轮仍不启动下一来源或Summary integration**。旧报告NOT_TESTED结论作为历史保留，由本报告和kyverno-parent/acceptance.json在限定验证范围内更新。

## 不可遗漏的全局阻塞

SOPS/age = NOT_TESTED / ENVIRONMENT_BLOCKED。

Requires disposable isolated Kubernetes environment for real controlled positive/negative execution and differential proof.

它继续阻止最终Security Manager portability成功声明。本轮未处理SOPS或其他来源。

## 文件

实现：infra/security/policy/kyverno-parent.mjs、kyverno-workload-audit.mjs、versions/kyverno-parent-baseline-v1.json；Engine新增父Gate入口。

证据：evidence/2026-11-01/kyverno-parent/parent-differential.json、acceptance.json、frozen-source-proof.json、tests-complete.log、all-policy-tests-final.log。
