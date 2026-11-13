# Kyverno/RBAC frozen compatibility：本轮结果

**最终状态NOT_TESTED，停止，不进入Kubescape或Summary。** 49个已执行差分样本一致，不能提升为完整父生产Gate验证。

## 1–4. 实际生产实现、事实与exceptions

生产Security Manager adapter中Kyverno阶段依次执行 `infra/security/rbac-contract.mjs && infra/security/admission-gate.mjs`，调用顺序保留。

RBAC原Gate读取：控制器availableReplicas必须为1；当前既有SA对两类Kyverno CRD的get能力均yes；聚合角色必须存在apiextensions.k8s.io/customresourcedefinitions/get规则；platform-devsecops Argo应用Synced/Healthy。它不是通用RBAC风险算法，没有新增“广权限即失败”等判断。本轮仅对这些原条件做事实映射，没有改权限。

Admission原Gate将server dry-run返回视为权威。正常请求必须allowed；负探测必须denied且stderr指向devsecops-workload-contract或devsecops-production-baseline。命令error、意外允许、意外拒绝、无关网络错误均不能被视为正确策略拒绝。Policy Engine不读取Pod spec自行判断privileged/UID0等是否违规，也不解释CEL。

原探测包含mutable_image、hostNetwork/PID/IPC、hostPath、privileged/escalation、writable_root、drop ALL、资源限制、token、nonroot/seccomp，以及生产补充的UID0、危险capability、registry、init container等；本轮使用原35项归档的真实结果，不提交新准入请求或创建测试对象。

父Gate还对比live生产policy与源码rules的CEL/preconditions/match及Enforce，并检查exception工作负载是否存在。三种合法exception为falco、nodeExporter、sonarInit，按原配置绑定namespace、owner UID、容器、镜像、命令/env、mount等；不增加通配例外。原Gate额外探测错误owner、变更env、额外权限等必须被拒绝。

所有原exception配置与#270归档中的具体身份、allowed结果均保存于exception-model.json。adapter只搬运这些事实，不重新决定某个工作负载是否获得例外。

原workloadAudit将现有模板风险记录为WARN；这些发现不会直接把成功的准入测试阶段变成FAIL。父阶段最终status仍可success。adapter当前没有处理该汇总，不能假称WARN→PASS已验证。

## 5. Adapter

新增 `infra/security/policy/kyverno-evidence.mjs`，提供admissionEvidence、rbacEvidence，Policy Engine增加独立kyverno-admission/kyverno-rbac分支；没有接生产Manager。

Admission保留两个维度：admissionDisposition=ALLOWED/DENIED、原自检gateDecision=PASS/FAIL。**违规请求正确被拒绝时，自检Gate是PASS，但工作负载仍DENIED**。没有将违规工作负载标成合规。原始diagnostic、case、source和exception identity完整拷贝且不修改；归档没有独立rule字段时不从空气中补造。

缺必要报告返回NOT_CONFIGURED、decision=null；已观察到的执行故障FAIL。proof类失败不被audit/low/override降级。没有重新实现Kyverno或RBAC算法。

## 6–13. 样本与差分

| 类别 | 数量 | 来源/结论 |
| --- | ---: | --- |
| 历史准入探测 | 35 | #270 admission-gate.json；正常与预期拒绝均使旧自检Gate PASS，新standard也PASS |
| 合法exception | 3 | #270历史真实allowance，均PASS/PASS，身份保留 |
| 当前RBAC事实 | 1 | 严格SSH下只读取得deployment可用数、两项can-i、role.rules、应用健康；旧脚本在无I/O VM重放与新standard一致 |
| 合成准入异常 | 4 | 意外允许、意外拒绝、无关网络拒绝、transport error，均FAIL/FAIL |
| 合成RBAC样本 | 6 | 合法、控制器不可用、read拒绝、聚合规则缺失、OutOfSync、Degraded；合法PASS/PASS，其余FAIL/FAIL |
| 缺证据测试 | 1 | 不属于差分计数；不得PASS |

合计49个差分样本，全部一致；50项本轮测试通过。真实历史探测是HISTORICAL_ARCHIVE；当前RBAC事实是REAL_READ_ONLY_OBSERVATIONS；合成样本明确SYNTHETIC_UNIT_ONLY。历史正确拒绝不是旧Gate执行失败；没有取得真实RBAC Gate失败运行，不伪称已验证自然生产故障。

Oracle不是adapter自造期望：准入对照执行未改admission-gate.mjs中的probe函数；RBAC对照执行未改rbac-contract.mjs主体，在无I/O VM中只替换输入来源/报告写入。历史准入观察只有allowed/diagnostic，测试重放等价的zero/nonzero分支，不把反推的exit分类称为原始完整subprocess record。

## 14. 不变性与安全边界

每例验证raw facts JSON前后逐字相同；exception配置、policy/rule/reason/resource信息仅保留已有字段，未改写。原admission-gate、rbac-contract、production-baseline及production-exceptions四个文件SHA与冻结清单相同。

本轮只读访问现有控制器和角色元数据及已有can-i，没有读取Secret、改Role/Binding、扩权、apply或发起准入dry-run，没有生产对象变更。没有处理其他来源、SOPS或发布/Summary逻辑。

## 15–17. 缺口、最终状态及总测试

**最终Kyverno/RBAC=NOT_TESTED**，不是因为已执行差分出现漂移，而是尚未建立完整父阶段覆盖：

- live policy与源码精确匹配和Enforce条件还没有adapter及独立差分；
- exception对应工作负载owner与完整原请求、每条rule/资源身份绑定尚不齐全；历史配置加allowed结果不能代替原请求归档；
- workload WARN事实及父阶段聚合未适配；
- 原阶段外部读取/报告写入等执行故障尚未完整冻结。

这些仍影响standard compatibility，不能以“父流程曾SUCCESS”补齐；停止且不开始下一来源。最小下一步仍限本来源：先补policy对齐、exception请求/owner及WARN聚合的事实契约和冻结对照，不改规则或扩大权限。

全部Policy tests **136/136 PASS**；本轮新增差分49、测试50。没有宣称全生产Gate兼容，也未接实际security-summary.json。

## 必须保留的最终验收阻塞

SOPS/age = **NOT_TESTED / ENVIRONMENT_BLOCKED**。

Requires disposable isolated Kubernetes environment for real controlled positive/negative execution and differential proof.

该项阻止最终SECURITY_MANAGER_PORTABILITY_VERIFIED，但不阻止独立调查其他来源。本轮未触碰SOPS实现或证据。

证据目录：evidence/2026-11-01/kyverno-policy。acceptance.json记录49例计数与缺口，differential.json逐例记录old/standard、分类及不可变性；current-rbac-facts.json为真实只读事实；original-hashes.json为原文件完整性证明。
