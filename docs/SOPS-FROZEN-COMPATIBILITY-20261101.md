# SOPS/age production compatibility：本轮停止记录

最终状态 **NOT_TESTED**：本轮已实现完整观察输入的adapter，并完成20个旧生产Gate原代码对照；但还没有能重放的完整真实生产执行事实集。不能用单元测试通过替代真实证据验收，停止于SOPS，不进入其他来源或Summary。

## 1. 生产位置与事实清单

生产入口为resources/security-manager/petclinic-adapter.json的Encrypted Credentials阶段，执行infra/security/secrets-gate.mjs；Manager绑定platform-business-age文件凭据为BUSINESS_AGE_FILE。前置infra/security/scanner-runtime.mjs加载工具manifest并校验锁定SHA，requireLease核验原outer holder，verifyTools仅核验sops工具的文件SHA/符号链接。未执行其他来源的测试或修改它们的Gate。

原Gate依次读取：credential是否存在；.git-sha可读；四个既定加密源的SOPS decrypt退出及JSON；desired kind/namespace/name/data/stringData格式；live actual type/data与desired精确深比较；非readOnly时原apply调用是否成功；after UID/data与actual一致；两组已有权限检查的yes/no；finally写报告是否成功。最后一个Secret虽然属于验证器拉取凭据，相关权限只是SOPS原Gate自身的检查，本轮没有实现或修改独立Kyverno/RBAC adapter。

**PASS**：上述检查全部成功。**WARN不存在**。任一步抛异常导致FAIL，未被audit/low/override降级。原脚本不显式读取或独立判定recipient/key/metadata；这些由实际SOPS decrypt操作处理，adapter没有新增recipient白名单，也不重实现SOPS或age。原Gate没有独立age命令/输出，不能声称冻结了不存在的age stdout。

失败分类：scope/type/data/UID/权限边界属于validation failure；manifest/tool完整性属于validation prerequisite；Lease、外部命令/读取/apply/报告写入失败属于execution error；BUSINESS_AGE_FILE缺失属于missing credential；已知Gate失败保留FAIL，缺少重放观察本身则NOT_CONFIGURED且decision=null，绝不PASS。原Gate没有独立missing-capability返回值，不为它发明PASS/跳过语义。

## 2. Secret handling与cleanup

原Gate保持解密结果和Secret值只在内存，apply通过stdin；不将明文写入工作区或报告，比较防止旧密文覆盖已变化live值。finally只写脱敏报告；没有独立清理临时key/decrypted-file的代码。因此cleanup failure是NOT_APPLICABLE，不新造cleanup Gate。finally写入失败是execution error，并已测试；不把它混成cleanup成功或失败。

新adapter只接受内存观察，输出比较结果、failureKind和decision metadata，不返回原解密stdout/data、凭据路径或stderr；不发明severity。生产真实Secret从未读取或归档；测试全部用明确SYNTHETIC_ONLY数据。

## 3. 实现和差分

新增infra/security/policy/sops-evidence.mjs，分离sopsFacts与sopsDecision；Policy Engine只增加sops调用分支，baseline-v1/standard下原FAIL始终FAIL。没有接Manager或实际security-summary.json，没有修改原生产Gate。

测试不是以adapter产出expected：在无网络、无真实进程、无文件写入的VM中执行原secrets-gate.mjs的整个Gate主体，只把外部操作替换为冻结观察。SOPS/age加解密工具本身不在adapter内运行。共享runtime前置使用已观察的manifest/Lease/tool校验结果，没有声称重验真实主机二进制。

20个frozen sample均标记 **SYNTHETIC_UNIT_ONLY**：

| 分组 | 样本 | old / standard |
| --- | --- | --- |
| 成功 | readOnly成功、原apply分支成功 | PASS / PASS，各1 |
| validation | JSON损坏、scope错误、data变化、type变化、UID变化、额外权限、必要读取被拒、验证器越界权限 | FAIL / FAIL，各1 |
| execution/prerequisite | decrypt非零、live读失败、after读失败、apply失败、缺credential、Lease失败、工具校验失败、manifest失败、source读取失败、最终报告写失败 | FAIL / FAIL，各1 |

另1项测试验证缺观察不PASS。原始输入/原SOPS stdout前后逐字保持，输出不含SYNTHETIC_ONLY数据；没有修改任何原raw状态。没有独立age输出可供测试，也没有伪造一个。

最初测试运行暴露VM宿主/客体对象prototype比较和权限stub索引问题，导致两个成功样本错误失败；测试隔离中修正同realm对象解析及参数定位后，21/21通过。初始失败日志保留，生产判断及Gate未改。

## 4. 真实证据与缺口

真实positive receipt **1份**：已有Jenkins270 secrets-gate.json，记录四项valuesPreserved/encryptedSource、UID及权限结果，status=success；对应源码9a78cc89f22fa98fb1ffcc43e2ae279299471793的secrets-gate与当前SHA相同。源完整性证明见source-integrity.json。

但该报告没有保存完整前置工具/Lease调用结果、原始decrypt返回、精确pre/post比较观察；不能把status=success补成不存在的原始记录，也不能为重放读取当前生产Secret并冒充历史。完整真实positive replay **0份**，真实negative **0份**。真实负例单列DEFERRED_REAL_NEGATIVE_EVIDENCE，20项合成对照没有升级为真实负例VERIFIED。

**blocker**：真实归档格式不足以重放完整生产观察链；adapter逻辑有完整的合成Gate-body对照，但尚不能认定required production evidence闭环。还缺独立共享runtime前置校验的完整差分证明，当前将其观察作为输入，不等于验证manifest/hash检测实现本身。

最小后续仍限SOPS：查找既有合法归档中更完整且脱敏的原始检查观察；若不存在，需另行规划如何在未来自然执行时取得不包含任何Secret值的比较/执行证明。不得为补证修改当前Gate、获取/归档明文、制造生产失败，或用合成数据填补历史。当前停止，不开始Kyverno/RBAC。

## 5. 最终计数与边界

- adapter implemented：YES（完整内存观察模式；不是当前生产流程已接入）。
- real positive receipts：1；complete real positive replay：0。
- real negative：0，DEFERRED_REAL_NEGATIVE_EVIDENCE。
- synthetic differential：20，全一致；其中10个execution/prerequisite/credential路径。
- cleanup samples：NOT_APPLICABLE；report-write error已计execution样本。
- 本轮SOPS tests：21/21；全部本地Policy tests：86/86 PASS。
- raw facts preserved：YES，真实Secret未采集。
- final SOPS status：NOT_TESTED；ready to leave phase：NO。
- 原Gate、加密源、recipient/key/metadata、实际Summary、发布逻辑与权限未变；无rollout/新服务。

证据目录：evidence/2026-11-01/sops-policy。acceptance.json记录最终状态，differential.json记录每例old/standard与failureKind。未更改其他来源的验收状态。
