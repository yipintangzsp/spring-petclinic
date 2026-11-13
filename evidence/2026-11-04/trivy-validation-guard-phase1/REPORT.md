# Trivy validation-only guard / runtime 本轮验收

本轮停止在真实刷新之前。第一阶段实现通过，第二阶段空间/证据预检拒绝，第三阶段未进入。

本地提交 `4de943bb825b1fb74bf2052ee9e95ef4903920d9`，未 push。生产 guard/Gate/Summary/发布路径均未改动。

1. **Guard 实现与默认行为**：新增显式 production/validation-only facade；原生产 helper 及其 callers 逐字不变，默认不会启用 validation。生产公式仍为 capacity×15%+12GiB。

2. **Validation 硬下限与隔离**：采用既有 release stop line ceil(capacity×15%+8GiB)，不可由配置下调；再叠加完整刷新/扫描峰值、瞬时写入、清理和其他写入预算。独立私有临时 cache/tmp、固定 binary/artifact SHA、明确 manifest provider；无生产 proxy/credential/cache 回退。

3. **监控与异常清理**：100ms interval / 500ms sample timeout / 1000ms max gap；TERM/KILL 各1000ms。写入上界至少覆盖3600ms完整停止窗口。超时、压力、owner丢失、写入超额、采样失败/间隙和终态未知均失败。只终止自己的 process group；ownership 或进程停止无法证明则拒绝删除。

4. **第一阶段测试**：Darwin ARM64 73/73，Linux ARM64 Node20.19.2 73/73；每平台13个真实受控小型 Node 进程用例，使用明确 synthetic 预算，绝非 Trivy DB 执行。已有 Regression147/147、Runtime143/143、Policy core5/5、contract10/10。Linux 两轮临时树均确认清理；首次时序用例失败、修正和清理证据保留。沙箱本地监听 EPERM 首次失败也保留，获准本地监听后完整回归通过。

5. **冻结差分的独立阻塞**：当前 tree 的 Trivy frozen differential 共190项，仅2项通过、188项失败，全部受旧 source lock 与已验收 Helm Jenkinsfile 增量 SHA 冲突影响。12个其余冻结源 SHA 一致；本轮未新增该差异，未重写旧清单或绕过检查。此结果不是漏洞 FAIL，不代表旧 Gate 被改变，但不能宣称当前 runtime Policy 已兼容。

6. **当前空间证据**：devops nodeFs/imageFs 是同一 backing，不得相加。可用 43.1472 GiB，固定 validation hard floor 45.7787 GiB，尚未发生任何新写入即差 2.6314 GiB。生产 refresh 原要求 49.7787 GiB。Mac backing 可用约 22.0871 GiB，不是额外独立 guest 空间。

7. **预算证明**：刷新 old/new/压缩/解压/temp/扫描报告峰值、停止延迟内瞬时写入、失败清理和物理 COW 上界均未建立。没有用监控替代预算，没有以压缩包大小冒充展开峰值，没有新造 PROVEN 文件。因此 BLOCKED_DO_NOT_REFRESH，阈值未反复下调。

8. **真实执行与 Trivy 接线**：DB refresh0、native scan0、报告0；旧 Gate vs Policy真实差分、单次求值、resultDigest复用均 NOT_TESTED。仅新增未激活的 guard/隔离 refresh IO 实现，未接入当前 Jenkins runtime，不伪造 native report。

9. **Dojo 接线**：BLOCKED_BY_TRIVY，本轮0次；没有使用其他轮报告拼接 same-run 16/16。

10. **生产保护**：三个节点 Ready，PetClinic3/3、3个Ready Endpoint、HTTP200，Harbor7个Ready Pod。Jenkins生产#270 SUCCESS，V1 Summary SHA、SCM pin、Argo Application/Deployment/Service/Ingress UID及spec、生产digest未变；Argo Synced/Healthy。Trivy StatefulSet/环境配置hash/Pod/PVC/DB文件块数inodemtime未变（未重算整个DB SHA）。Helm证据及旧实验/资源审计封存均逐文件校验未变。

11. **权限/清理/变更范围**：只新增3个源码/测试/文档文件，本地提交；无 IAM 扩权、无 privileged Pod、无 Kubernetes资源创建、无 Jenkins任务或生产配置修改。Linux测试仅现有容器中的已知临时目录与普通子进程，两轮目录均已确认不存在。

12. **下一步允许操作**：STOP。资源审计仍 CLOSED。只有现有资源发生实质变化且完整的 reviewed artifact-bound peak/burst/cleanup/backing预算可验证满足固定底线，才可另行进行 validation-only预检。先通过明确版本化、审查过的源码兼容迁移解决 Helm raw SHA 与旧 Trivy lock 的冲突；保留历史清单，不绕过。条件全部满足后才允许同轮真实刷新/扫描→旧Gate/Policy/单次求值/digest验证→同轮Dojo。不得启用 SummaryV2/主架构，不推进 Helm迁移。

Evidence: phase1-acceptance.json, phase2-preflight-proof.json, frozen-source-diagnosis.json, production-preservation.json, linux-guard-tests.json, linux-initial-test-cleanup.json, all test logs.

```text
TRIVY_DUAL_MODE_GUARD=VERIFIED_IMPLEMENTATION_ONLY
PRODUCTION_GUARD=UNCHANGED
PHASE1_IMPLEMENTATION=VERIFIED
PHASE2_REAL_REFRESH=BLOCKED
CURRENT_TREE_FROZEN_TRIVY_DIFFERENTIAL=FAILED_SOURCE_IDENTITY
REAL_TRIVY_REFRESH_COUNT=0
REAL_TRIVY_SCAN_COUNT=0
TRIVY_STORAGE_ENVIRONMENT=ENVIRONMENT_BLOCKED
TRIVY_RUNTIME_FACT_CAPTURE=INCOMPLETE
TRIVY_REAL_GATE_POLICY_EQUIVALENCE=NOT_TESTED
TRIVY_REAL_POLICY_SINGLE_EVALUATION=NOT_TESTED
TRIVY_REAL_RESULT_DIGEST_REUSE=NOT_TESTED
DEFECTDOJO_RUNTIME_DEPENDENCY=BLOCKED_BY_TRIVY
DEFECTDOJO_SAME_RUN_VALIDATION=NOT_PERFORMED
DEFECTDOJO_RUNTIME_FACT_CAPTURE=INCOMPLETE
FINAL_WIRED_CAPABILITY=14/16
REAL_RUNTIME_FACT_CAPTURE=INCOMPLETE
REAL_POLICY_OWNER=INCOMPLETE
IMMUTABLE_ARTIFACT_RUNTIME=INCOMPLETE
SUMMARY_V2_MIGRATION=INCOMPLETE
PRODUCTION_HELM_DEPLOYMENT=NOT_ACTIVE
RELEASE_COUNT=0
ROLLOUT_COUNT=0
STATE=STOP
```

STOP。
