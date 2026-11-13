# SOPS real controlled compatibility — 2026-11-02

```text
SOPS_COMPATIBILITY =
INCOMPLETE
```

没有执行 Gate 或 Policy case，没有兼容性 PASS/FAIL 判定，没有 DRIFT。失败发生在执行器 prerequisite，不能把 exit127 算成冻结 Gate 的 FAIL。

## 阻塞证据

`startup-node-prerequisite.json`：通过真实 MIN_RBAC_EXECUTOR guard 和原 observation harness，在既有 Linux/aarch64 镜像内实际执行 `node --version`，exit127、无 signal/timeout。镜像缺 Node，无法启动 `.mjs` Gate。宿主机的 Node 不提供 Linux SOPS 的原生执行能力。没有改工具锁、替换 SOPS 为 shim、运行 VM/mock Gate 或把先前 unit sample 当本轮真实 differential。

最小修复是补齐可追踪的 Linux Node 执行环境及同一 guard 下的 kubectl/真实逐调用观察接线，再以新建、单独记录的 fixture baseline 执行矩阵。已有 observation harness 能验证 Python sentinel/local object，不等于真实 Node Gate 调用链已经接好。

## 35 项最终报告

| # | 要求 | 结果 |
| --- | --- | --- |
| 1 | isolated identity | guard 验证固定 test cluster/server/CA/kube-system UID，实际 node arm64；无其他 context |
| 2 | min token | 真实 SA token 未过期且运行前剩余超过20分钟，SelfSubjectReview/SA UID/groups/ns UID通过；无重签发/无admin fallback |
| 3 | guard sanity | 5/5 PASS：正确、缺 profile、unknown profile、错误 config SHA、admin credential 混入 min |
| 4 | baseline drift | 无；23 对象完整 canonical hash/UID 及文件/工具/recipient 均与保存基线一致 |
| 5 | total matrix | 12 |
| 6 | applicable | 12，按已有冻结源码；不是执行通过 |
| 7 | NOT_APPLICABLE | 0 |
| 8 | old Gate executed | 0 |
| 9 | Policy executed | 0 |
| 10 | oldDecision counts | {}，没有把 bootstrap exit127 记 FAIL |
| 11 | policyDecision counts | {} |
| 12 | MATCH | 0 |
| 13 | DRIFT | 0 |
| 14 | first drift | 无；未达到可比较执行阶段 |
| 15 | prerequisite evidence | startup-node-prerequisite.json：真实 Linux Node 缺失 |
| 16 | abnormal exit | exit127，signal=null，timedOut=false，stdout/stderr只存metadata；无 Gate exit 证据 |
| 17 | UID continuity | NOT_RUN；未删除/重建 Secret 来制造样本 |
| 18 | value preservation | NOT_RUN；未修改 Secret 值 |
| 19 | Lease mismatch | NOT_RUN |
| 20 | RBAC denied | NOT_RUN；没有用 admin 替代负例路径 |
| 21 | tool missing | 仅执行器 Node 缺失 prerequisite；矩阵 TOOL_MISSING/SOPS case NOT_RUN |
| 22 | report write failure | NOT_RUN |
| 23 | raw fact preservation | 原观察器记录实际启动元数据；无解密 stdout、无构造 adapter raw 或 Policy decision |
| 24 | final restore | 没有 case mutation，无需恢复；cleanup前全部对象UID/ownership再确认，随后按Phase12清理 |
| 25 | evidence index | evidence-index.json 中所有引用存在且 hash匹配 |
| 26 | fixture cleanup | 23精确对象逐一UID-precondition删除、GET404确认；密文安全证据保留，两对private key/token/临时root已销毁；kind保留 |
| 27 | production API | 0 |
| 28 | production Secret/credential | 值提取/使用0；受保护配置仅字节hash对照，不把hash读取说成从未打开文件 |
| 29 | production age-key | 0 |
| 30 | production files changed | NO；3963个既有项目文件全未变 |
| 31 | Policy baseline changed | NO |
| 32 | Summary changed | NO |
| 33 | SOPS_COMPATIBILITY | INCOMPLETE |
| 34 | exact blocker | Linux executor缺Node及待接真实Gate逐调用观察，不能安全产出同次真实事实的差分证据 |
| 35 | next permitted action if VERIFIED | 不适用；本轮非VERIFIED。先修复上述执行环境和观察接线，再重建新fixture基线，不接Summary或其他结构性阻塞 |

## 清理范围

清理前重新验证每个对象的 cluster/UID/run ownership，先确认 namespace 中无外来 Pod/PVC/业务资源，只允许本run精确对象及控制器默认 SA/root CA ConfigMap。未 force delete、未移 finalizer、未删 kind/node/生产数据。namespace清理仅限本轮隔离 fixture。

原 fixture-instance 的 READY 是历史时点，不再代表 fixture 仍存在：按本轮清理授权，原临时 root 和对象已经删除。两个 age private key/token未归档；安全密文副本、public fingerprints、源码/工具hash和基线引用保留。

没有新增 Policy compatibility 样本，不改变既有累计 tests/coverage，不宣称负例兼容。STOP。
