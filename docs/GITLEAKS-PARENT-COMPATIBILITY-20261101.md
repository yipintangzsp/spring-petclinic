# Gitleaks 完整生产父阶段兼容性（2026-11-01）

**Gitleaks = VERIFIED**，范围仅为当前冻结生产父命令及所选原 Security Manager 聚合逻辑与 Policy Engine **baseline-v1 / standard** 的兼容性。**127/127 MATCH，drift=0；old / standard 均为 PASS15 / FAIL112。**

这不是新生产扫描、在线 Gitleaks/集群健康认证或完整 generic Gitleaks portability 认证。全部新父阶段输入是可丢弃的合成数据，实际执行完整原生产代码，但其文件、子进程、socket、Kubernetes 操作均由受控替身提供，证据分类是 **CONTROLLED_REPLAY**，不冒充历史事故或 REAL_CONTROLLED_EXECUTION。

本轮新测试132/132 PASS；已有分类器8项测试在临时工作目录中执行原测试文件并通过，其中原7份冻结差分记录逐项相同，未覆盖原证据。本轮测试执行共140/140 PASS；既有其他来源没有重跑。累计口径2005=1873+132，已有8项重跑不重复累加，不声称全量重跑2005。

## 1–3：生产入口、调用和 prerequisite

- `Jenkinsfile` 的 `DevSecOps Source & Admission` 中直接 `sh 'node infra/security/source-gate.mjs'`。该联合阶段还调用其他 Gate，本轮不把 Gitleaks 证明扩大为整个联合阶段。
- `Jenkinsfile.security-audit` 调用原 `securityManager(adapter:'petclinic',mode:'enforce')`；`resources/security-manager/petclinic-adapter.json` 的 `Secret Source` 模块执行同一命令。
- 当前生产父实现是 `infra/security/source-gate.mjs`；还读取 `tools-lock.json`、`reviewed-false-positives.json`，并调用原 `synthetic-credential.mjs` 创建一次性自测内容。
- **不导入共享 `scanner-runtime.mjs`。** 生产脚本内有自己的 run/k/read、Lease、Pod、隔离探测和 finally。共享 runtime 的工具 manifest/hash gate 不属于这条生产命令，不能凭“应该存在”给本轮新增规则。
- try之前：创建 `.devsecops`、读取固定 Gitleaks image配置、读取外层 `platform-heavy` Lease并核对当前 holder、`git rev-parse HEAD`。不存在单独获取嵌套锁，也没有单独的 Gitleaks version/二进制预检查。
- 创建 scanner Pod、Ready等待、可信 Jenkins Pod IP、canary基线、`nc -z`能力与连续网络拒绝、ServiceAccount token缺失、UID65532、只读根文件系统、imageID digest均按原代码验证后才转移源码。

四层明确分开：**prerequisite → scanner execution → 原始report / 既有分类事实 → 父Gate进程及Manager聚合**。scanner命令成功不等于安全PASS。

## 4–6：源码、调用和 exit-code 语义

源码来自当前checkout的 `git archive --format=tar HEAD`，128MiB上限，通过tar输入Pod `/work/source`；没有扫描开发机目录或读取真实凭据。生产命令没有项目可配置的sourceDir参数。

三次实际调用形式均是：

```text
gitleaks dir <path> --redact=100 --no-banner --log-level error --report-format json --report-path <file>
```

分别扫描 `/work/fixture`、`/work/clean`、`/work/source`，报告为 `/work/positive.json`、`/work/clean.json`、`/work/source.json`。没有显式 `--config`；不依据外部文档推断工具行为。

| 观察 | 现有父Gate语义 |
| --- | --- |
| scanner exit0或exit1 | 都是run允许的执行结果，仍要解析报告和分类 |
| positive fixture | 必须exit1且包含github-pat，否则FAIL |
| clean fixture | 必须exit0且无Finding，否则FAIL |
| source exit1 + 已审查Finding | 可以PASS |
| source exit1 + 空Finding数组 | 原代码可以PASS，本轮不改变 |
| source exit0 + 未接受Finding | FAIL，不能拿执行成功覆盖Finding |
| exit2/127、signal/null、spawn error、timeout | 原helper抛错，父Gate FAIL |
| 原Manager enforce接收exit10 | failed / FAIL，不能变WARN |

Ready请求、scanner exec、delete分别保留190s、90s、55s调用预算；外层Jenkins联合stage原有10分钟预算未改。测试用ETIMEDOUT观察验证已有错误路径，不运行真实长时等待。

## 7：报告解析与现有分类器

原脚本执行 `JSON.parse(String(cat.stdout)||'[]')`，再把原始Finding投影为rule/file/line/fingerprint。源扫描的原始native报告另外写入 `.devsecops/gitleaks-native.json`，最终父报告写入 `.devsecops/source-gate.json`。

- 缺报告是cat失败，不等同于空数组。
- source空bytes按原代码转为空数组；空白、损坏JSON、null/object等按实际执行结果失败。
- review JSON解析失败按现有异常处理；但**零Finding时循环不访问review entries**，即使entries=null仍可能PASS。不能在抽取adapter时增加新FAIL。
- 原审查循环仍按 `/work/source/` 前缀、路径逃逸拒绝、精确源行SHA、rule/path匹配决定接受或阻断。
- 新父adapter调用未修改的 `gitleaksEvidence` 处理有Finding的完整证据，不实现第二套Finding分类器。原Finding、原native metadata、位置、退出码、prerequisite观察和报告bytes均单独保留，不补造severity。

## 8：父聚合、错误和 cleanup

直接Jenkins入口消费原Node进程退出结果。原Security Manager在本轮被真实本地Groovy执行，但资源计划仅选择Gitleaks、Jenkins DSL为inert替身，保留module stage、credentials边界、shell返回、结果写入、archive和异常传播；不执行其他来源、实际Summary脚本或Jenkins CPS。

父脚本中有明确cleanup契约，**不是NOT_APPLICABLE**：finally关闭canary；存在uid时读取Pod核对UID、正常delete并等待、读回确认消失。替换UID、读回失败、删除失败、仍存在、canary close错误、最终report写入失败均保留FAIL。没有实际删除任何Pod。

原代码在created UID缺失时跳过cleanup；UID检查后按名称删除，并未使用原子UID删除前置条件。这里只忠实兼容，不修补这些行为。node API TCP可达只记录，memory.peak非数字变null，imageID仅按既有substring digest检查，均没有额外加严。

## 9–18：完整样本与执行边界

| 证据 / 分支 | 数量 | 范围 |
| --- | ---: | --- |
| 原classifier-only差分 | 7 | 保留且独立复核，不计完整parent样本 |
| 完整原脚本重放 | 108 | 原source-gate完整body，只有import替换为测试依赖 |
| 原Manager所选父聚合重放 | 19 | 原Groovy入口，inert Jenkins DSL |
| 完整parent差分合计 | **127** | 全部CONTROLLED_REPLAY，输入均synthetic/disposable |
| REAL_HISTORICAL完整parent | **0** | 有界本地文件名搜索未找到完整source-gate归档；没有拿概览success补造完整事实 |
| 新增独立契约检查 | 5 | 缺证、level/raw不变、原7样本保留、缺native、非决策状态；不是完整parent样本 |
| prerequisite直接分支 | 8 | holder、lock、revision等；另有isolation10、tool-unavailable6、image identity2 |
| execution error | 24 | 普通外部操作18 + scanner异常退出6 |
| timeout | 5 | scanner三处、Ready、canary基线 |
| missing report | 3 | positive/clean/source各1 |
| malformed report | 11 | JSON/shape/空白/review；其中未使用review字段保留原PASS |
| report read | 3 | 三报告读取失败 |
| IO/write | 6 | mkdir/lock/review读取、初始/最终父报告、native写入 |
| cleanup | 7 | 包括替换、删除、读回、残留及组合错误 |
| parent aggregation | 19 | 原Manager返回码、配置边界、DSL错误 |

上述类别是fixture的主标签，完整不重叠分支表见 `acceptance.json`；每个fixture还保留其全部实际操作轨迹。没有把127个合成输入称为127次真实Gitleaks执行。SYNTHETIC_UNIT_ONLY的原7个classifier样本及5个新增契约检查也没有提升为历史生产证据。

## 19–22：差分和不变性

| Decision | Existing parent | baseline-v1 / standard |
| --- | ---: | ---: |
| PASS | 15 | 15 |
| FAIL | 112 | 112 |
| WARN | 0 | 0 |

**MATCH127 / MISMATCH0；raw facts preserved = YES。**

独立collector只运行完整原Gate收集外部执行事实；Policy不导入collector、VM或oracle，不接受oldDecision输入。父adapter消费原process/Manager执行结果，成功路径必须保留native、父报告和既有classifier事实；缺证返回NOT_TESTED/null。原scanner exit1与原Node父进程非零是不同层级，证据保留两者。

127份落盘fixture全部重新读取：raw SHA127/127、decisions127/127、input SHA108/108（19份wrapper另存原输入与执行事实）；所有rawEvidence深比较、前后序列化相等。49个声明的I/O/命令故障注入均确认实际到达；没有靠未执行的fixture名称声称覆盖。

原7个classifier样本在临时目录运行原测试后与原件完全相同。2613份受保护既有文件中2612份未变；唯一允许变化是Policy `engine.mjs` 的两行追加：import和Gitleaks stage分派。移除两行可恢复其修改前完整SHA。原Gitleaks分类器、source Gate、Jenkins、Manager、发布、actual Summary、所有旧证据和最终盘点文件未改。

受控fixture的native Secret字段全为`[REDACTED]`；自测写入只有一次性非秘密marker，不调用真实凭据生成/导出。真实Secret读取0、真实Gitleaks执行0、实际kubectl/socket0、生产Summary写入0；临时classifier与Groovy输入目录已清理。fixture证据保留用于复核，不是生产临时资源残留。

## 23–26：剩余缺口、最终状态与停止

已无当前冻结生产父逻辑standard compatibility blocker。缺少历史完整CLI/prerequisite记录与自然失败事故，以及新在线工具/集群执行、Jenkins CPS认证，这些均未冒充完成。历史真实负例仍可后补，不能用它否认已完成的完整当前代码受控差分。

最终 **Gitleaks = VERIFIED，可退出本次compatibility阶段**。新132项测试、原classifier8项复核全部PASS，当前执行140/140，FAIL0；未重跑其他已验收adapter。

只写Gitleaks自己的 `coverage-delta.json`，不重建此前authoritative final audit，不修改其他来源状态，不接Summary、不改发布、不rollout、不开始下一来源。最终架构开关、生命周期、Router等仍留后续，不在本轮实现。

机器可读证据位于 `evidence/2026-11-01/gitleaks-parent/`：`production-inventory.json`、`differential.json`、`workflow-differential.json`、`acceptance.json`、`persisted-fixture-verification.json`、`fault-reachability.json`、`source-preservation.json`、`safety-check.json`、测试日志及fixture。
