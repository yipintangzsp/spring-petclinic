# Falco baseline与final生产Gate兼容性

Falco baseline/final = **VERIFIED**，范围限当前冻结源码baseline-v1/standard的完整阶段决策兼容。不是生产攻击测试、当前sensor健康认证或全量检测能力证明。未修改规则、部署、原Gate、权限、Summary或业务发布，无生产操作。

## 1–6 实际实现和判定事实

生产adapter的Falco Baseline执行 `runtime/health.mjs baseline`；Falco Final执行同文件默认check模式。原分类来自runtime/health-contract.mjs与event-policy.mjs。两阶段分开保留，不合并成一个“进程运行”判断。

共同前置：原outer Lease；isolated-sensor-proof的ruleset与cleanup证明；falco manifest摘要；DaemonSet desired整数且>=1、ready=desired；唯一未删除sensor Pod、devops节点、固定ARM64镜像及ruleset标签；当前container/node boot身份。查询来源是原kubectl logs和Pod/node数据，最后请求sensor /healthz；本轮不调用Loki或其他查询出口。

Baseline校验已知非负restart数、Ready/runningSince，启动至少5分钟、boot/container身份存在。priorExit不干净或未知可产生历史WARN，不能据此单独FAIL。通过后保存source/build绑定的baseline。

Final必须存在本构建baseline，source/build一致；Pod UID、node boot、container ID、runningSince、image、restarts全部不变且Ready。历史restart计数不被抹零，新restart或替换即FAIL。

历史driver诊断baseline读取最近10分钟、final从baseline capturedAt起，tail500；历史fatal仅console.warn。当前日志采样固定15秒，tail1000；driver/fatal实时检测失败可直接FAIL。

事件事实由Falco提供，旧纯policy只确认其中当前可验证高风险行为：规则Sensitive Read且显式reader/open系统调用成功读/etc/shadow；规则Sensitive Write且成功写原关键系统路径。它还要求当前业务namespace、node、Pod UID/container匹配、Ready、启动时间有效。原路径归一化与范围、读进程集合不变。

时间过期/窗口外、隔离测试、业务范围外、身份不确认、被EROFS/EACCES阻止、普通rule/路径、重复事件均保留原warning分类。priority本身不构成FAIL，也没有新增severity映射。

第一次窗口同一候选>=2独立事件时才等待16秒、读取第二段15秒窗口。两个不重叠窗口中相同Pod UID/container/process/path/reason各>=2次，才是持续确认行为FAIL；一次候选、短暂重复或跨process变化不满足。当前driver fatal与当前健康不佳独立FAIL，不能被事件WARN掩盖。

## 7 Adapter及Oracle

新增falco-parent.mjs，Engine分别提供falco-baseline/falco-final入口，模式错配显式POLICY_ERROR。版本文件冻结原health/event/health-contract摘要；源码变化需重新验证，不默用旧基线。未修改生产Manager。

旧Oracle在无I/O VM中执行完整未修改health.mjs，两模式分别运行；kubectl/files/fetch/clock/sleep只提供冻结观察，无真实等待、读日志、HTTP或危险行为。新adapter消费同一观察并复用原event/health纯policy，不重新实现Falco检测。

成功样本逐项比较原始liveChecks、driver diagnostics、historicalWarning和完整runtimeAssessment；所有样本比较old/standard决策及完整raw输入不变。原有13个Falco子契约样本和其他来源证据保留，不重复计入完整阶段数量。

## 8–17 样本、故障与计数

历史依据2份：已有Jenkins270 runtime-baseline/runtime-health归档。受控fixture使用其sensor身份，其他实时Pod/命令响应/事件窗口由冻结合成输入构造，**106例全部为CONTROLLED_COMPLETE_STAGE_WITH_HISTORICAL_SENSOR_IDENTITY**；不是106次生产执行、真实攻击或历史故障。新生产危险活动/命令0。

| 项目 | 数量 |
| --- | ---: |
| baseline完整差分 | 52 |
| final完整差分 | 54 |
| 总匹配/不匹配 | 106 / 0 |
| old decision PASS / FAIL | 37 / 69 |
| standard PASS / FAIL | 37 / 69 |
| 持续事件失败样本 | 4 |
| 当前fatal/第二窗口fatal失败样本 | 4 |
| 执行与健康错误分组 | 46 |
| 缺证据单独测试（不计差分） | 1 |

执行故障包括Lease、proof/lock/manifest、DS/Pod缺失或不可用、错误节点/镜像/ruleset、Ready失败、日志/工作负载查询、JSON损坏、health HTTP/query、source/目录/报告写入。另有baseline近期启动/身份缺失、restart异常、baseline写失败，以及final丢baseline、foreign source/build、new restart/container/boot/start变化等独立分支。成功报告构造依赖proof.cases，缺失导致原序列化失败，新引擎也FAIL。

重要原有边界：

- 原logs命令退出非零才抛错，并非所有stderr/error字段单独失败；不额外设计新transport Gate。
- 成功查询的空日志并不自动FAIL；畸形JSON若没有命中driver fatal，记录malformedJsonLines但原Gate不阻断，adapter保持该行为。
- Falco事件内容写出“fatal error loading BPF”不等于driver operational fatal；原diagnostics排除带rule的事件文本。
- 仅priority升至Critical、未知rule、普通文件、旧事件都不构成新增FAIL。
- 普通warning可与整个阶段PASS共存；新metadata保留原warning map，未将WARNING事件改成安全PASS。

## 18–22 不变性、证据边界与状态

raw event的rule/priority/time/process/user/container/workload字段、健康/query/source均前后不变；没有伪造缺失priority或severity。原manifest、rules、health/event代码、proof以及实际Summary摘要与冻结清单一致。

完整父阶段已知判定分支有受控冻结对照，本轮无剩余结构性standard兼容blocker。自然生产故障的完整真实输入仍可作为DEFERRED_REAL_NEGATIVE_EVIDENCE补证，但不是否认已完成的全旧代码受控对照。不能将本次结论推广为当前sensor实时健康、连续/云节点覆盖、所有系统调用检测或无日志损失。

最终Falco baseline/final **VERIFIED**，可离开compatibility阶段。全部Policy tests **408/408 PASS**（此前301+本轮107）。本轮停止，不开始Cosign、Summary、Router或其他来源。

全局保留：SOPS/age=NOT_TESTED/ENVIRONMENT_BLOCKED；Sonar真实负例=DEFERRED_REAL_NEGATIVE_EVIDENCE，最终portability未获准声明。

证据目录：evidence/2026-11-01/falco-parent，acceptance.json为本轮结论；differential.json逐例记录；historical-receipts.json保存已有脱敏历史依据；source-integrity.json为源码不变性；all-policy-tests-final.log记录408/408。
