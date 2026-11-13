# Sonar 真实历史负例补证与推进结论

本轮仅检索既有Sonar/Jenkins证据。没有扩大Sonar或Jenkins权限，没有修改known_hosts、Gate、Summary、发布逻辑；没有触发构建、扫描或rollout，也没有处理其他安全来源。

## 最终状态

| 项目 | 状态 |
| --- | --- |
| Sonar positive path | VERIFIED |
| Sonar negative real-evidence path | NOT_TESTED |
| 延后分类 | DEFERRED_REAL_NEGATIVE_EVIDENCE |
| Sonar adapter现有OK/ERROR映射实现 | 已实现；ERROR合成测试仅为单元测试 |
| 可否进入剩余production Gate adapter差分阶段 | 可以；此补证缺口不再作为结构性blocker |
| 全生产Gate/Policy Engine验收 | 未完成，不能据此宣称已验证 |

本次结论按用户最新指令，更新此前“必须先补齐Sonar真实负例才可推进”的停止规则。原报告与acceptance.json仍作为前轮历史记录保留；本轮最终结论在negative-evidence-disposition.json。

## 证据来源与实际检索范围

1. 使用原可信HostKeyAlias=192.168.1.58、目标192.168.64.11、StrictHostKeyChecking=yes，通过已有授权Jenkins身份只读检索petclinic-ci全部139个已完成FAILURE构建的日志和归档索引，读入31.84MiB，未达到200MiB读取预算。日志精确匹配Maven实际 `[ERROR] QUALITY GATE STATUS: FAILED`，排除shell grep命令里的关键词，不把Jenkins FAILURE等同于Sonar失败。
2. 找到真实Sonar失败日志的构建：#174、#173、#130、#122、#121、#120。检索结果原件historical-failure-search.json保留每个构建的状态、时间、真实Gate日志、task身份线索与候选artifact索引。
3. 对本地三个既有evidence根目录进行有界检查：1596个文本/JSON文件、100MiB，总预算或单文件大小导致1539项跳过，不声称整个磁盘穷尽检索。发现build-130-console.log中的真实失败记录，进一步定向检查sonar-findings-120/121/122/130.json及ci-173/174历史console；这些报告有ERROR条件，但没有明确task/analysis绑定。
4. 定向读取Jenkins #174的原始归档 `target/platform/sonar-quality.json`、实际失败日志、Sonar Action及artifact索引。该报告中Gate=ERROR，new_coverage=92.0/LT80/OK，new_duplicated_lines_density=0.0/GT3/OK，**new_violations=6/GT0/ERROR**。原失败日志明确FAILED；没有Sonar Action或report-task归档。只保留治理判定必要字段，没有抓取无关issue内容或任何凭据。
5. 上轮已经取得的授权CE task/精确analysisId正例证据继续有效。未重试已知403的analysis历史列表接口，未切换高权限身份或直读Sonar数据库以绕开该限制。

## 为什么仍不把负例标为VERIFIED

**有真实Sonar Gate失败观察，也有真实ERROR条件报告；缺少的是完整、可复核的任务绑定链。** #174的诊断报告来自project级查询，不含ceTaskId或analysisId，不能将当前task或仅时间相近的分析移接到历史失败上。

尚缺：

- 失败构建归档的report-task.txt或Sonar Action等直接task绑定；
- 该task映射到analysisId的记录；
- 以该analysisId返回的Quality Gate条件与原始旧Gate失败记录对应。

因此不能完成 `build→task→analysis→ERROR条件→旧FAIL→standard FAIL` 的真实负例差分，也没有凭空补ID或伪造analysis。用该真实但未绑定的#174报告直接调用现有adapter，返回`POLICY_ERROR: Sonar task/project/analysis binding incomplete or mismatched`，未不安全地接受它；原始归档内容保持不变。negative-artifact-validation.json保存校验摘要和拒绝结果。

## 已实现行为与下一步边界

现有adapter把Sonar权威OK映射PASS、ERROR映射FAIL，不重算threshold或metric。合成ERROR映射测试仍只用于独立单元测试，不冒充真实Sonar负例。已有正例实证和绑定防错行为保持VERIFIED；本轮5项Sonar独立测试全部通过，无scanner执行。

允许下一轮继续其余production Gate adapter盘点、冻结事实和差分；本轮不实际进入其他来源。Sonar负例作为**DEFERRED_REAL_NEGATIVE_EVIDENCE**保留，待未来自然失败留下完整合法归档，或已有完整历史证据可取得时补验。无需为此制造生产失败、改变Gate或申请更高权限。实际Summary接入仍受全生产Gate差分验收约束，不能借此跳过其他未覆盖来源。

本轮机器可读最终结果：`evidence/2026-11-01/sonar-policy/negative-evidence-disposition.json`。之前报告中的停止结论不再作为Sonar补证阻塞全部Policy Engine的依据。
