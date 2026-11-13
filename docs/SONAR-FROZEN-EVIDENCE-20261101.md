# Sonar Quality Gate frozen evidence · 2026-11-01

本轮停止状态：**完整正反例验收 NOT_TESTED，Sonar adapter 不标记整体 VERIFIED。** 已恢复可信管理通道，获得真实正例，完成局部差分；没有改变服务器 Gate/Jenkins Gate、Provenance opt-in、Dojo/Loki、实际Summary或发布逻辑，没有rollout或新常驻组件。

## 可信入口 VERIFIED

只读 ssh-keyscan 获取192.168.64.11三种公钥，逐项与当前用户 known_hosts 内原192.168.1.58可信记录核对，key type和完整公钥集合一致。

| 类型 | 当前与可信记录一致的 fingerprint |
| --- | --- |
| ED25519 | SHA256:nKfNkeCTSMNscgQKxptFwg14rsFjTYIWIjSfJ1hwG7s |
| ECDSA | SHA256:LzeaK4m5TwDSd5rOVHDg8UuR6UfFOY1dcoFdHJLKpVc |
| RSA | SHA256:Fk3Plj+p+nF3LLxBSsqiPI0F9PmuZiZPZ67k7/yzRME |

仓库既有 TERRAFORM-20261024、RABBITMQ-INTEGRATION-20261023 已记录该VM专用IP和旧SSH身份对应关系。随后沿用 HostKeyAlias=192.168.1.58、HostName=192.168.64.11、StrictHostKeyChecking=yes 成功连接 devops。known_hosts未添加、修改、删除，不需要改变已有信任记录。不能仅因keyscan返回值就建立信任；本次是与既有可信公钥匹配后连接。

## 已取得的真实 Sonar 正例

通过现有Jenkins credential ID sonar-token仅读取CE task与指定analysisId的project_status。凭据仅在服务端内存中使用，未输出/归档；没有创建或扩大权限。

- project key：petclinic。
- CE task：0241e049-d93c-469d-ba33-4a7efa5f67d2，SUCCESS。
- analysisId：45274956-df04-4d69-8869-62961b4d762e。
- 服务端 executedAt：2026-10-30T03:23:19Z。
- 使用 `/api/qualitygates/project_status?analysisId=45274956-df04-4d69-8869-62961b4d762e`，没有用当前project全局Gate冒充历史analysis。
- Gate status=OK，ignoredConditions=false。

| metric key | comparator | errorThreshold | actualValue | condition status |
| --- | --- | --- | --- | --- |
| new_coverage | LT | 80 | 92.0 | OK |
| new_duplicated_lines_density | GT | 3 | 0.0 | OK |
| new_violations | GT | 0 | 0 | OK |

对应旧生产接入方式是 Maven Sonar scanner 的 `sonar.qualitygate.wait=true`；没有发现该构建的SonarAnalysisAction，因此不能声称使用waitForQualityGate Jenkins step。Jenkins #270真实日志保存 `QUALITY GATE STATUS: PASSED`，新standard映射PASS一致。

绑定强度明确区分：CE task.componentKey/id/analysisId与请求路径严格对应，**task→analysis→Gate直接绑定 VERIFIED**。task ID来自现存工作区 target/sonar/report-task.txt；文件mtime03:23:13Z、task执行03:23:19Z均位于#270开始和该轮历史Summary记录03:27:41Z之间。#270为最近构建，原日志记录PASSED。**Jenkins #270关联有工作区与时间佐证，但没有逐构建归档report-task/SonarAction的直接绑定，后者 NOT_TESTED**。没有把时间相关性描述成强归档证明。

## 实现和测试

新增 `infra/security/policy/sonar-evidence.mjs`，仅将原服务端事实及绑定转换为标准输入。未知/缺失状态、condition细节缺失、task/project/analysisId不一致返回POLICY_ERROR，不推断PASS。Sonar的OK/ERROR由服务端权威结果直接映射PASS/FAIL，不按severity、strict或override重算其条件。没有更改原始指标、阈值或Finding。

Policy Engine只新增Sonar分支，不接Manager或实际Summary。单独Sonar测试5项通过；包含之前13项的轻量本地Policy测试合计18/18通过，没有执行扫描或发布。

真实OK样本差分与事实不变性已验证，证据positive-differential.json。ERROR分支仅进行了明确标记为**合成数据的本地映射测试**，该测试不构成真实失败analysis验收，不归档为生产失败样本。

## Blocker与停止点

只读补查 `/api/project_analyses/search?project=petclinic&ps=100` 返回 **HTTP403**。此前task和指定analysisId Gate请求均200并已保存，不笼统称整个Sonar不可读。准确拒绝端点与部分成功原始响应保存在sonar-analysis-evidence.json。403后未继续远端枚举、切换更高权限身份、修改项目Browse权限或Gate。

缺少：

1. 真实ERROR/FAILED分析的CE task、具体analysis Gate条件和对应旧Jenkins失败日志；不能把任意Jenkins FAILURE当成Sonar Gate失败。
2. 对应构建归档的report-task/task action，增强当前工作区时间关联为直接构建绑定。

最小下一步：由已有授权的只读Browse身份导出上述指定分析证据，或提供已有构建归档；不需要改变Sonar Gate、不需要构造新的生产失败分析、更不需要业务rollout。拿到后仅恢复Sonar差分，其他来源不动。

已有VERIFIED范围：host key信任核验；task/project/analysis Gate绑定及三项真实condition；正例PASS与原PASSED日志一致；adapter不重算且原始事实不变。真实失败差分NOT_TESTED、完整Sonar验收未完成，**不具备据此宣称全生产Gate差分已通过的条件**。独立后续工作应先补这两项证据，而非提前接security-summary.json。

所有本轮记录：`evidence/2026-11-01/sonar-policy/`。acceptance.json为本轮最终状态；host-trust.json、analysis-linkage.json分别说明验证边界，evidence-hashes.json索引JSON原件摘要。未覆盖前轮失败记录，也未删除历史证据。
