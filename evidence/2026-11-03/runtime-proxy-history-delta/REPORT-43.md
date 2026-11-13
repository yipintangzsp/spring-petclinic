# 历史代理证据恢复：大归档补查与停止报告

本轮附件与上一轮字节相同，SHA256=5d6a8c85a11a7eb392635a3d36fe244fc5d28a084516e25a480181295c36a66d。没有获得基线reset授权。

原漂移：6648字节/e3c322… → 6306字节/b702ff…仍UNEXPLAINED。前轮另有6516字节/1d7962…及主core替换，本轮当前采样仍为1d79621b4379e25e22722a227b33844fa1e8fe5bb796fef308a4eceab331c175，6516字节；不追认原漂移安全，不建立新baseline。

1. **trusted old config candidates found** — 继承已封存150小配置候选、38会话、174归档及303构建/4082归档条目的检索结果。本轮仅补查23个此前因大小上限未打开的归档：9个未压缩TAR遍历至末尾，14个gzip到32MiB解压读取上限停止；新找到9个配置条目，旧hash匹配0。逐条路径/entry时间/hash/大小/信任等级见large-archive-results.json。14个gzip未全部遍历，不能声称全盘穷尽或不存在旧内容。

2. **selected pre-drift config** — 无。TRUSTED_PRE_DRIFT 内容 NOT_FOUND，LIKELY/UNTRUSTED未提升为权威。

3. **selected config timestamp** — 不适用。旧hash采样命令执行区间为2026-11-03T09:17:41.592–09:17:41.603Z；这是采样命令时间，不是文件写入时间。

4. **selected config hash** — 无选定内容。可信旧hash锚点仍为e3c322ce52c284ac77450781fce9ed71fe0711e52d62550d076059956e054452，6648 bytes；第一轮后值b702ff16eae6f27f0cc84e11e59565b1dded8e2c197778f0b888297266593d62，6306 bytes。

5. **old generated xray config evidence** — 仍未找到可信旧generated config内容；本轮新增9个归档配置条目均UNTRUSTED，不提升为pre-drift权威。历史具体主config路径及部分运行记录沿用前轮封存证据。

6. **previous active-listener evidence** — FOUND但PARTIAL：封存trivy-infra-repair/local-baseline.json记录旧主xray PID98992、127.0.0.1:10808、mixed/noauth/no accounts；proxy-before.json记录回环HTTP代理到registry返回401，LAN路径失败。它们绑定的更早配置hash为87a3d90fdd5a7ef3f531e8d9fe5358028f6b4ff67faf7a0c9ac6a7c36d56b846，不是缺失的e3c322旧内容，不能补填其上游/路由。

7. **drift timeline** — 可信旧hash采样命令09:17:41.592–.603Z；新hash采样09:21:43.956–09:21:44.755Z，形成保守观察界限。09:20:24.172875Z有GUI活动，主xray6529启动时间精确到09:20:28这一秒，新文件mtime=09:20:28.424101798Z，均仅时间相关。WindowClosing=09:17:08.6293Z在旧hash采样之前，不是本次写入证明。完整时间线见drift-timeline.json；不用mtime推定精确写入时刻。

8. **writer evidence** — 本轮没有新增文件写入审计、GUI保存/订阅刷新事件。前轮596历史日志及会话记录仍仅支持候选GUI=WEAK；没有因补查归档或后续运行态稳定提升writer归因。

9. **writer attribution** — WEAK：候选GUI生成器；历史具体写入者、操作、触发动作仍UNKNOWN。没有CONFIRMED/STRONG级别的目标文件写入证据。

10. **GUI rewrite evidence** — WEAK。GUI活动 + 主子进程时间对齐 + 生成器已知行为；缺直接保存事件/旧字段变化，不能提升。历史订阅刷新未证明。

11. **raw config diff** — 无法执行真实旧→新raw diff：没有可信旧字节；只保留已封存旧/后hash、大小与mtime，不先归一化再猜变化。新parser的受控单元测试不是历史diff。

12. **semantic diff** — UNKNOWN。未把历史未记录字段补成当前值。部分旧监听事实不足以证明完整语义；前轮额外的6516字节变化仍单独保留，本轮没有新增的历史解释或baseline。

13. **listener old/current** — 更早可信记录127.0.0.1:10808；本轮当前真实lsof仍见回环10808/10812，详见current-proxy-readonly.json。旧10812基线未知。不得拿之前查询失效PID6529的T0作为当时监听证明。

14. **port old/current** — 10808 → 最新10808（监听及mixed inbound一致）；旧10812状态UNKNOWN，不宣称所有端口未变。

15. **LAN exposure old/current** — 更早10808回环监听且LAN代理请求失败；最新主进程仍回环，生成inbound未开放LAN。仅该入口事实，不能据此推导整个旧配置等价。

16. **routing old/current** — 旧完整routing UNKNOWN；本轮生成配置domainStrategy=AsIs，摘要见current-proxy-readonly.json。不是旧→新等价证明。

17. **outbound identity old/current** — 旧上游/服务端身份UNKNOWN。当前只导出受保护的配置身份摘要、tag和协议，不导出服务器/凭据。旧/新身份等价无法证明。

18. **security flags old/current** — 更早mixed/noauth、accounts=false已记录；旧TLS/transport/DNS等其余开关UNKNOWN。最新公开字段及摘要见当前采样；未提供的security字段不猜测为安全或不安全。

19. **PROXY_SEMANTIC_DIFF** — UNKNOWN。

20. **TRUSTED_PRE_DRIFT_CONFIG** — NOT_FOUND。

21. **TRUSTED_PRE_DRIFT_RUNTIME_EVIDENCE** — FOUND，范围PARTIAL；不足以证明e3c322→b702ff的完整语义兼容。

22. **FILE_WRITER_ATTRIBUTION** — WEAK。

23. **V2RAYN_GUI_REWRITE_EVIDENCE** — WEAK。

24. **HISTORICAL_PROXY_DRIFT_EVIDENCE** — INSUFFICIENT。

25. **V2RAYN_DRIFT_CLASS** — UNEXPLAINED。新变化不追认旧漂移安全。

26. **PROXY_RUNTIME_SEMANTICS_CHANGED** — UNKNOWN，针对原历史漂移。

27. **checkpoint reconsideration conditions** — 历史A/B/C仍未满足：UNEXPLAINED、语义UNKNOWN、writer证据WEAK。本轮当前主配置SHA与前轮最新6516字节观察一致，但单点相同不证明稳定性或原漂移安全；不得重新验收checkpoint。

28. **RUNTIME_14_OF_16_CHECKPOINT** — FAILED，resume gate CLOSED；不重新生成checkpoint、不改hash规则、不实施语义豁免。

29. **clean-baseline reset required YES/NO** — YES（若历史无法恢复而要继续checkpoint）。本轮附件与前轮字节完全相同，仍明确禁止自动reset；未建立epoch/version。

30. **exact next permitted action** — STOP。已按声明边界结束历史恢复，不反复重扫。下一策略ESTABLISH_NEW_CLEAN_BASELINE须明确批准后另轮执行：记录当前完整语义/变化来源、有限稳定观察、新epoch/version、永久保留旧FAILED/UNEXPLAINED，禁止追认旧漂移安全。本轮不执行reset。

31. **runtime tests** — 本轮重跑runtime143/143 PASS，隔离completeness-negative11/11 PASS。

32. **candidate tests** — 本轮candidate40/40 PASS，一次性checkout已移除。

33. **Policy core** — 本轮Policy core5/5 PASS。

34. **contract checks** — 本轮contract10/10 PASS；未修改任何现有Gate或checkpoint hash合同。

35. **Regression 147/147** — 本轮Regression147/147 PASS；新归档读取边界测试8/8、检索/parser/时间线unit16/16、真实历史时间界限重核8/8均PASS；共400项本地测试/检查，不是新增Policy兼容样本计数。

36. **evidence integrity** — 本轮原FAILED checkpoint离线完整性12/12 PASS；12组1005个旧封存文件全部hash一致，含上一轮95文件。新证据独立封存，不覆盖旧结果。

37. **source/hash preservation** — 455冻结引用/229唯一文件、77实现文件全一致，兼容计数2202保持；无源码/生产Gate/发布/合同修改。

38. **production Jenkins state** — 新只读复核petclinic-ci仍#270 SUCCESS，没有新build；历史Jenkins归档检索沿用上轮封存记录，不宣称本轮新增归档。

39. **V1 state** — V1仍active，Summary SHA=ec9ee51a06d4b9f61c6c0eaf50b374d1e25e6d3ca687908b7596d3a2c794f5d8。Trivy存储/DB文件元数据及metadata.json hash、Dojo所选元数据与前轮一致；未重新计算完整DB内容SHA；未激活Summary V2。

40. **nodes state** — 本轮只读复核三个节点Ready；非连续HA演练结论。

41. **PetClinic state** — 本轮复核PetClinic3/3、3个Ready Endpoint、HTTP200，Argo Synced/Healthy及Deployment spec未变，Harbor7个Pod Ready。

42. **release count** — 0。

43. **rollout count** — 0。

## 最终裁决

```yaml
TRUSTED_PRE_DRIFT_CONFIG: NOT_FOUND
TRUSTED_PRE_DRIFT_RUNTIME_EVIDENCE: FOUND
FILE_WRITER_ATTRIBUTION: WEAK
V2RAYN_GUI_REWRITE_EVIDENCE: WEAK
PROXY_SEMANTIC_DIFF: UNKNOWN
HISTORICAL_PROXY_DRIFT_EVIDENCE: INSUFFICIENT
V2RAYN_DRIFT_CLASS: UNEXPLAINED
PROXY_RUNTIME_SEMANTICS_CHANGED: UNKNOWN
RUNTIME_14_OF_16_CHECKPOINT: FAILED
FINAL_WIRED_CAPABILITY: 14/16
REAL_RUNTIME_FACT_CAPTURE: INCOMPLETE
REAL_POLICY_OWNER: INCOMPLETE
IMMUTABLE_ARTIFACT_RUNTIME: INCOMPLETE
SUMMARY_V2_MIGRATION: INCOMPLETE
```

本轮是增量补查。前轮未重跑的历史日志/会话/旧运行事实均明确引用封存记录：[前轮完整报告](../runtime-proxy-history-recovery/REPORT-43.md)。新增[归档结果](large-archive-results.json)、[当前保护核验](protected-state.json)、[测试计数](test-counts.json)、[停止收据](stop-receipt.json)。
