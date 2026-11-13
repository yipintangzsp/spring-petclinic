# 历史代理漂移证据恢复报告

结论：历史内容未恢复、writer=WEAK、语义UNKNOWN、checkpoint FAILED，14/16维持。未建立新基线。

本轮新增观察：主运行配置在只读检查中由6306变为6516字节，SHA=1d79621b4379e25e22722a227b33844fa1e8fe5bb796fef308a4eceab331c175，文件mtimeNs=1793707156171991692；主xray变为PID49177（本地19:59:16启动），GUI仍PID84672。变化原因UNKNOWN，本轮代理写入/重启命令均为0。这不是旧漂移解释；不能报告“代理运行态未变”。详见additional-observed-drift.json和current-post-additional-drift.json。

1. **trusted old config candidates found** — 150个小配置候选中无旧hash匹配；仅有一个2026-05-24 GUI备份及若干mtime较早的元数据/非代理文件，均不能作为本次旧运行配置。38份相关Codex会话检索到2个嵌入配置形状，均不匹配。174个归档候选中23个超过64MiB未打开，其余匹配16个小条目，无旧hash匹配；检索有界、不宣称全盘穷尽。逐候选路径/时间/hash/大小/来源/信任等级见config-candidates.json、additional-archive-search.json及session-evidence-search.json。

2. **selected pre-drift config** — 无。TRUSTED_PRE_DRIFT 内容 NOT_FOUND，LIKELY/UNTRUSTED未提升为权威。

3. **selected config timestamp** — 不适用。旧hash采样命令执行区间为2026-11-03T09:17:41.592–09:17:41.603Z；这是采样命令时间，不是文件写入时间。

4. **selected config hash** — 无选定内容。可信旧hash锚点仍为e3c322ce52c284ac77450781fce9ed71fe0711e52d62550d076059956e054452，6648 bytes；第一轮后值b702ff16eae6f27f0cc84e11e59565b1dded8e2c197778f0b888297266593d62，6306 bytes。

5. **old generated xray config evidence** — 可信旧内容未找到。现有configTest*.json属于测速生成物，不能代替主config.json；原始工具输出中的2个片段不匹配旧hash，未当作真实旧配置。

6. **previous active-listener evidence** — FOUND但PARTIAL：封存trivy-infra-repair/local-baseline.json记录旧主xray PID98992、127.0.0.1:10808、mixed/noauth/no accounts；proxy-before.json记录回环HTTP代理到registry返回401，LAN路径失败。它们绑定的更早配置hash为87a3d90fdd5a7ef3f531e8d9fe5358028f6b4ff67faf7a0c9ac6a7c36d56b846，不是缺失的e3c322旧内容，不能补填其上游/路由。

7. **drift timeline** — 可信旧hash采样命令09:17:41.592–.603Z；新hash采样09:21:43.956–09:21:44.755Z，形成保守观察界限。09:20:24.172875Z有GUI活动，主xray6529启动时间精确到09:20:28这一秒，新文件mtime=09:20:28.424101798Z，均仅时间相关。WindowClosing=09:17:08.6293Z在旧hash采样之前，不是本次写入证明。完整时间线见drift-timeline.json；不用mtime推定精确写入时刻。

8. **writer evidence** — 复查596条历史unified日志，筛选17条脱敏事件；应用窗口1条WindowClosing；没有目标文件的write/rename审计。进程父子链和官方7.20.4生成器路径仅说明候选能力。38份会话中74个相关工具命令引用不等于74次写入；写语法也可能只写evidence。shell历史未获得相关命令，不据此排除用户GUI动作。Codex日志未匹配目标路径/hash。

9. **writer attribution** — WEAK：候选GUI生成器；历史具体写入者、操作、触发动作仍UNKNOWN。没有CONFIRMED/STRONG级别的目标文件写入证据。

10. **GUI rewrite evidence** — WEAK。GUI活动 + 主子进程时间对齐 + 生成器已知行为；缺直接保存事件/旧字段变化，不能提升。历史订阅刷新未证明。

11. **raw config diff** — 无法执行真实旧→新raw diff：没有可信旧字节；只保留已封存旧/后hash、大小与mtime，不先归一化再猜变化。新parser的受控单元测试不是历史diff。

12. **semantic diff** — UNKNOWN。没有把未记录字段填成当前值。更早可信监听事实只覆盖部分语义；本轮又观察到额外运行配置变化，单独记录，不用它解释旧事件。

13. **listener old/current** — 更早可信记录127.0.0.1；最新动态主进程捕获仍监听127.0.0.1:10808及127.0.0.1:10812。10812旧基线未记录。T0旧采样器查询已退出PID6529，listenerCheckExit非0，不能作为当时监听证明；采用current-post-additional-drift.json的动态PID捕获。

14. **port old/current** — 10808 → 最新10808（监听及mixed inbound一致）；旧10812状态UNKNOWN，不宣称所有端口未变。

15. **LAN exposure old/current** — 更早10808回环监听且LAN代理请求失败；最新主进程仍回环，生成inbound未开放LAN。仅该入口事实，不能据此推导整个旧配置等价。

16. **routing old/current** — 旧完整模式/规则UNKNOWN；最新生成配置domainStrategy=AsIs，规则/配置摘要见current-post-additional-drift.json。没有把当前AsIs补写成历史模式。

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

27. **checkpoint reconsideration conditions** — A未满足（仍UNEXPLAINED）；B未满足（语义UNKNOWN）；C未满足（writer/source未证实）；D生产K8s/V1未改，但本地代理本轮另有观察到的变化，不能称整个proxy运行态未变。故不重新验收。

28. **RUNTIME_14_OF_16_CHECKPOINT** — FAILED，resume gate CLOSED；不重新生成checkpoint、不改hash规则、不实施语义豁免。

29. **clean-baseline reset required YES/NO** — YES：若要在历史不可恢复条件下继续推进，需要用户明确批准未来新基线epoch；本轮未批准、未执行。当前代理仍有变化，新基线也不能直接拿一次采样验收。

30. **exact next permitted action** — STOP。下一策略ESTABLISH_NEW_CLEAN_BASELINE，仅在明确批准后另轮进行：完整记录当前语义与变化来源、有限稳定观察、新checkpoint epoch/version、永久保留旧漂移及FAILED记录，不声称旧漂移安全。本轮不自动重置，也不改代理。

31. **runtime tests** — 143/143 PASS；隔离副本完整性负例11/11 PASS，合计154/154。本地测试不等于真实16源COMPLETE。

32. **candidate tests** — 40/40 PASS，一次性checkout已移除。初次completeness wrapper因旧输出目录已有而被exist_ok=False拦截，未写旧证据；仅新证据wrapper路径修正后通过，初始失败收据保留。

33. **Policy core** — 5/5 PASS。

34. **contract checks** — 10/10 PASS，Policy/Gate及checkpoint合同未改。

35. **Regression 147/147** — 147/147 PASS。检索/差分parser/时间线单元16/16 PASS，真实时间线一致性8/8 PASS。新取证工具初次缺失时间处理2项错误已在新工具内修正，原失败日志保留，不隐瞒、不改变生产实现。

36. **evidence integrity** — 旧FAILED checkpoint离线完整性12/12 PASS；11组910个旧封存文件全部hash一致（包括上一轮99文件）。本轮证据单独封存，不覆盖旧证据。

37. **source/hash preservation** — 455个冻结引用/229个唯一文件 + 77个实现文件全一致；Policy兼容计数2202不增加；无源码/发布/Gate/合同修改。

38. **production Jenkins state** — 生产petclinic-ci仍#270 SUCCESS，最新Summary hash未变；没有新build。两个任务303构建/4082归档条目未发现相关配置。Cosign验证#32/#33及任务定义hash未变。

39. **V1 state** — 仍active，Summary SHA=ec9ee51a06d4b9f61c6c0eaf50b374d1e25e6d3ca687908b7596d3a2c794f5d8；Summary V2未启用。Trivy存储/DB元数据和Dojo所选数据hash与上轮一致，未刷新、未改guard、未写Dojo。

40. **nodes state** — 最新只读复核aliyun-worker/devops/ucloud-worker均Ready；非连续HA演练结论。

41. **PetClinic state** — 最新复核3/3 Ready、3个Ready Endpoint、HTTP200，Argo Synced/Healthy，Deployment generation175/revision164及spec未变，Harbor7个Pod Ready。

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

边界：本轮392项本地测试/检查最终通过，不代表历史证据充足。Time Machine无机器备份目录；数据卷无APFS快照，系统卷只有OS更新快照，未挂载；UTM仅现有6个文件，无可用旧配置快照，不打开虚拟磁盘。23个大归档未展开；没有全盘穷尽搜索承诺。没有恢复、重启、修改代理/Gate/Trivy/Dojo，也未建立新checkpoint或COMPLETE。

[候选索引](config-candidates.json) · [会话证据](session-evidence-search.json) · [真实采样命令时间](capture-command-timing.json) · [时间线](drift-timeline.json) · [可信部分运行证据](trusted-pre-drift-runtime-evidence.json) · [生产保护核验](protected-state.json) · [停止收据](stop-receipt.json)。
