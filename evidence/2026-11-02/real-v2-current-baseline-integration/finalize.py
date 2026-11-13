"""Record exact completed work and unimplemented integration, without promotion of unit proofs."""
from pathlib import Path
import hashlib,json,re
R=Path(__file__).resolve().parents[3];O=Path(__file__).resolve().parent
read=lambda p:json.loads(p.read_text())
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
def save(n,d):(O/n).write_text(json.dumps(d,ensure_ascii=False,indent=2)+'\n')
before=read(O/'before-sha256.json')
changed=[n for n,h in before.items() if not (R/n).is_file() or sha(R/n)!=h]
assert not changed,changed
v1=read(O/'V1_IDENTITY.json');active=read(O/'ACTIVE_V1_IDENTITY.json')
assert all(sha(O/'v1-tree'/n)==x['sha256'] for n,x in v1['files'].items())
assert all(sha(O/'active-v1-tree'/n)==x['sha256'] for n,x in active['files'].items() if x['exists'])
authority=R/'evidence/2026-11-02/summary-integration-readiness-recheck'
refs=read(authority/'source-integrity.json')['checks']
assert all(sha(R/x['path'])==x['expected'] for x in refs)
index_checks=read(authority/'index-integrity.json')['checks']
for x in index_checks:
    p=Path(x['path']);p=p if p.is_absolute() else R/p
    if x['directMatch']:assert sha(p)==x['expected']
    else:assert x['resolved'] and sha(R/x['archivedPath'])==x['expected'] and sha(p)==x['actual']
candidate=read(R/'infra/security/summary-v2/candidate-integrity-r2.json')
for version in candidate['versions'].values():
    assert all(sha(R/n)==h for n,h in version['files'].items())
assert candidate['compatibilityBaseline']['readinessSha256']==sha(authority/'readiness.json')
matrix=read(authority/'authoritative-source-matrix.json')['sources']
for row in matrix:assert sha(R/row['classifierAdapterPath'])==row['adapterSha256']
def tap(name,count):
    data=(O/name).read_text()
    stats={k:int(v) for k,v in re.findall(r'^(?:#|ℹ) (tests|pass|fail|cancelled|skipped|todo) (\d+)$',data,re.M)}
    assert stats['tests']==stats['pass']==count and all(stats[k]==0 for k in ['fail','cancelled','skipped','todo'])
    return {**stats,'log':name,'logSha256':sha(O/name),'exitStatus':0}
tests={'candidate':tap('rebased-candidate-tests.log',40),'originalRegression':tap('legacy-regression.log',147),'snapshotRollbackRegression':tap('rollback-regression.log',147),'policyCore':tap('policy-core.log',5)}
contract=read(O/'policy-contract.json');assert contract['ready'] and len(contract['checks'])==10 and all(x['status']=='VERIFIED' for x in contract['checks'])
falco=read(O/'falco-v2-rebase-preflight.json');assert falco['samples']==falco['match']==4 and falco['drift']==0
for x in falco['records']:
    assert x['oldGateDecision']==x['policyDecision']==x['artifactDecision']==x['summaryDecision']
    assert x['resultDigest']==x['gateResultDigest']==x['summaryResultDigest'] and x['rawUnchanged']
    assert all(n==1 for n in x['controlledEvaluationCounts'].values()) and x['realPipelineCountsObserved'] is False
    p=Path(x['artifactPath']);assert sha(p)==x['artifactDigest'] and p.stat().st_mode&0o777==0o400
reg=read(O/'regression-execution-policy.json');assert reg['MATCH']==reg['samples']==2 and reg['DRIFT']==0
workspace=read(O/'live-workspace-hashes.json');live=read(O/'live-jenkins-baseline.json')
main=next(x for x in workspace['workspaces'] if '@script/' not in x['workspace']['path'])
assert main['online'] and not main['files']['infra/security/policy/engine.mjs']['exists'] and not main['files']['infra/security/summary-v2/owner.mjs']['exists']
reports=read(O/'archived-native-observation-contract.json')
assert all(x['exists'] and x['status']=='success' and not all(x['requiredFieldsPresent'].values()) for x in reports['rows'])
source_ids=['sbom','regression','falco-baseline','kyverno','kubescape','gitleaks','sops','trivy','cosign','sonarqube','zap','falco-final','defectdojo','provenance','build-provenance','semgrep-command-audit']
save('runtime-source-coverage.json',{'canonicalSourceCount':16,'compatibilitySourceLabels':18,'alias':{'semgrep':'semgrep-command-audit'},'postScope':['security-approval-promotion'],'sources':[{'sourceId':s,'actualPipelineEvaluationCount':None,'actualPipelineResultIdentity':None,'actualRuntimeFactDigest':None,'evidenceStatus':'NOT_TESTED','reason':'No new non-release pipeline executed; runtime observation collection and non-test owner are not implemented/wired'} for s in source_ids],'countMeaning':'null is NOT_OBSERVED, not an invented zero or one','controlledCountsAreNotRuntimeCounts':True})
blockers=[
 {'id':'B1','kind':'IMPLEMENTATION_BLOCKER','capability':'real runtime fact capture','evidence':['archived-native-observation-contract.json','live-workspace-hashes.json'],'detail':'Six archived native-report schemas cover seven canonical stages but lack the complete frozen observations. Historical success reports cannot substitute for same-run prerequisite/IO/cleanup and observed Falco clocks. No production collectors were implemented in this iteration.','minimalFix':'Implement passive same-run observation capture against unchanged production Gate execution, preserving actual command/IO/clock/cleanup outcomes in memory and exporting only safe bound receipts. Do not invent missing observations.'},
 {'id':'B2','kind':'IMPLEMENTATION_BLOCKER','capability':'actual authoritative Policy owner / once proof','evidence':['ACTIVE_V1_IDENTITY.json','live-workspace-hashes.json'],'detail':'Actual Manager executes original module commands and helpers; its workspace contains no Policy Engine or V2 owner. Candidate createSourceOwner remains a single-process helper exercised by controlled tests, not a real pipeline owner.','minimalFix':'Wire one non-release pipeline owner to the real capture path; bind claims/results to the run, reject duplicate evaluations before Engine execution, and hand the same result identities to Gate/artifact/Summary.'},
 {'id':'B3','kind':'IMPLEMENTATION_BLOCKER','capability':'consumer migration / real artifact','evidence':['controlled-candidate-tests/candidate-summary-differential.json','rebased-candidate-tests.log'],'detail':'No real 16-source COMPLETE pre-approval artifact or Summary V2 was generated. Real Promotion/Regression dispatch remains V1; candidate guard tests do not install migrated consumers.','minimalFix':'After B1/B2, produce the immutable complete artifact and migrate non-release consumer validation with explicit version selection; run the complete real pipeline differential/anti-self-approval/mixed-version/rollback checks before declaring VERIFIED.'}
]
save('owner-trace.json',{'actualOwner':'NONE_FOR_POLICY_IN_REAL_PIPELINE','actualOrchestrator':'vars/securityManager.groovy call -> plan loop; securityProvenance/securityBuildProvenance helpers','activeManagerSha256':active['files']['vars/securityManager.groovy']['sha256'],'localManagerSha256':sha(R/'vars/securityManager.groovy'),'candidateHelper':'infra/security/summary-v2/owner.mjs:createSourceOwner.evaluateOnce','realWorkspace':main['workspace'],'actualOwnerWired':False,'realSingleEvaluationProof':'NOT_TESTED','newNonReleaseBuildExecuted':False,'unitOnlyOwnershipMustNotBePromoted':True})
save('source-preservation.json',{'protectedFiles':len(before),'changedPreexistingFiles':changed,'frozenSourceReferences':len(refs),'distinctFrozenSources':len({x['path'] for x in refs}),'sourceFailures':[],'priorEvidenceHashRefsRechecked':len(index_checks),'priorEvidenceUnresolved':0,'snapshotFiles':len(v1['files']),'activeSnapshotFiles':len(active['files']),'falcoAdapterSha256':sha(R/'infra/security/policy/falco-parent.mjs'),'falcoGateSha256':sha(R/'infra/security/runtime/health.mjs'),'policyEngineSha256':sha(R/'infra/security/policy/engine.mjs'),'policyBaselineSha256':sha(R/'infra/security/policy/versions/baseline-v1.json'),'activeV1IntegrityContractsChanged':False,'productionGateChanged':False,'summaryProducerChanged':False,'scannerAdapterSemanticsChanged':False,'onlyRepositoryAdditionOutsideEvidence':'infra/security/summary-v2/candidate-integrity-r2.json'})
save('test-disposition.json',{'tests':tests,'contractChecks':{'pass':10,'total':10},'falcoCandidatePreflight':{'match':4,'drift':0,'classification':falco['classification']},'localRegressionDifferential':{'match':2,'drift':0,'classification':'REAL_CONTROLLED_LOCAL_NODE_EXECUTION_NOT_REAL_JENKINS_INTEGRATION'},'initialFalcoPreflightError':{'classification':'HARNESS_CROSS_REALM_JSON_BOUNDARY','log':'falco-v2-rebase-preflight.log','resolution':'Round-trip captured fixture through explicit JSON boundary before strict candidate codec; no facts or Gate changed','retryLog':'falco-v2-rebase-preflight-retry.log'},'sshInitialSandboxDeniedThenTrustedEscalatedReadSucceeded':True,'realPipelineValidation':'NOT_EXECUTED'})
save('verdict.json',{'REAL_V2_PIPELINE_INTEGRATION':'INCOMPLETE','SUMMARY_V2_MIGRATION':'INCOMPLETE','phasesCompleted':[1,2,3],'phase4':'NOT_IMPLEMENTED_NOT_WIRED','phase5':'CANONICAL_INVENTORY_CONFIRMED_RUNTIME_RESULTS_NOT_CAPTURED','laterPhaseControlledChecks':'Evidence only, not real implementation acceptance','candidateRebase':'VERIFIED_FOR_INACTIVE_CANDIDATE','readinessCompatibilityAuthority':'READY_RETAINED; no scanner/adapter/Gate/Policy change','blockers':blockers,'infrastructureAccess':'AVAILABLE_TRUSTED_READ_ONLY; not the blocker','productionV2Activation':False,'newJenkinsBuilds':0,'realApproval':0,'signing':0,'promotion':0,'release':0,'rollout':0,'realArtifactIdentity':None,'actualSummaryWritten':False,'nextPermittedActionIfVerified':None,'minimalRemainingWork':'Implement B1/B2 in the authorized non-release path, then execute B3; no plugin-contract work.'})

identity=v1['identity'];rebase=read(O/'V2_REBASED_IDENTITY.json')
sections=[
 ('current V1 identity',identity+'；fresh local snapshot 542 files / tree '+v1['snapshotTreeSha256']+'。真实 job petclinic-ci #270 SUCCESS，platform-security@'+active['libraries'][0]['version']+'；13 个实际 V1 源文件另存，local/live Manager 身份分开。'),
 ('existing V2 candidate classification','633 条旧候选引用中 629 UNCHANGED_COMPATIBLE、4 NEEDS_REBASE（2 个 Falco 文件在 V1/V2 两分支各引用一次）；没有未解释 STALE/INVALID。代码候选不是已经通过实际接线。'),
 ('stale V2 references found','falco-parent.mjs 与 falco-parent.test.mjs 的旧哈希；旧候选仍完整保留，不激活。原 2128 不能继续作为当前 aggregate；r2 显式绑定 2202/0 与 Falco 89/91。'),
 ('V2 rebase changes','仅新增 candidate-integrity-r2.json，SHA '+rebase['contractSha256']+'；候选 V1 rollback 分支接受当前冻结文件，V2 分支 110 个精确文件身份。生产 V1 integrity contract 未改，producer 实现字节未改。'),
 ('current authoritative owner','真实 Policy owner 尚未实现/接线。实际 vars/securityManager.groovy call/plan loop 和两个 helper 仍是 V1 工具编排；owner.mjs 只是候选 helper。已通过受信 SSH 只读证实 workspace 缺 Engine 和 owner。此项不是权限或主机故障。'),
 ('canonical runtime source count','16；见 runtime-source-coverage.json。18 compatibility labels 中 semgrep alias 去重、Promotion 为 post scope，Sonar 仍在 runtime expected 集合。'),
 ('per-source evaluation counts','真实 16 项均 null / NOT_OBSERVED，没有新 pipeline。受控 fixture 每项 1 单列，不能冒充真实 runtime once。'),
 ('duplicate evaluation result','候选单 owner 并发/重复调用在二次求值前拒绝，既有测试通过；跨进程/真实 pipeline duplicate proof NOT_TESTED。'),
 ('real runtime fact capture result','未完成。只读检查 #270 的 SOPS、Kyverno、Kubescape、Cosign、Dojo、Falco 六类真实归档成功报告，仅导出字段名/哈希，发现缺完整观察字段；它们是 HISTORICAL_ARCHIVE，不是本轮新 runtime facts。未补造事实。'),
 ('immutable artifact identity','真实 artifact NOT_GENERATED / identity=null；4 个 controlled Falco artifact 的 digest/path 在 falco-v2-rebase-preflight.json，明确不是实际 pipeline 产物。'),
 ('artifact completeness','真实 NOT_TESTED。候选固定 16-source 完整/缺失/重复/stale 拒绝测试通过；没有拿缺失事实生成真实 COMPLETE。'),
 ('artifact integrity','真实 NOT_TESTED。controlled artifacts 0400/create-only、SHA 和 result identity 验证通过。当前 r2 精确文件哈希均匹配，没有 wildcard 或关闭校验。'),
 ('candidate binding','真实 NOT_TESTED；受控 build/candidate/stale 绑定和拒绝检查通过。没有把 #270 的历史 binding 套成新运行。'),
 ('Summary V2 real generation','未执行。只在 evidence 中生成受控 Summary，并运行真实候选序列化函数；未写 actual security-summary.json。'),
 ('V1/V2 semantic differential','真实 pipeline NOT_EXECUTED；既有 6 个状态的实际 V1 序列化 vs 候选 V2 旧字段 deepEqual 通过，范围 CONTROLLED_SERIALIZATION_AND_ENGINE_UNIT。'),
 ('PASS result','受控 6-state differential 中 PASS 通过；真实 pipeline NOT_TESTED。'),
 ('FAIL result','受控 FAIL 保留；Falco 原 2 秒样本全链 FAIL 一致；真实 pipeline NOT_TESTED。'),
 ('WARN result','受控 WARN 保留；真实 pipeline NOT_TESTED。'),
 ('SKIPPED result','受控 SKIPPED/null decision 保留，不改为 PASS；真实 pipeline NOT_TESTED。'),
 ('NOT_CONFIGURED result','受控 NOT_CONFIGURED/null 保留；真实 pipeline NOT_TESTED。未把“采集器没实现”虚报成合法 runtime NOT_CONFIGURED。'),
 ('POLICY_ERROR result','受控错误策略保留明确 error，无静默降级；真实 pipeline NOT_TESTED。'),
 ('Falco current normal-path result','baseline/final 各 1 个 frozen 受控正常通过样本：old Gate=Policy=artifact=Summary=PASS；原 Gate 完整 body 再执行，未调用真实 sensor。'),
 ('Falco 2-second IO boundary V2 result','baseline/final 两个原反例，均 FAIL=FAIL=FAIL=FAIL；同一个 resultDigest 被 Gate/artifact/Summary 复用。4 个 Falco preflight 合计 MATCH 4/DRIFT 0；不是 live runtime。V2 代码未增加固定 +16s。'),
 ('Promotion V2 migration','实际 consumer 未迁移。原 gateEvidence/sign-approve/promote 不变；候选 preApprovalPolicyInput 检查通过不能当作已安装的真实 guard。'),
 ('Promotion tamper/unknown rejection','候选 exact-version verifier 的 unknown/tamper/mixed-version 测试通过；真实 dispatch NOT_TESTED。旧 validateGate 忽略附加 metadata 的风险仍由现有测试明确证明，因此不可激活。'),
 ('anti-self-approval','ANTI_SELF_APPROVAL(candidate)=PASS；原测试拒绝 future PromotionResult/approval 字段。真实 pipeline 仍 NOT_TESTED，不输出无范围的实际 anti-self-approval PASS。没有执行批准或 Promotion。'),
 ('Regression V2 migration','实际 integrity dispatch 未迁移；保留原 top-level Node exit-code Gate，未用 TAP 计数替换 Gate。'),
 ('Regression 147/147','本轮原命令 147/147 PASS；独立冻结 V1 snapshot 中再次 147/147 PASS；两次真实本地退出均为 0，分别送 Engine 后 PASS/PASS，2 MATCH/0 DRIFT。没有把本地执行当 Jenkins 新构建。'),
 ('Jenkins archive regression','真实 Jenkins 归档读取正常；候选 .devsecops/** glob 静态覆盖检查通过；新 V2 artifact 的真实归档 NOT_TESTED，无新构建。'),
 ('Loki regression','受控 JSON 旧字段兼容通过；本轮无 production publish/live query。真实 migrated consumer transport NOT_TESTED。'),
 ('Grafana regression','14 个既有 JSON selector 的受控字段兼容通过；未修改查询或执行在线 Grafana 验证。'),
 ('other consumer regression','原 Promotion 两项 baseline tests 包含在 147 项内通过；sign-approve/promote/generic Summary 的实际 V2 消费尚未迁移。'),
 ('Policy core 5/5','本轮 5/5 PASS。'),
 ('contract checks 10/10','本轮既有只读契约 checks 10/10 VERIFIED。'),
 ('source hash validation',str(len(refs))+' 冻结 source refs / '+str(len({x['path'] for x in refs}))+' distinct 全匹配；3118 条既有 evidence refs 重核无未解决失败；4973 个保护旧文件零修改。旧 evidence 未覆盖。'),
 ('current Falco adapter hash validation',sha(R/'infra/security/policy/falco-parent.mjs')+'，与最新权威矩阵/r2 一致。'),
 ('Falco Gate hash validation',sha(R/'infra/security/runtime/health.mjs')+'，保持不变。'),
 ('Policy baseline validation',sha(R/'infra/security/policy/versions/baseline-v1.json')+'，Engine 与 baseline 都未改。'),
 ('mixed-version matrix','候选 A/B/C/D/E/F/H、malformed artifact/result 拒绝测试通过；真实消费者未安装，不能标记 production mixed-version matrix VERIFIED。V1 只允许显式 rollback，不自动 fallback。'),
 ('rollback result','受控 exact snapshot/hash/显式 V2→V1 选择 PASS，且 snapshot Regression 147/147；真实 pipeline rollback NOT_TESTED，因为未切换。命令 node evidence/2026-11-02/real-v2-current-baseline-integration/check-v1-rollback.mjs 可只读重核。'),
 ('V1 restored after rollback','生产 NO_SWITCH_PERFORMED，始终 V1，不声称执行过生产恢复。local Manager 与 live Manager SHA 不同，严禁拿 local 快照批量覆盖 live。'),
 ('release count','0；真实 approval/signing/promotion 同为 0。'),
 ('rollout count','0；Jenkins new build 0。'),
 ('REAL_V2_PIPELINE_INTEGRATION','INCOMPLETE。'),
 ('SUMMARY_V2_MIGRATION','INCOMPLETE。'),
 ('exact blocker if not VERIFIED','B1 同次执行完整事实采集未实现；B2 真实 non-test Policy owner、跨阶段唯一求值与 Gate receipt 交接未接线；B3 实际 artifact/Summary 和 Promotion/Regression version dispatch 未迁移、真实全链未运行。以上是工程实现缺口，不是当前基础设施故障；r2 与 fixture PASS 不能关闭它们。'),
 ('exact next permitted action if VERIFIED','不适用，未 VERIFIED。剩余工作仍是本次授权的真实非发布接线：先实现 B1/B2，再运行 B3 的 complete artifact、consumer/mixed-version/anti-self-approval/rollback 验证；不进入统一插件契约、开关、Dojo 解耦或 Router。')]
assert len(sections)==47
report='REAL_V2_PIPELINE_INTEGRATION =\nINCOMPLETE\n\nSUMMARY_V2_MIGRATION =\nINCOMPLETE\n\n本轮完成 r2 候选重基线、当前 V1 冻结、可信只读生产入口/原生报告契约检查及候选回归；未完成用户要求的真实 pipeline owner/采集器/消费者接线。当前基础设施可达，不能把未完成实施说成权限阻塞，也不能用受控检查冒充实际接线 VERIFIED。\n\n'
report+='\n\n'.join(f'{i}. **{name}**：{value}' for i,(name,value) in enumerate(sections,1))
report+='\n\n真实 canonical source 列表（16 项，当前新 pipeline counts 全为 NOT_OBSERVED）：'+', '.join(source_ids)+'。\n\n初次受限沙箱 SSH 返回 Operation not permitted，随后授权的严格 host-key SSH 成功；未修改 known_hosts、未关闭校验。初次 Falco V2 preflight 在候选 codec 拒绝 VM 跨 realm 对象，修复测试 JSON 边界后通过，原失败日志保留；没有调整任何 scanner/Gate/Policy 判定。\n\n所有候选 40 tests、Falco 4 项和本地 Regression 2 次执行都在其明确范围内保留；不得从这些数字推导实际 Jenkins 全链通过。生产 V1、旧 candidate-integrity.json 和全部历史证据均保留。新 candidate-integrity-r2.json 仍 inactive。\n'
(O/'REPORT.md').write_text(report)
files={str(p.relative_to(R)):sha(p) for p in sorted(O.rglob('*')) if p.is_file() and p.name not in ['artifact-sha256.json','final-validation.json']}
files['infra/security/summary-v2/candidate-integrity-r2.json']=sha(R/'infra/security/summary-v2/candidate-integrity-r2.json')
save('artifact-sha256.json',files)
assert all((R/n).is_file() and sha(R/n)==h for n,h in files.items())
save('final-validation.json',{'evidenceIntegrity':'PASS','indexedFiles':len(files),'indexSha256':sha(O/'artifact-sha256.json'),'protectedPreExistingFilesUnchanged':len(before),'sourceRefsRechecked':len(refs),'REAL_V2_PIPELINE_INTEGRATION':'INCOMPLETE','SUMMARY_V2_MIGRATION':'INCOMPLETE','actualPipelineCounts':'NOT_OBSERVED','newJenkinsBuilds':0,'release':0,'rollout':0,'productionV2Activated':False,'realArtifactGenerated':False})
print(json.dumps({'REAL_V2_PIPELINE_INTEGRATION':'INCOMPLETE','SUMMARY_V2_MIGRATION':'INCOMPLETE','candidateTests':40,'falcoCandidatePreflight':4,'originalRegression':147,'rollbackSnapshotRegression':147,'core':5,'contracts':10,'unmodifiedProtectedFiles':len(before),'indexedFiles':len(files),'blockers':[x['id'] for x in blockers]},ensure_ascii=False))
