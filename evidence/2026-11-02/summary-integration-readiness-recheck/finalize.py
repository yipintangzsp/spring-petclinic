"""Independent read-only reconciliation; writes only this iteration's audit evidence."""
from pathlib import Path
from collections import Counter
import hashlib,json,re

R=Path(__file__).resolve().parents[3]; O=Path(__file__).resolve().parent
F=R/'evidence/2026-11-02/falco-time-contract-repair'
read=lambda p:json.loads(p.read_text())
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
def save(name,data):(O/name).write_text(json.dumps(data,ensure_ascii=False,indent=2)+'\n')
def pointer(identity):
    name,fragment=identity.split('#',1); obj=read(R/name)
    for bit in fragment.split('/')[1:] if fragment else []:
        bit=bit.replace('~1','/').replace('~0','~')
        obj=obj[int(bit)] if isinstance(obj,list) else obj[bit]
    assert isinstance(obj,dict),identity
    return obj
def statistics(identities):
    assert len(identities)==len(set(identities))
    old=Counter();new=Counter();drift=0;preserved=True
    for identity in identities:
        row=pointer(identity)
        a=next((row[k] for k in ['oldDecision','legacyDecision','legacy'] if k in row),None)
        b=next((row[k] for k in ['standardDecision','standard','policyDecision'] if k in row),None)
        if identity.endswith('#/result'):
            a=row['oldGate']['oldDecision'];b=row['policy']['decision'];raw=row['rawEvidence']['rawPreserved']
        else:
            if a is None:a=row.get('oldStatus')
            if b is None:b=row.get('standardStatus')
            raw=next((row[k] for k in ['rawPreserved','rawUnchanged','inputUnchanged'] if k in row),False)
        drift+=int(a is None or a!=b or row.get('oldStatus')!=row.get('standardStatus'))
        preserved=preserved and raw;old[a]+=1;new[b]+=1
    return dict(samples=len(identities),matches=len(identities)-drift,drifts=drift,rawPreserved=preserved,oldDecisions=dict(old),policyDecisions=dict(new))

d=read(O/'readiness.json');m=read(O/'authoritative-source-matrix.json')
diff=read(O/'differential-reconciliation.json');integ=read(O/'index-integrity.json')
sources=read(O/'source-integrity.json');summary=read(O/'summary-preconditions.json')
assert len(m['sources'])==18 and sum(m['counts'].values())==18
for row in integ['checks']:
    p=Path(row['path']);p=p if p.is_absolute() else R/p
    if row['directMatch']:assert p.is_file() and sha(p)==row['expected']
    else:
        assert row['resolution']=='HISTORICAL_SNAPSHOT_SUPERSEDED_WITH_EXACT_OLD_BYTES' and row['resolved']
        assert sha(R/row['archivedPath'])==row['expected'] and sha(p)==row['actual']
for row in sources['checks']:assert sha(R/row['path'])==row['expected']
snapshot=read(R/'evidence/2026-11-02/sops-authoritative-differential-02/project-before.json')
for row in m['sources']:
    for n in row['productionImplementationPaths']+row['evidenceFiles']+row['evidenceIndexes']:assert (R/n).is_file(),n
    for n,h in row['sourceHashes'].items():assert sha(R/n)==h
    name=row['classifierAdapterPath'];actual=sha(R/name)
    assert actual==row['adapterSha256']
    assert sha(R/row['policyMappingPath'])==row['policyMappingSha256']
    if row['source'].startswith('falco-'):
        t=row['adapterVersionTransition']
        assert snapshot[name]==t['oldSha256']==sha(R/t['archivedOldPath'])
        assert actual==t['newSha256'] and not row['historicalEvidence']['counted']
    else:assert actual==snapshot[name]
for key,field in [('parentRecordIds','completeParentDeduplicated'),('mainRecordIds','mainEvidenceWithSonarPositive'),('layeredRecordIds','layeredRetainedRecords')]:
    assert statistics(diff[key])==diff[field],field
    assert not any('2026-11-01/falco-parent/differential.json#' in p for p in diff[key])
assert diff['completeParentDeduplicated']['drifts']==0
assert all(diff[k]['rawPreserved'] for k in ['completeParentDeduplicated','mainEvidenceWithSonarPositive','layeredRetainedRecords'])
assert diff['mainEvidenceWithSonarPositive']['samples']==diff['completeParentDeduplicated']['samples']+1
assert diff['layeredRetainedRecords']['samples']-diff['mainEvidenceWithSonarPositive']['samples']==sum(diff['supplementaryScopes'].values())
falco={x['source']:x for x in m['sources'] if x['source'].startswith('falco-')}
assert falco['falco-baseline']['parentStageSampleCount']==89
assert falco['falco-final']['parentStageSampleCount']==91
for source,mode in [('falco-baseline','baseline'),('falco-final','check')]:
    ids=[i for i in diff['parentRecordIds'] if '/falco-time-contract-repair/' in i and pointer(i)['mode']==mode]
    assert len(ids)==falco[source]['parentStageSampleCount']
    assert statistics(ids)==falco[source]['statistics']
new_index='evidence/2026-11-02/falco-time-contract-repair/artifact-sha256.json'
assert sum(x['index']==new_index for x in integ['checks'])==len(read(R/new_index))==107
assert not d['blockers'] and d['SUMMARY_INTEGRATION_READINESS']=='READY'
core=read(O/'core-readiness.json')
assert core['ready'] and len(core['checks'])==10 and all(x['status']=='VERIFIED' for x in core['checks'])
tap=(O/'core-tests.log').read_text()
tap_counts={k:int(v) for k,v in re.findall(r'^(?:#|ℹ) (tests|pass|fail|cancelled|skipped|todo) (\d+)$',tap,re.M)}
assert tap_counts['tests']==tap_counts['pass']==5 and all(tap_counts[k]==0 for k in ['fail','cancelled','skipped','todo'])
assert not any(read(O/'core-command-exits.json').values())

# Fresh production-entry reconstruction from current manager/adapter and Jenkins bytes.
adapter=read(R/'resources/security-manager/petclinic-adapter.json')
manager=(R/'vars/securityManager.groovy').read_text()
audit=(R/'Jenkinsfile.security-audit').read_text();jenkins=(R/'Jenkinsfile').read_text()
assert 'securityProvenance(cfg+' in manager and 'securityBuildProvenance(' in manager
assert "cfg.adapter=='petclinic'" in manager and "mode != 'enforce'" in manager
manager_call=re.search(r'securityManager\(([^\n]+)\)',audit)[1].replace(' ','')
assert "adapter:'petclinic'" in manager_call and "mode:'enforce'" in manager_call
for x in adapter:assert next(y for y in m['sources'] if y['source']==x['id'])['productionEntry']==x['command']
assert any('command-audit.mjs' in x['command'] and 'semgrep-gate.mjs' in x['command'] for x in adapter)
assert 'sign-approve.mjs' in audit and 'promote.mjs' in audit
stages=[]
for n in ['Jenkinsfile','Jenkinsfile.security-audit','Jenkinsfile.candidate-build']:
    text=(R/n).read_text();stages.append({'path':n,'sha256':sha(R/n),'stages':[{'line':text[:x.start()].count('\n')+1,'name':x[1]} for x in re.finditer(r"stage\('([^']+)'\)",text)]})
save('production-callgraph-validation.json',{'status':'PASS','currentAdapterStages':adapter,'conditionalModules':['vars/securityProvenance.groovy','vars/securityBuildProvenance.groovy'],'additionalSources':['semgrep-command-audit','security-approval-promotion'],'jenkinsStages':stages,'completeSourceCount':18,'sourceEntriesReconstructed':True,'liveStagesExecuted':0})

# Only classify inactive candidate staleness; never rewrite a V2 lock in this audit.
candidate=read(R/'infra/security/summary-v2/candidate-integrity.json')
stale=[{'path':p,'expected':h,'current':sha(R/p)} for p,h in candidate['versions']['V2']['files'].items() if sha(R/p)!=h]
assert {x['path'] for x in stale}=={'infra/security/policy/falco-parent.mjs','infra/security/policy/falco-parent.test.mjs'}
save('candidate-version-classification.json',{'activeProductionVersion':'V1_UNCHANGED_AS_LAST_FROZEN','liveProductionChecked':False,'candidate':'INACTIVE_V2','status':'NOT_ACTIVATABLE','staleFiles':stale,'reason':'Approved Falco repair changes the adapter and clock-aware test; old exact candidate hashes retained','readinessImpact':'LATER_ARCHITECTURE_WORK; current source compatibility accepts the explicit repaired adapter transition','activationConstraint':'A separately authorized migration must create a reviewed candidate identity; no lock update or V2 activation here'})
summary.update(localCurrentOutputExists=(R/'.devsecops/security-summary.json').exists(),localOutputNote='No substitute Summary is generated by this audit.',sourceLocksReferencingProducer=['infra/security/policy/versions/promotion-baseline-v1.json','infra/security/policy/versions/regression-baseline-v1.json'],futureChangeConstraint='Separately authorized migration must reconcile frozen producer/consumer identities and preserve current Gate semantics; inactive old candidate cannot be activated unchanged.',policyDecisionContract={'currentEngineField':'decision','futureSummaryField':'policyDecision','actualSummaryFieldAdded':False})
save('summary-preconditions.json',summary)
classification=read(O/'blocker-disposition.json')
classification['items']+=[{'priorBlocker':'Falco observed-window timing drift','status':'CLOSED_FOR_SUMMARY_INTEGRATION','reason':'New authoritative 89 baseline/91 final differential records, DRIFT=0; production Gate/baseline unchanged'},{'priorBlocker':'Summary V2 migration and inactive candidate hash transition','status':'STILL_LATER_ARCHITECTURE_WORK','reason':'Implementation is stopped. Current source compatibility uses the repaired adapter; candidate activation requires separately reviewed identity reconciliation.'}]
classification['BLOCKING_SUMMARY_INTEGRATION']=d['blockers']
classification['LATER_ARCHITECTURE_WORK']=['Summary V2 migration implementation and candidate version reconciliation','unified plugin contract','SECURITY_ENABLED','globalMode','per-plugin switches','capability checks','DefectDojo decoupling','Result Router','Loki/Grafana query closure','portability smoke','Provenance opt-in normalization']
save('blocker-disposition.json',classification)

# Independently protect all pre-existing evidence and implementation bytes.
before=read(O/'before-sha256.json')
changed=[n for n,h in before.items() if not (R/n).is_file() or sha(R/n)!=h];assert not changed,changed
save('no-mutation-proof.json',{'protectedFiles':len(before),'changed':changed,'productionApiAccess':0,'newResources':0,'rollout':0,'release':0,'newJenkinsBuilds':0,'summaryProducerModified':False,'actualSummaryModified':False,'managerOrJenkinsModified':False,'preExistingEvidenceRewritten':False,'freshIndependentShaRecheck':True,'writesOnlyInside':str(O)})
old=read(R/'evidence/2026-11-02/summary-integration-readiness-audit/readiness.json')
save('aggregate-transition.json',{'previousEvidence':'evidence/2026-11-02/summary-integration-readiness-audit','previousStatus':'SUSPENDED_PENDING_RECHECK; retained historical snapshot','previousParent':old['parentStageAggregate'],'recomputedParent':diff['completeParentDeduplicated'],'falcoReplacement':{'oldBaseline':52,'oldFinal':54,'newBaseline':89,'newFinal':91,'netAdditionalCases':74,'oldCountsRetainedOnlyAsHistory':True},'newStatus':d['SUMMARY_INTEGRATION_READINESS'],'allOtherCountsUnchanged':all(x['parentStageSampleCount']==next(y for y in read(R/'evidence/2026-11-02/summary-integration-readiness-audit/authoritative-source-matrix.json')['sources'] if y['source']==x['source'])['parentStageSampleCount'] for x in m['sources'] if not x['source'].startswith('falco-'))})

parent=diff['completeParentDeduplicated'];counts=m['counts'];old_dist=json.dumps(parent['oldDecisions'],ensure_ascii=False)
sections=[
('production source count','18；当前 14 adapter stages＋2 conditional Provenance modules＋Command Analysis＋Promotion，逐项重读入口和冻结源码。'),
('complete source inventory','完整来源、入口、source/adapter/Policy SHA、分类、索引、证据限制见下表及 authoritative-source-matrix.json。'),
('VERIFIED count',str(counts['VERIFIED'])),('DEFERRED count',str(counts['DEFERRED'])+'（Sonar）'),('ENVIRONMENT_BLOCKED count',str(counts['ENVIRONMENT_BLOCKED'])),('NOT_TESTED count',str(counts['NOT_TESTED'])+'；Sonar 的真实负例子路径仍 NOT_TESTED，不把它包装成全项 VERIFIED。'),('FAILED count',str(counts['FAILED'])),
('Falco baseline final status','VERIFIED；新 authoritative time-contract repair，89 MATCH / 0 DRIFT。'),
('Falco final final status','VERIFIED；新 authoritative time-contract repair，91 MATCH / 0 DRIFT。'),
('SOPS status','VERIFIED；12 approved/applicable/old Gate executions/Policy executions，MATCH 12，DRIFT 0，final evidence 88 个文件身份重核，cleanup 仍有完整记录；本轮不重建 fixture。'),
('Sonar status','DEFERRED；真实正例 VERIFIED；真实负例直接 build→task→analysis→ERROR/conditions 绑定缺失。独立 synthetic ERROR 逻辑测试仍 PASS。既定非阻断接受条件有效，不提升 Sonar。'),
('per-source authoritative sample counts','见下表。Semgrep 与 Command Analysis 共用 136 条、只计一次；Sonar 真实正例 1 单列，不计完整 parent。'),
('new Falco baseline authoritative count','89＝原 52＋时间 37；不是 52＋89。'),
('new Falco final authoritative count','91＝原 54＋时间 37；不是 54＋91。'),
('old Falco evidence handling','SUPERSEDED_FOR_TIME_BOUNDARY_COVERAGE；原件未改，历史索引继续核验；不再作为当前/辅助差分记录重复计数。修复前 20 个 controlled drift 仅作缺陷历史，不计当前兼容样本。'),
('authoritative deduplicated total',str(parent['samples'])+'；从当前 JSON pointers 重算，不沿用旧 2128。'),
('total MATCH',str(parent['matches'])),('total DRIFT',str(parent['drifts'])),
('old decision distribution',old_dist+'；NOT_CONFIGURED/SKIPPED 保留其 null-decision 状态，不等同 PASS。'),
('Policy decision distribution',json.dumps(parent['policyDecisions'],ensure_ascii=False)+'；与原 Gate 一致。'),
('main evidence total',str(diff['mainEvidenceWithSonarPositive']['samples'])+'＝parent '+str(parent['samples'])+'＋Sonar real positive 1。'),
('layered evidence total',str(diff['layeredRetainedRecords']['samples'])+'＝main＋辅助 201；辅助包含 Trivy release20/DB41、旧 Kyverno child49、Command child5、contracts39、SOPS unit20、Gitleaks classifier7、原 classifier recheck20；不是独立完整 parent 执行。'),
('evidence index count',str(integ['indexCount'])+'：既有 46＋Falco 新索引 1＋上一轮 readiness 审计索引 1。本轮自己的输出索引另计。'),
('evidence hash validation',str(integ['hashReferences'])+' refs；'+str(integ['directMatches'])+' 直接匹配，2 条历史 guard 转换通过保留旧字节及已批准 transition 收据验证；未解决失败 0；'+str(integ['uniqueReferencedFiles'])+' 个 distinct referenced files。新 Falco 索引 107/107 全部核验。'),
('source hash validation',str(sources['references'])+' 冻结 source refs / '+str(sources['uniqueFiles'])+' distinct files 全部匹配；另核验 18 来源 adapter 引用/16 distinct adapters（Semgrep/Command 与两 Falco 各共享实现），以及 Engine/baseline；source/index 重复引用不是样本。'),
('new Falco adapter hash status','ACCEPTED_CURRENT：'+falco['falco-baseline']['adapterSha256']+'；旧 SHA 与 archive/transition 显式绑定，未修改旧快照。'),
('frozen Falco Gate hash status','UNCHANGED：'+falco['falco-baseline']['sourceHashes']['infra/security/runtime/health.mjs']+'。'),
('Policy baseline hash status','UNCHANGED：'+sha(R/'infra/security/policy/versions/baseline-v1.json')+'。'),
('Policy core result','5/5 PASS；既有只读 contract checks 10/10 VERIFIED；默认 standard、显式 low、strict、overrides、POLICY_ERROR、raw preservation 均有效。未修改 Policy。'),
('Summary producer/schema identification','PetClinic infra/security/security-summary.mjs（Jenkinsfile.security-audit:48/:75）；generic resources/security-manager/summary.mjs（Shared Library）及相同仓库副本 infra/security/manager/summary.mjs；schema=1 内联，无独立 schema 文件。消费者为 Promotion evidence/contract/sign-approve/promote、Jenkins archive、Loki sink 和 Grafana JSON queries。metadata 契约 policyVersion/securityLevel/profile/effectivePolicy/appliedOverrides/policyDecision 已识别；当前 Engine 字段 decision，尚未接入实际 Summary。'),
('remaining deferred debt','Sonar 真实负例直接逐构建 task 归档及完整 analysis/conditions 链；其他 controlled replay 的完整历史 CLI/prerequisite/live 认证范围限制继续保留。REAL_CONTROLLED_EXECUTION 不冒充生产事故，历史样本不冒充本轮 live run。'),
('later architecture work','见 blocker-disposition.json：Summary V2 migration、统一插件契约、SECURITY_ENABLED、globalMode、per-plugin switches、capability、Dojo 解耦、Result Router、Loki/Grafana closure、portability smoke、Provenance opt-in。inactive V2 candidate 仍有两个预期 Falco hash stale，不可激活；下轮授权迁移必须建立新 reviewed identity。本轮不重写该锁。'),
('active Summary integration blockers','无 source compatibility/readiness blocker；后续实现债没有被当作已完成。READY 不授权启用未更新的候选版本。'),
('SUMMARY_INTEGRATION_READINESS',d['SUMMARY_INTEGRATION_READINESS']),
('exact blocker if NOT_READY','不适用，本轮 readiness blocker 为空。'),
('exact next permitted action if READY','STOP，等待下一阶段单独授权；本轮不恢复 Summary V2、不改 producer/security-summary.json、不迁移 Promotion/Regression、不启动插件架构工作。')]
assert len(sections)==36
table=['| Source | Status | Parent 样本 | 旧 = Policy 判定分布 |','|---|---|---:|---|']
for x in m['sources']:
    count=str(x['parentStageSampleCount'])
    if x['source']=='sonarqube':count+='；真实正例 1 单列'
    if x['source']=='semgrep':count+='；与 Command 共用'
    table.append('| '+x['source']+' | '+x['latestCompatibilityStatus']+' | '+count+' | '+json.dumps(x['statistics']['oldDecisions'],ensure_ascii=False)+' |')
report='SUMMARY_INTEGRATION_READINESS =\n'+d['SUMMARY_INTEGRATION_READINESS']+'\n\n本轮仅权威 readiness 重检；不代表 Summary V2 已实现或在线验收。\n\n'
report+='\n\n'.join(f'{i}. **{name}**：{value}' for i,(name,value) in enumerate(sections,1))+'\n\n'+'\n'.join(table)
report+='\n\n计数与范围：2202 个完整 parent 样本＋Sonar 正例 1＝main 2203；辅助层 201＝layered 2404。Semgrep/Command 去重、Trivy parent 与辅助阶段分开、SOPS execution JSON 只计一次；旧 Falco complete suite 和新时间矩阵中的 before/after 不重复计数。历史 evidence index 的多个引用不是多个执行。全部结论限冻结 standard 兼容性，不声明所有安全规则正确、在线 sensor 验证或 Jenkins/V2 集成已完成。\n\n生产访问/新 Jenkins build/release/rollout 均为 0。已有源码、Summary、GitOps、Gate、Policy、证据全部不变。本轮只在此新目录写审计脚本、日志、矩阵和报告。\n'
(O/'REPORT.md').write_text(report+'\n')
files={str(p.relative_to(O)):sha(p) for p in sorted(O.rglob('*')) if p.is_file() and p.name not in ['artifact-sha256.json','final-validation.json']}
save('artifact-sha256.json',files)
assert all(sha(O/n)==h for n,h in files.items())
save('final-validation.json',{'status':'PASS','SUMMARY_INTEGRATION_READINESS':d['SUMMARY_INTEGRATION_READINESS'],'auditArtifactFiles':len(files),'auditIndexSha256':sha(O/'artifact-sha256.json'),'preExistingProjectFilesUnchanged':len(before),'existingEvidenceIndexes':integ['indexCount'],'existingHashReferences':integ['hashReferences'],'directMatches':integ['directMatches'],'historicalSupersessionResolutions':2,'unresolvedReferenceFailures':0,'recordPointersRecomputedIndependently':True,'sourceHashesRecheckedFresh':True,'adapterTransitionAccepted':True,'summaryOrProducerModified':False,'productionAccess':0,'liveGateOrScannerRuns':0,'newJenkinsBuilds':0,'release':0,'rollout':0,'nextStageStarted':False})
print(json.dumps({'SUMMARY_INTEGRATION_READINESS':d['SUMMARY_INTEGRATION_READINESS'],'parent':parent,'counts':counts,'indexFiles':integ['indexCount'],'hashRefs':integ['hashReferences'],'frozenSourceRefs':sources['references'],'protectedFilesUnchanged':len(before),'STOP':True},ensure_ascii=False))
