"""Verify current evidence and report partial runtime integration without promotion."""
from pathlib import Path
import hashlib,json,re
R=Path(__file__).resolve().parents[3];O=Path(__file__).resolve().parent
load=lambda p:json.loads(p.read_text())
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
def save(name,value):(O/name).write_text(json.dumps(value,ensure_ascii=False,indent=2)+'\n')
before=load(O/'before-sha256.json');changed=[p for p,h in before.items() if not (R/p).is_file() or sha(R/p)!=h];assert not changed,changed
authority=R/'evidence/2026-11-02/summary-integration-readiness-recheck'
source_refs=load(authority/'source-integrity.json')['checks'];assert all(sha(R/x['path'])==x['expected'] for x in source_refs)
indices=load(authority/'index-integrity.json')['checks']
for x in indices:
    p=Path(x['path']);p=p if p.is_absolute() else R/p
    if x['directMatch']:assert sha(p)==x['expected']
    else:assert x['resolved'] and sha(R/x['archivedPath'])==x['expected'] and sha(p)==x['actual']
contract=load(R/'infra/security/summary-v2/candidate-integrity-r2.json')
assert all(sha(R/p)==h for v in contract['versions'].values() for p,h in v['files'].items())
bundle=load(O/'runtime-source-bundle-r4.json');assert all(sha(R/p)==h for p,h in bundle['files'].items())
build=load(O/'jenkins-build-4.json');assert build['build']==4 and build['result']=='FAILURE' and not build['building']
artifacts=build['artifacts'];coverage=next(v for p,v in artifacts.items() if p.endswith('coverage.json'))
assert not coverage['failures'] and coverage['complete'] is False and len(coverage['missing'])==11
captured=[s for s in coverage['sources'] if s['state']=='CAPTURED'];assert len(captured)==5
for row in captured:
    name=row['sourceId'];r=next(v for p,v in artifacts.items() if p.endswith('/'+name+'.result.json'));c=next(v for p,v in artifacts.items() if p.endswith('/'+name+'.capture.json'));g=coverage['gate'][name]
    assert row['evaluationCount']==c['evaluationCount']==1
    assert row['resultDigest']==r['resultDigest']==c['resultDigest']==g['resultDigest']
    assert r['result']['decision']==g['decision']=='PASS' and c['execution']['exitStatus']==0 and r['evidenceComplete']
    assert r['binding']==coverage['binding'] and c['rawPayloadPersisted'] is False and c['rawFactDigest']==r['rawFactDigest']
    if name.startswith('falco'):
        windows=c['evidence'][0]['sampleWindows'];assert windows
        for w in windows:
            assert w['windowEndMs']-w['windowStartMs']==15000
            assert w['windowEndMs']<=w['startedAtMs']<=w['logCompletedAtMs']<=w['completedAtMs']
            # The query's actual observed ISO bound, not a synthetic wait.
            from datetime import datetime
            assert int(datetime.fromisoformat(w['querySince'].replace('Z','+00:00')).timestamp()*1000)==w['windowStartMs']
assert all(s['evaluationCount'] is None and s['resultDigest'] is None for s in coverage['sources'] if s['state']=='NOT_OBSERVED')
assert coverage['artifactGenerated'] is False and 'incomplete' in coverage['artifactRejection']
assert not any('pre-approval-' in p for p in artifacts)
counts=build['regression'][0]['counts'];assert counts['tests']==counts['pass']==147 and counts['fail']==0
def tap(file,expected):
    text=(O/file).read_text();stats={k:int(v) for k,v in re.findall(r'^(?:#|ℹ) (tests|pass|fail|cancelled|skipped|todo) (\d+)$',text,re.M)}
    assert stats['tests']==stats['pass']==expected and all(stats[k]==0 for k in ['fail','cancelled','skipped','todo'])
    return {**stats,'path':file,'sha256':sha(O/file)}
checks={'collectorOwner':tap('collector-owner-tests-r4.log',19),'candidate':tap('candidate-tests.log',40),'policyCore':tap('policy-core.log',5),'regression':{'classification':'REAL_JENKINS_BUILD_4',**build['regression'][0]}}
checks['policyContracts']=load(O/'policy-contract.json');assert checks['policyContracts']['ready'] and len(checks['policyContracts']['checks'])==10
replay=load(O/'source-replay-results.json');assert replay['falco']['samples']==replay['falco']['match']==4 and replay['falco']['drift']==0
assert replay['sops']['shapes']==3 and replay['sops']['productionSecretAccess']==0
live=load(O/'live-jenkins-baseline.json');old=load(R/'evidence/2026-11-02/real-v2-current-baseline-integration/live-jenkins-baseline.json')
prod=next(j for j in live['jobs'] if j['job']=='petclinic-ci');prior=next(j for j in old['jobs'] if j['job']=='petclinic-ci')
for key in ['latestBuild','result','scriptPath','summarySha256','checkoutRevisions']:assert prod[key]==prior[key],key
workspace=load(O/'live-workspace-hashes.json');oldspace=load(R/'evidence/2026-11-02/real-v2-current-baseline-integration/live-workspace-hashes.json')
for current,previous in zip(workspace['workspaces'],oldspace['workspaces']):assert current==previous
post=load(O/'node-lease-postflight.json');assert post['lease']['validationHolderReleased']
assert all(next(c['status'] for c in n['conditions'] if c['type']=='Ready')=='True' for n in post['nodes'])
leak_patterns=[r'AGE-SECRET-KEY-1[A-Z0-9]{40,}',r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----',r'"token"\s*:\s*"eyJ[A-Za-z0-9_.-]{80,}']
leaks=[];scanned=[]
for p in O.glob('*.json'):
    text=p.read_text();scanned.append(p.name)
    if any(re.search(pattern,text) for pattern in leak_patterns):leaks.append(p.name)
assert not leaks,leaks
save('secret-leakage-check.json',{'classification':'PATTERN_SCAN_AND_DATA_MINIMIZATION_NOT_UNIVERSAL_LEAK_PROOF','jsonFilesChecked':scanned,'matches':leaks,'productionSopsGateExecutions':0,'productionSecretOrAgeKeyAccess':0,'rawPayloadsArchived':False,'tokenOnlyInGateProcessMemoryAndOriginalTemporaryKubeconfig':True})
save('source-preservation.json',{'protectedFiles':len(before),'changedPreexistingFiles':changed,'frozenSourceReferences':len(source_refs),'distinctFrozenSourcePaths':len({x['path'] for x in source_refs}),'priorIndexReferences':len(indices),'frozenSourcesMatch':True,'r2CandidateUnchanged':True,'uploadedBundleFilesMatch':len(bundle['files']),'productionWorkspaceUnchanged':True,'productionJob':{k:prod[k] for k in ['job','latestBuild','result','summarySha256']},'hashes':{p:sha(R/p) for p in ['infra/security/runtime/health.mjs','infra/security/policy/falco-parent.mjs','infra/security/secrets-gate.mjs','infra/security/scanner-runtime.mjs','infra/security/policy/engine.mjs','infra/security/policy/versions/baseline-v1.json','infra/security/security-summary.mjs']}})
matrix=load(authority/'authoritative-source-matrix.json')['sources']
mapping=[]
for row in matrix:
    name=row['source'];canonical=None if name=='security-approval-promotion' else 'semgrep-command-audit' if name=='semgrep' else name
    item=next((s for s in coverage['sources'] if s['sourceId']==canonical),None)
    mapping.append({'compatibilityLabel':name,'canonicalRuntimeSource':canonical,'priorCompatibilityStatus':row['latestCompatibilityStatus'],'runtimeCapture':item['state'] if item else 'POST_APPROVAL_OUT_OF_SCOPE','evaluationCount':item['evaluationCount'] if item else None,'resultDigest':item['resultDigest'] if item else None})
save('runtime-source-coverage.json',{'inventoryLabels':18,'canonicalRuntimeSources':16,'captured':5,'missing':coverage['missing'],'binding':coverage['binding'],'mapping':mapping,'noInventedSkipOrNotConfigured':True})
save('test-results.json',checks)
blockers=[{'id':'B1','type':'IMPLEMENTATION_AND_EXECUTION_GAP','detail':'11 canonical sources have no complete same-run capture in the dedicated path. Wrapper projections are not full scanner/child execution proof; unsupported native shapes remain unavailable. Existing historical success reports cannot fill missing runtime prerequisites or facts.','sources':coverage['missing'],'minimalFix':'Extend passive source-specific capture and original workflow bindings for these sources, preserving native outputs and existing Gate semantics; use the accepted isolated SOPS fixture boundary instead of production credentials.'},
 {'id':'B2','type':'PARTIAL_OWNER_WIRING','detail':'The real dedicated owner evaluates 5 sources exactly once and reuses their receipts. It does not yet receive all 16 sources or the real Provenance helper outcomes.','minimalFix':'Feed all expected original module/helper facts to this sole owner, with atomic claims and no invented skipped states.'},
 {'id':'ARTIFACT','type':'EXPECTED_COMPLETENESS_REJECTION','detail':'The bounded five-source runner intentionally stops with exit 3. Its full-artifact branch is not yet wired to real external Gate observations/legacy Summary snapshot/producer identity. No immutable complete runtime artifact exists.','minimalFix':'After complete facts and Gate compatibility, supply actual external checks, bound preapproval V1 fields and r2 producer identity to the candidate writer; never bypass completeness or fabricate passing checks.'}]
verdict={'REAL_RUNTIME_FACT_CAPTURE':'INCOMPLETE','REAL_POLICY_OWNER':'INCOMPLETE','IMMUTABLE_ARTIFACT_RUNTIME':'INCOMPLETE','SUMMARY_V2_MIGRATION':'INCOMPLETE','realCapturedSourceCount':5,'expectedSourceCount':16,'blockers':blockers,'dedicatedJenkinsBuilds':4,'productionBuildsTriggered':0,'release':0,'rollout':0,'summaryActivated':False,'approval':0,'promotion':0,'postflight':post,'notAnInfrastructureOrPermissionsBlocker':True}
save('verdict.json',verdict)
identities='；'.join(s['sourceId']+'='+s['resultDigest'] for s in captured)
items=[
 ('selected real pipeline insertion point','vars/securityManager.groovy:58 命令返回后、:60 results.add 前；两个 provenance helper 的返回值也须在 Security Gate 前收口。生产文件未接线。'),
 ('authoritative owner file/function/stage','专用 Jenkinsfile.runtime-facts 的 Original command → Runtime facts → Authoritative owner → Gate reuse；run-nonrelease.mjs:stage → captureStage → createRuntimeOwner.accept → reuseForGate。这是实际 Jenkins 执行的非发布编排，目前仅覆盖 5 项。'),
 ('runtime facts envelope','schema/kind/sourceId/buildBinding/execution/presence/rawFactDigest/reports/evidence/facts/envelopeDigest；facts.raw 保留来源专用 payload；匿名 fd3 仅传内存原始事实，磁盘保留哈希/安全命令观察/receipt。collector 不调用 Policy。'),
 ('canonical runtime source count','16。'),
 ('compatibility→runtime source mapping','18 compatibility labels；semgrep 是 semgrep-command-audit 的 alias；security-approval-promotion 是 post-approval，不能加入 preapproval。完整映射见 runtime-source-coverage.json。'),
 ('sources successfully captured','Regression、Falco baseline、Kyverno/RBAC、Kubescape、Falco final；#4 均为原命令 exit 0 → standard PASS。Kubescape 原 AUDIT 事实未被改写为无漏洞声明。'),
 ('missing sources',', '.join(coverage['missing'])+'。全部 NOT_OBSERVED，未伪造 SKIPPED/NOT_CONFIGURED/PASS。'),
 ('per-source evaluation counts','5 个已接入来源各 1；11 个未观察来源为 null，不把 null 当作 0 或 1。'),
 ('duplicate evaluation result','本轮 owner/collector 测试覆盖重复、并发重复、第二 owner/run claim、重复 Gate handoff：均在第二次求值前拒绝，计数仍为 1。未在 Jenkins 注入重复生产故障。'),
 ('per-source result identities',identities),
 ('Gate reuse proof','#4 五项 result.json、capture.json、gate.json、coverage.gate 的 resultDigest 完全相同；复用不调用 Engine。'),
 ('aggregate Gate compatibility result','INCOMPLETE：只证明五项旧命令/Policy/per-source Gate 一致，未声称 16-source aggregate 已验证。#2 的 Kyverno 采集器错读 tools manifest 被 drift guard 拦截；修正为原 tools-lock 后 #3/#4 一致，未改 Gate/adapter。'),
 ('immutable artifact path','NOT_GENERATED；没有把 partial receipt bundle 命名为 COMPLETE artifact。'),
 ('artifact producer/version','目标为原 r2 contract V2 producer；candidate-integrity-r2.json 未改。本轮真实 artifact producer evidence 尚未生成。'),
 ('artifact completeness','INCOMPLETE：5/16；#4 在真实路径拒绝缺失 11 项。'),
 ('artifact integrity','真实完整 artifact NOT_TESTED；候选 integrity/immutable/mixed-version 行为在隔离 checkout 的 40 项测试中通过，不能替代 runtime artifact。'),
 ('candidate/build binding',json.dumps(coverage['binding'],ensure_ascii=False)+'；source commit 不能单独证明含 untracked 实现的工作树，因此同时绑定 504 文件精确 bundle manifest。'),
 ('missing-source rejection','真实 #4 已拒绝；artifactGenerated=false，exit 3；没有伪造补项。'),
 ('duplicate-source rejection','collector/owner 19 项及候选 40 项中验证通过；真实全量 artifact 尚无。'),
 ('stale-result rejection','collector/候选测试通过；旧 build/candidate 绑定不能用于本轮。'),
 ('malformed-result rejection','collector/候选测试通过，篡改 raw facts/envelope/result integrity 均拒绝。'),
 ('POLICY_ERROR preservation','单元及候选测试保留显式 POLICY_ERROR；不能作为 legacy success 复用；本轮在线五项未出现 POLICY_ERROR。'),
 ('SKIPPED preservation','显式观察到 skipped 的受控测试保留 null decision；本轮未把未执行来源替换为 skipped。'),
 ('NOT_CONFIGURED preservation','受控测试保留 null decision；native success 报告缺完整观察时不成为 PASS；未声称未执行来源真实已 not_configured。'),
 ('Falco runtime facts result','#4 baseline/final 均真实 PASS、once、same receipt；每次查询 windowEndMs 从当次实际 since-time 下界 + 15000ms 还原，同时记录真实开始/结束时间。baseline 稳定性检查保留首次原 Date.now，不被后续查询覆盖。无固定 +16s 推导样本。'),
 ('Falco 2-second boundary result','4 个 accepted whole-Gate 回放 MATCH/0 DRIFT，其中 baseline/final 原 2 秒边界均旧 Gate FAIL = Policy FAIL；分类 CONTROLLED_ACCEPTED_GATE_REPLAY_NOT_LIVE_RUNTIME。不是线上故障。'),
 ('SOPS runtime facts result','正向/解密失败/工具缺失三类 accepted archive 的脱敏 shape 均可由 envelope 无变化承载。分类 HISTORICAL_CONTROLLED_EXECUTION_REDACTED_SHAPE_ONLY；未拿脱敏 digest 当解密原文重新求值；本轮新 SOPS Gate 执行 0。生产 Secret/key 访问 0；执行入口强制验证真实 isolated MIN_RBAC guard，不能靠环境 flag 绕过。'),
 ('Policy core 5/5','本轮 5/5 PASS。'),
 ('contract checks 10/10','本轮只读 10/10 VERIFIED，未重定义 baseline。'),
 ('Regression 147/147','真实 Jenkins #4 原 Regression 命令 exit 0，147 tests/147 pass/0 fail/skip/todo/cancel；未改 Regression Gate，不用 TAP 计数取代原退出码。'),
 ('source hash validation',str(len(before))+' 个旧文件零修改；'+str(len(source_refs))+' source refs / '+str(len({x['path'] for x in source_refs}))+' distinct 全匹配；'+str(len(indices))+' prior index refs 重核通过；r2 精确引用和最终上传 504 文件均匹配。关键哈希见 source-preservation.json。'),
 ('V1 active path unchanged YES/NO','YES。生产 petclinic-ci 仍 #270 SUCCESS，原 V1 Summary SHA '+prod['summarySha256']+'；生产 workspace 与前轮只读基线逐项一致。'),
 ('production files changed','既有生产文件 0；新增 infra/security/runtime-facts/*、独立 Jenkinsfile.runtime-facts、当轮 evidence/docs。独立 job/config/workspace 是新非发布验证面。临时沿用 heavy Lease，完成后释放；未扩大 RBAC。'),
 ('Jenkins validation build count','4 个专用非发布构建；#1 partial 3 项；#2 Kyverno collector drift 被拦截；#3/#4 五项一致但均因完整性不足 exit 3。生产 build 触发 0。'),
 ('release count','0。'),('rollout count','0。'),
 ('REAL_RUNTIME_FACT_CAPTURE','INCOMPLETE。'),('REAL_POLICY_OWNER','INCOMPLETE。'),('IMMUTABLE_ARTIFACT_RUNTIME','INCOMPLETE。'),
 ('exact blocker if any','B1：11-source collector/真实执行未补齐；B2：唯一 owner 仅接入五项，尚无全部 helper 事实；artifact runtime 全量生产身份/外部检查/绑定旧字段输入也尚未接线。均为明确工程缺口，不是 SSH/Jenkins 权限故障。'),
 ('exact next permitted action if all VERIFIED','尚未全部 VERIFIED，所以不存在进入 Summary 的许可。本阶段剩余工作仍是上述 B1/B2 与完整 candidate artifact；Summary/Promotion/Regression migration 均不得推进。')]
assert len(items)==41
report=['# Runtime facts / authoritative owner 本轮报告','',
 '结论：真实专用 Jenkins 已证明 5/16 来源的采集、一次求值及 Gate receipt 复用；整体仍 INCOMPLETE，完整 artifact 未生成。',
 '', '验证范围严格区分：REAL_DEDICATED_NONRELEASE_JENKINS_EXECUTION、CONTROLLED_ACCEPTED_GATE_REPLAY、HISTORICAL_REDACTED_SHAPE、SYNTHETIC_UNIT_ONLY。','']
for i,(title,text) in enumerate(items,1):report.extend([f'{i}. **{title}** — {text}',''])
report.extend(['```text','REAL_RUNTIME_FACT_CAPTURE =','INCOMPLETE','REAL_POLICY_OWNER =','INCOMPLETE','IMMUTABLE_ARTIFACT_RUNTIME =','INCOMPLETE','SUMMARY_V2_MIGRATION =','INCOMPLETE','```','','已停在本阶段；未接 Summary V2。'])
(O/'REPORT.md').write_text('\n'.join(report)+'\n')
(R/'docs/RUNTIME-FACTS-OWNER-20261102.md').write_text('# Runtime facts / owner 当前实施状态\n\n本轮仅实现部分非发布接线，不能宣称 B1/B2 全部完成。\n\n'+ '\n'.join(report[2:])+'\n')
print(json.dumps({'captured':5,'expected':16,'runtimeIntegration':'INCOMPLETE','protectedUnchanged':len(before),'policyCore':5,'contracts':10,'collectorOwnerTests':19,'candidateTests':40,'realJenkinsRegression':147,'reportItems':len(items),'release':0,'rollout':0}))
