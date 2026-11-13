from pathlib import Path
import json,hashlib,re
R=Path.cwd();O=R/'evidence/2026-11-02/runtime-final-eight';load=lambda p:json.loads(p.read_text());sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
def save(n,x):(O/n).write_text(json.dumps(x,ensure_ascii=False,indent=2)+'\n')
build=load(O/'jenkins-build-12.json');assert build['build']==12 and not build['building']
art=build['artifacts'];get=lambda suffix:next(v for p,v in art.items() if p.endswith('/'+suffix))
c=get('coverage.json');captured=[s for s in c['sources'] if s['state']=='CAPTURED'];assert len(captured)<16 and not c['complete'] and not c['artifactGenerated'];assert not any('pre-approval-' in p for p in art)
assert len({s['sourceId'] for s in c['sources']})==16
assert c['promotion']==c['release']==c['rollout']==0 and not c['summaryActivated']
for row in captured:
 id=row['sourceId'];r=get(id+'.result.json');e=get(id+'.capture.json');g=c['gate'][id]
 assert row['evaluationCount']==e['evaluationCount']==1
 assert row['resultDigest']==r['resultDigest']==e['resultDigest']==g['resultDigest']
 assert r['binding']==c['binding'] and r['rawFactDigest']==e['rawFactDigest'] and r['evidenceComplete'] and not r['error'] and not e['rawPayloadPersisted']
assert len({x['resultDigest'] for x in captured})==len(captured)
assert all(s['evaluationCount'] is None and s['resultDigest'] is None for s in c['sources'] if s['state']=='NOT_OBSERVED')
for id in ['sbom','regression','falco-baseline','falco-final','kyverno','kubescape']:assert c['gate'][id]['decision']=='PASS'
for id in ['provenance','build-provenance']:assert c['gate'][id]['status']=='SKIPPED' and c['gate'][id]['decision'] is None
bundle=load(O/'build-12-runtime-source-bundle.json');assert build['definitionSha256']==sha(R/'Jenkinsfile.runtime-facts')==bundle['files']['Jenkinsfile.runtime-facts']
generated=set(bundle['generatedGitMetadataFiles'])|{'runtime-sbom-clean-source.tar.gz','runtime-sbom-clean-source.json','runtime-sonar-origin.json'}
assert all(p in generated or sha(R/p)==h for p,h in bundle['files'].items())
if 'sops' in c['gate']:
 s=get('sops-runtime-receipt.json');d=load(O/'isolated-delivery-receipt.json');assert s['oldExit']==0 and s['policyDecision']=='PASS' and s['rawFactDigest']==d['rawFactDigest'] and s['resultDigest']==s['gateResultDigest'];assert s['executionScope']=='CONTROLLED_ISOLATED_RUNTIME' and s['guard']['profile']=='MIN_RBAC_EXECUTOR'
 assert get('isolated-channel-cleanup.json')['cleanupComplete']
if 'sonarqube' in c['gate']:
 s=get('sonar-current-lineage.json');assert s['binding']==c['binding'] and s['raw']['lineage']['validationBinding']==c['binding'];assert s['raw']['binding']['taskId']==s['raw']['task']['task']['id'];assert s['raw']['binding']['requestedAnalysisId']==s['raw']['task']['task']['analysisId'];assert s['resultDigest']==s['gateResultDigest'];assert s['negativeCompatibility']=='DEFERRED_REAL_NEGATIVE_EVIDENCE'
for id in ['sbom','sonar']:
 if any(p.endswith('/'+id+'-build-input.json') for p in art):assert get(id+'-build-input.json')['cleanupComplete']
for name in ['WRONG_KEY','TOOL_MISSING']:
 s=load(O/'sops'/('support-'+name.lower()+'.json'));assert s['oldExit']==1 and s['supporting']['oldDecision']==s['supporting']['policyDecision']=='FAIL'
assert load(O/'sops/cleanup-result.json')['status']=='COMPLETE'
rb=load(O/'sops/rbac-verification.json');assert rb['allMatched'] and len(rb['checks'])==27
assert load(O/'sops/preservation.json')['allMatched']
before=load(O/'before-sha256.json');changed=[p for p,h in before.items() if not (R/p).is_file() or sha(R/p)!=h];assert all(p=='Jenkinsfile.runtime-facts' or p.startswith('infra/security/runtime-facts/') for p in changed),changed
a=R/'evidence/2026-11-02/summary-integration-readiness-recheck';refs=load(a/'source-integrity.json')['checks'];assert all(sha(R/x['path'])==x['expected'] for x in refs)
indices=load(a/'index-integrity.json')['checks']
for x in indices:
 p=Path(x['path']);p=p if p.is_absolute() else R/p
 if x['directMatch']:assert sha(p)==x['expected']
 else:assert x['resolved'] and sha(R/x['archivedPath'])==x['expected'] and sha(p)==x['actual']
r2=load(R/'infra/security/summary-v2/candidate-integrity-r2.json');assert all(sha(R/p)==h for v in r2['versions'].values() for p,h in v['files'].items())
priorIndex=load(R/'evidence/2026-11-02/runtime-remaining-sources/artifact-sha256.json');files=priorIndex.get('files',priorIndex);assert all(sha(R/'evidence/2026-11-02/runtime-remaining-sources'/p)==h for p,h in files.items())
live=load(O/'live-jenkins-baseline.json');old=load(R/'evidence/2026-11-02/runtime-remaining-sources/live-jenkins-baseline.json');prod=next(j for j in live['jobs'] if j['job']=='petclinic-ci');prior=next(j for j in old['jobs'] if j['job']=='petclinic-ci')
for k in ['latestBuild','result','scriptPath','summarySha256','checkoutRevisions']:assert prod[k]==prior[k],k
assert load(O/'live-workspace-hashes.json')==load(R/'evidence/2026-11-02/runtime-remaining-sources/live-workspace-hashes.json')
p=load(O/'node-lease-postflight.json');assert p['lease']['validationHolderReleased'];assert all(next(c['status'] for c in n['conditions'] if c['type']=='Ready')=='True' for n in p['nodes'])
def tap(file,expected):
 t=(O/file).read_text();d={k:int(v) for k,v in re.findall(r'^(?:#|ℹ) (tests|pass|fail|cancelled|skipped|todo) (\d+)$',t,re.M)};assert d['tests']==d['pass']==expected and d['fail']==d['skipped']==d['cancelled']==0;return {**d,'file':file,'sha256':sha(O/file)}
tests={'collectorOwner':tap('collector-source-tests.log',57),'candidate':tap('candidate-tests.log',40),'policyCore':tap('policy-core.log',5),'contractChecks':load(O/'policy-contract.json'),'regression':build['regression'][0]}
assert tests['contractChecks']['ready'] and len(tests['contractChecks']['checks'])==10
assert tests['regression']['counts']['tests']==tests['regression']['counts']['pass']==147 and tests['regression']['counts']['fail']==0
replay=load(O/'source-replay-results.json');assert replay['falco']['match']==4 and replay['falco']['drift']==0
save('test-results.json',tests);save('runtime-source-coverage.json',c)
rows=[];inventory=load(O/'remaining-eight-inventory.json');plan=load(R/'resources/security-manager/petclinic-adapter.json')
for row in c['sources']:
 id=row['sourceId'];i=next((x for x in inventory['sources'] if x['sourceId']==id),{});p=next((x for x in plan if ('semgrep-command-audit' if x['id']=='semgrep' else x['id'])==id),None)
 if p is None:
  assert id in ['provenance','build-provenance'];p={'command':'securityProvenance([:])' if id=='provenance' else 'securityBuildProvenance([:])'}
 observed=id in c['gate'];e=get(id+'.capture.json') if observed else None
 scope='CONTROLLED_ISOLATED_RUNTIME' if id=='sops' and observed else 'REAL_DEDICATED_NONRELEASE_NEW_ANALYSIS' if id=='sonarqube' and observed else 'ACTUAL_DEFAULT_UNENABLED_RETURN_ONLY' if id in ['provenance','build-provenance'] else 'REAL_DEDICATED_NONRELEASE_ORIGINAL_COMMAND' if observed else 'NOT_OBSERVED'
 rows.append({**row,'executionScope':scope,'factProducer':p['command'],'writeBoundary':i.get('factFormationTrace','Unchanged already-approved read-only/bounded path'),'collectorContract':row['contract'],'resultId':row['resultDigest'],'gateResultId':c['gate'].get(id,{}).get('resultDigest'),'oldDecision':c['gate'].get(id,{}).get('decision'),'policyStatus':c['gate'].get(id,{}).get('status'),'rawFactsPreserved':True if observed else None,'rawFactDigest':e['rawFactDigest'] if e else None,'blocker':None if observed else i.get('currentCaptureGap')})
save('source-fact-contracts.json',{'canonicalCount':16,'startingWired':8,'endingWired':len(captured),'sources':rows,'promotionExcluded':True,'noPreApprovalCycle':True})
save('source-preservation.json',{'baselineFiles':len(before),'allowedPreexistingFilesChanged':changed,'protectedFilesUnchanged':len(before)-len(changed),'unauthorizedChanges':[],'frozenSourceReferences':len(refs),'distinctFrozenPaths':len({x['path'] for x in refs}),'indexReferences':len(indices),'priorIterationSealUnchanged':True,'r2Unchanged':True,'productionWorkspaceUnchanged':True,'productionJob':{k:prod[k] for k in ['job','latestBuild','result','summarySha256']}})
leaks=[];scanned=[]
for p in O.rglob('*'):
 if p.is_file() and not p.is_symlink() and p.suffix in ['.json','.log']:
  t=p.read_text(errors='replace');scanned.append(str(p.relative_to(O)))
  if any(re.search(v,t) for v in [r'AGE-SECRET-KEY-1[A-Z0-9]{40,}',r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----',r'"token"\s*:\s*"eyJ[A-Za-z0-9_.-]{80,}']):leaks.append(str(p.relative_to(O)))
assert not leaks,leaks
save('secret-leakage-check.json',{'classification':'Pattern scan plus data minimization, not universal proof','files':scanned,'matches':[],'productionSecretReads':0,'productionAgeKeyReads':0,'rawScannerPayloadsPersisted':False,'isolatedPrivateRootRemoved':True})
verdict={k:'INCOMPLETE' for k in ['REAL_RUNTIME_FACT_CAPTURE','REAL_POLICY_OWNER','IMMUTABLE_ARTIFACT_RUNTIME','SUMMARY_V2_MIGRATION']};verdict.update({'canonical':16,'startingWired':8,'endingWired':len(captured),'newlyWired':[s['sourceId'] for s in captured if s['sourceId'] in ['sops','sonarqube']],'missing':c['missing'],'blocker':'PRE_WRITE_FACT_BOUNDARY_NOT_AVAILABLE for remaining external-write parents; complete current parent facts do not exist before first write. No write executed to fabricate completion.','sonarCompatibilityNegative':'DEFERRED_REAL_NEGATIVE_EVIDENCE','productionBuildsCreated':0,'validationBuildsCreated':[10,11,12],'release':0,'rollout':0,'summaryActivated':False})
save('verdict.json',verdict)
items=[
('canonical runtime source count','16，registry unchanged。'),('starting wired count','8。'),('exact remaining 8 inventory','remaining-eight-inventory.json；由实际 registry/plan/#9 coverage 派生。'),('risk classification','SOPS CONTROLLED_ISOLATED；Sonar LINEAGE_BLOCKED → fresh analysis attempt；其余六项 OTHER_BLOCKED。'),('new sources wired',', '.join(verdict['newlyWired'])),('ending wired count',str(len(captured))+'/16。'),('still blocked sources',', '.join(c['missing'])),('per-source execution scope','source-fact-contracts.json；SOPS CONTROLLED_ISOLATED_RUNTIME，非 live production。'),('per-source real fact producer','source-fact-contracts.json 中 exact production command；原 Gate/adapter 未改。'),('per-source write boundary','inventory 的 factFormationTrace/earliestAllPolicyFactsExist/beforeAnyExternalMutation。六个父阶段在写入后才形成完整事实。'),('per-source collector contract','source-fact-contracts.json；raw in memory + digest/report identity/actual process observations。'),('per-source evaluation count','已捕获来源均为 1；未观察来源为 null。'),('per-source resultId','source-fact-contracts.json resultId，完整 64 位 digest；无重复。'),('Gate resultId reuse','每项 resultId == gateResultId；最终脚本逐项断言。'),('local/read-only source results','原八项重验：六 PASS、两 actual default SKIPPED；无 enabled provenance 声明。'),('pre-write source results','六项 PRE_WRITE_FACT_BOUNDARY_NOT_AVAILABLE；未强行执行写操作。'),('Trivy result','未执行 mandatory Harbor POST scan；不能用现有 GET 替代父阶段事实。'),('ZAP result','未创建 scanner Pod 或扫描生产目标；单独 loopback 不能替代完整父阶段。'),('Cosign result','未解密生产签名包/签名/写 registry；verify-only 无法覆盖冻结 admission parent。'),('DefectDojo result','未 import/reimport/PATCH；现有 canned in-memory fixture 属单元兼容性，非当前运行事实。'),('Gitleaks result','原 source-gate 创建 Pod 后才产生隔离、native/classifier、cleanup 事实；本轮停止于写前。'),('Semgrep/Command Analysis result','原两阶段创建 Pod 后才形成完整事实；shared canonical source 保持一项，未双求值。'),('SOPS runtime result','真实隔离 positive → same owner；wrong-key/tool-missing → FAIL/FAIL，只是支持观察；positive preflight 不求值。见 sops/ 与 delivery receipt。'),('SOPS production Secret/key access count','0/0；仅复用公开工具二进制。'),('Sonar candidate lineage result','见 sonar-current-lineage.json（如捕获）及 coverage；绑定当前 build/source → fresh report-task → task → analysis → server conditions。runtime image 仅 audit context，不伪称 image-content attestation。'),('Sonar compatibility-debt status','DEFERRED_REAL_NEGATIVE_EVIDENCE；无历史真实负例升级。'),('pre-approval cycle check','无 PromotionResult 依赖；Semgrep alias 不增加 canonical 数。'),('wired/16 completeness',str(len(captured))+'/16，未补假 SKIPPED。'),('duplicate source check','16 个 canonical ID distinct；所有实际 result digests distinct。'),('artifact completeness','INCOMPLETE；实际完整性拒绝保留。'),('artifact identity/hash','未创建 COMPLETE artifact；各 source resultDigest 与构建输入 bundle 均可追溯。'),('aggregate Gate result','完整 aggregate 未产生；不得由部分来源推断全量 PASS。'),('Falco normal regression','baseline/final 两个 ACCEPTED_GATE_REPLAY 正常样本 PASS/PASS；#12 两阶段真实 PASS。'),('Falco 2-second regression','baseline/final 两个 2s 样本 old FAIL == Policy FAIL；Gate 同 digest；未恢复固定 +16s。'),('collector/owner tests','57/57 PASS。'),('candidate tests','40/40 PASS，disposable checkout。'),('Policy core','5/5 PASS。'),('contract checks','10/10 PASS。'),('Regression 147/147','真实 #12 147/147 PASS。'),('source-specific tests','Sonar 8、隔离 channel 10 包含在 57 中；SOPS 3 条受控路径+1 no-Policy preflight；27 auth checks。不增加权威 2202 compatibility count。'),('production V1 state','petclinic-ci #270 SUCCESS，V1 active；Summary SHA '+prod['summarySha256']),('source/hash preservation','source-preservation.json：冻结 source/index/r2/前轮 seal/production workspace 均匹配。'),('nodes/Lease cleanup','3 nodes Ready；production heavy Lease released；isolated owned 23 resources + private keys/token/root 清理，kind 保留。'),('Jenkins validation builds created','#10 baseline；#11 NoHttp prerequisite failure；#12 clean separate checkout + isolated channel。'),('production Jenkins builds created','0。'),('release count','0。'),('rollout count','0。'),('REAL_RUNTIME_FACT_CAPTURE','INCOMPLETE。'),('REAL_POLICY_OWNER','INCOMPLETE。'),('IMMUTABLE_ARTIFACT_RUNTIME','INCOMPLETE。'),('SUMMARY_V2_MIGRATION','INCOMPLETE。'),('exact blocker if still INCOMPLETE',verdict['blocker']),('exact next permitted action if all runtime verdicts VERIFIED','条件尚未成立。本轮 STOP。后续先审查六项完整父阶段的已授权执行边界/专用隔离方案；不得自动执行外部写入，不连接 Summary V2。')]
assert len(items)==53
text='# Remaining runtime facts：本轮结果\n\n'+ '\n\n'.join(str(i)+'. **'+name+'**\n\n   '+value for i,(name,value) in enumerate(items,1))
text+='\n\n```text\n'+'\n'.join(k+' = '+v for k,v in verdict.items() if k in ['REAL_RUNTIME_FACT_CAPTURE','REAL_POLICY_OWNER','IMMUTABLE_ARTIFACT_RUNTIME','SUMMARY_V2_MIGRATION'])+'\n```\n'
(O/'REPORT.md').write_text(text)
# Freeze files under this round only; symlink snapshots refer to old immutable
# evidence and are deliberately not copied, modified or traversed.
index={str(p.relative_to(O)):sha(p) for p in sorted(O.rglob('*')) if p.is_file() and not p.is_symlink() and p.name!='artifact-sha256.json' and '__pycache__' not in p.parts}
save('artifact-sha256.json',{'files':index});print(json.dumps({'sealedFiles':len(index),'captured':len(captured),'missing':c['missing'],'verdicts':{k:v for k,v in verdict.items() if k.startswith(('REAL_','IMMUTABLE_','SUMMARY_'))}}))
