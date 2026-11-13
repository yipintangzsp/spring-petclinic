from pathlib import Path
import json,hashlib,re,subprocess
R=Path.cwd();O=Path(__file__).resolve().parent;P=O.parent/'runtime-proxy-drift-review'
sha=lambda b:hashlib.sha256(b).hexdigest()
read=lambda n:json.loads((O/n).read_text())
save=lambda n,x:(O/n).write_text(json.dumps(x,ensure_ascii=False,indent=2)+'\n')
checks=[]
for x in json.load(open('evidence/2026-11-02/summary-integration-readiness-recheck/source-integrity.json'))['checks']:
 actual=sha(Path(x['path']).read_bytes());assert actual==x['expected'],x['path'];checks.append({'path':x['path'],'expected':x['expected'],'actual':actual})
impl=read('implementation-before.json')
for p,h in impl.items():assert sha(Path(p).read_bytes())==h,p
seals=[]
for name in ['runtime-proxy-drift-review','runtime-14-checkpoint-guard-review','runtime-dojo-dependency-review','runtime-independent-boundaries','runtime-final-three','trivy-infra-repair','trivy-storage-expansion','trivy-pre-expansion','trivy-backup-capacity','trivy-external-storage-gate','runtime-boundary-followup']:
 b=O.parent/name;m=json.load(open(b/'evidence-sha256.json'))
 for p,h in m['files'].items():assert sha((b/p).read_bytes())==h,(name,p)
 seals.append({'path':str(b.relative_to(R)),'manifestSha256':sha((b/'evidence-sha256.json').read_bytes()),'verifiedFiles':len(m['files']),'failures':0})
save('source-hash-preservation.json',{'frozenReferences':len(checks),'uniqueFiles':len(set(x['path'] for x in checks)),'implementationFiles':len(impl),'checks':checks,'failures':[],'oldEvidenceSeals':seals,'compatibilityCount':2202,'compatibilityCountChanged':False,'checkpointContractChanges':0})
counts={}
for name,expected in [('runtime-tests',143),('candidate-tests',40),('completeness-negative',11),('policy-core-tests',5),('regression-tests',147),('checkpoint-integrity-tests',12)]:
 t=(O/(name+'.log')).read_text();c={k:int(v) for k,v in re.findall(r'(?m)^(?:#|ℹ) (tests|pass|fail|cancelled|skipped|todo) (\d+)$',t)};assert c.get('tests')==c.get('pass')==expected and c.get('fail')==c.get('skipped')==c.get('cancelled')==0,(name,c);counts[name]=c
assert read('policy-contract.json')['ready'] and len(read('policy-contract.json')['checks'])==10
t=(O/'history-tools-tests.log').read_text();assert re.search(r'Ran 16 tests.*\n\nOK\s*$',t,re.S)
timeline=read('drift-timeline.json');assert len(timeline['checks'])==8 and all(c['result']=='PASS' for c in timeline['checks'])
counts.update({'policy-contract':{'tests':10,'pass':10,'fail':0},'evidence-search-parser-timeline-unit':{'tests':16,'pass':16,'fail':0},'real-timeline-consistency':{'checks':8,'pass':8,'fail':0}})
save('test-counts.json',{'suites':counts,'totalTestsAndChecks':sum(v.get('tests',v.get('checks',0)) for v in counts.values()),'allPassed':True,'initialHelperFailuresRetained':['test-harness-initial-failure.json','history-tools-tests.initial-failure.log'],'noGateOrCheckpointContractChanged':True,'noRealCompleteArtifactGenerated':True})
def dbmeta(base):
 t=(base/'trivy-filesystem-after.stdout').read_text();f={l.split('|')[0]:l for l in t.splitlines() if l.startswith('/home/scanner/.cache/trivy/') and len(l.split('|'))==7};h={p:x for x,p in re.findall(r'(?m)^([a-f0-9]{64})  (/home/scanner/.cache/trivy/(?:db|java-db)/metadata.json)$',t)};assert f and len(h)==2;return {'files':f,'metadataSha256':h}
assert dbmeta(O)==dbmeta(P)
a=read('trivy-storage-after.json');b=json.load(open(P/'trivy-storage-after.json'))
for k in ['pod','pvcs','volumes','statefulsetSpecSha256','environmentConfigurationSha256']:assert a[k]==b[k],k
assert a['nodeFs']['capacityBytes']==b['nodeFs']['capacityBytes']
assert read('dojo-governance-after.json')==json.load(open(P/'dojo-governance-after.json'))
assert read('dojo-current-report-prerequisites-after.json')==json.load(open(P/'dojo-current-report-prerequisites-after.json'))
assert read('config-candidates.json')['oldMatchingCount']==read('session-evidence-search.json')['oldMatchingCount']==read('additional-archive-search.json')['oldMatchingCount']==0
jobs=read('jenkins-archive-search.json')['jobs'];assert not any(b['candidateArtifacts'] for j in jobs for b in j['builds'])
runtime=read('observation-T0.json');assert runtime['files'][0]['rawSha256']=='b702ff16eae6f27f0cc84e11e59565b1dded8e2c197778f0b888297266593d62'
assert not runtime['activeRuntimeSummary']['lanExposure']
processes=read('process-inventory.json')['processes']
latest=read('current-post-additional-drift.json');additional=read('additional-observed-drift.json')
assert latest['sha256']==additional['current']['sha256'] and not latest['currentSemantics']['lanExposure']
assert latest['notANewBaseline'] and additional['agentWrites']==additional['agentRestarts']==0
assert any(p['usesMainConfig'] and p['listenerExit']==0 and '127.0.0.1:10808 (LISTEN)' in p['listenerOutput'] for p in latest['processes'])
j=next(x for x in read('live-jenkins-final.json')['jobs'] if x['job']=='petclinic-ci');assert j['latestBuild']==270 and j['result']=='SUCCESS' and not j['building'] and j['summarySha256']=='ec9ee51a06d4b9f61c6c0eaf50b374d1e25e6d3ca687908b7596d3a2c794f5d8'
live=read('live-protected-final.json');health=read('health-final.json');nodes=read('node-lease-postflight.json')['nodes'];assert live['argocdSync']=='Synced' and live['argocdHealth']=='Healthy' and live['http']['status']==200
assert health['deployment']['generation']==175 and health['deployment']['revision']=='164' and health['deployment']['ready']==3
assert len(nodes)==3 and all(next(c['status'] for c in n['conditions'] if c['type']=='Ready')=='True' for n in nodes)
save('protected-state.json',{'productionJenkinsBuild':270,'result':'SUCCESS','v1SummarySha256':j['summarySha256'],'v1ActiveUnchanged':True,'frozenPolicyAndGateSourcesUnchanged':True,'proxyAgentWrites':0,'proxyAgentRestarts':0,'runtimeConfigByteHashUnchangedFromPriorPostDrift':False,'additionalObservedProxyDrift':'additional-observed-drift.json','latestRuntimeObservation':'current-post-additional-drift.json','currentRuntimeHash':latest['sha256'],'mainXrayIdentityChangedExternally':True,'guiConfigHash':runtime['files'][1]['rawSha256'],'guiConfigHashChangedSincePriorReview':runtime['files'][1]['rawSha256']!=json.load(open(P/'observation-T3.json'))['files'][1]['rawSha256'],'proxyChangeCause':'UNKNOWN_NOT_AGENT_WRITE; no unchanged or safe proxy state claim','trivyStorageConfigUnchanged':True,'trivyDbFileMetadataAndMetadataHashesUnchanged':True,'fullDbContentShaRecomputed':False,'dojoSelectedMetadataUnchanged':True,'cosignValidationArchivesUnchanged':True,'nodesReady':[n['name'] for n in nodes],'petclinicReady':3,'readyEndpoints':3,'HTTP':200,'argocd':'Synced/Healthy','deploymentGeneration':175,'deploymentRevision':164,'newBuilds':0,'release':0,'rollout':0})
verdict={'TRUSTED_PRE_DRIFT_CONFIG':'NOT_FOUND','TRUSTED_PRE_DRIFT_RUNTIME_EVIDENCE':'FOUND','FILE_WRITER_ATTRIBUTION':'WEAK','V2RAYN_GUI_REWRITE_EVIDENCE':'WEAK','PROXY_SEMANTIC_DIFF':'UNKNOWN','HISTORICAL_PROXY_DRIFT_EVIDENCE':'INSUFFICIENT','V2RAYN_DRIFT_CLASS':'UNEXPLAINED','PROXY_RUNTIME_SEMANTICS_CHANGED':'UNKNOWN','RUNTIME_14_OF_16_CHECKPOINT':'FAILED','FINAL_WIRED_CAPABILITY':'14/16','REAL_RUNTIME_FACT_CAPTURE':'INCOMPLETE','REAL_POLICY_OWNER':'INCOMPLETE','IMMUTABLE_ARTIFACT_RUNTIME':'INCOMPLETE','SUMMARY_V2_MIGRATION':'INCOMPLETE'}
save('verdict.json',verdict)
save('stop-receipt.json',{'status':'STOPPED_HISTORICAL_EVIDENCE_INSUFFICIENT','newCleanBaselineRequiredToProceedWithoutHistoricalEvidence':'YES','nextAllowedStrategy':'ESTABLISH_NEW_CLEAN_BASELINE','baselineResetPerformed':False,'baselineResetRequiresExplicitUserApproval':True,'futureRequirements':['Fully document current semantics','Bounded stability observations','New checkpoint epoch/version','Permanently retain unexplained historical drift','Never describe old drift as safe'],'checkpointContractChanged':False,'checkpointReaccepted':False,'resumeAllowed':False,'newCompleteArtifactGenerated':False,'proxyWrites':0,'proxyRestarts':0,'TrivyGuardChanges':0,'TrivyDbRefreshes':0,'DojoWrites':0,'release':0,'rollout':0})
save('git-identity.json',{'branch':subprocess.check_output(['git','branch','--show-current'],text=True).strip(),'HEAD':subprocess.check_output(['git','rev-parse','HEAD'],text=True).strip(),'newCommits':0,'onlyNewReviewEvidenceWritten':True,'preexistingTrackedDirtyFilesPreserved':True})
print(json.dumps({'checks':sum(v.get('tests',v.get('checks',0)) for v in counts.values()),'frozenReferences':len(checks),'implementationFiles':len(impl),'priorSealedFiles':sum(s['verifiedFiles'] for s in seals),'checkpoint':'FAILED','newBaselineEstablished':False}))
