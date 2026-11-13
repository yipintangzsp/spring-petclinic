from pathlib import Path
import json,hashlib,re,datetime,subprocess,sqlite3
R=Path.cwd();O=Path(__file__).resolve().parent;P=O.parent/'runtime-14-checkpoint-guard-review'
def read(n):return json.loads((O/n).read_text())
def save(n,x):(O/n).write_text(json.dumps(x,ensure_ascii=False,indent=2)+'\n')
sha=lambda b:hashlib.sha256(b).hexdigest()
checks=[]
for x in json.load(open('evidence/2026-11-02/summary-integration-readiness-recheck/source-integrity.json'))['checks']:
 actual=sha(Path(x['path']).read_bytes());assert actual==x['expected'],x['path'];checks.append({'path':x['path'],'expected':x['expected'],'actual':actual})
for p,h in read('implementation-before.json').items():assert sha(Path(p).read_bytes())==h,p
seals=[]
for name in ['runtime-14-checkpoint-guard-review','runtime-dojo-dependency-review','runtime-independent-boundaries','runtime-final-three','trivy-infra-repair','trivy-storage-expansion','trivy-pre-expansion','trivy-backup-capacity','trivy-external-storage-gate','runtime-boundary-followup']:
 b=O.parent/name;m=json.load(open(b/'evidence-sha256.json'))
 for p,h in m['files'].items():assert sha((b/p).read_bytes())==h,(name,p)
 seals.append({'path':str(b.relative_to(R)),'manifestSha256':sha((b/'evidence-sha256.json').read_bytes()),'verifiedFiles':len(m['files']),'failures':0})
save('source-hash-preservation.json',{'frozenReferences':len(checks),'uniqueFiles':len(set(x['path'] for x in checks)),'implementationFiles':len(read('implementation-before.json')),'failures':[],'checks':checks,'priorEvidenceSeals':seals,'compatibilityCount':2202,'compatibilityCountChanged':False})
counts={}
for name,expected in [('runtime-tests',143),('candidate-tests',40),('policy-core-tests',5),('regression-tests',147),('checkpoint-integrity-tests',12),('proxy-checkpoint-tests',8),('completeness-negative',11)]:
 t=(O/(name+'.log')).read_text();c={k:int(v) for k,v in re.findall(r'(?m)^(?:#|ℹ) (tests|pass|fail|cancelled|skipped|todo) (\d+)$',t)}
 assert c.get('tests')==expected and c.get('pass')==expected and c.get('fail')==0 and not c.get('skipped') and not c.get('cancelled'),(name,c);counts[name]=c
assert read('policy-contract.json')['ready'] and len(read('policy-contract.json')['checks'])==10
assert re.search(r'Ran 12 tests.*\n\nOK\s*$',(O/'semantic-analysis-tests.log').read_text(),re.S)
counts['policy-contract']={'tests':10,'pass':10,'fail':0};counts['semantic-analysis-only']={'tests':12,'pass':12,'fail':0}
save('test-counts.json',{'suites':counts,'total':sum(x['tests'] for x in counts.values()),'allPassed':True,'semanticImplementationChanged':False,'checkpointIntegrityScope':'Prior sealed FAILED checkpoint only; no new checkpoint reacceptance'})
a=read('trivy-storage-before.json');b=read('trivy-storage-after.json')
for k in ['pod','pvcs','volumes','statefulsetSpecSha256','environmentConfigurationSha256']:assert a[k]==b[k],k
assert a['nodeFs']['capacityBytes']==b['nodeFs']['capacityBytes']
def dbmeta(base,phase):
 t=(base/('trivy-filesystem-'+phase+'.stdout')).read_text();files={l.split('|')[0]:l for l in t.splitlines() if l.startswith('/home/scanner/.cache/trivy/') and len(l.split('|'))==7};hashes={p:h for h,p in re.findall(r'(?m)^([a-f0-9]{64})  (/home/scanner/.cache/trivy/(?:db|java-db)/metadata.json)$',t)}
 assert files and len(hashes)==2
 return {'files':files,'metadataSha256':hashes}
assert dbmeta(O,'before')==dbmeta(O,'after')==dbmeta(P,'after')
assert read('dojo-governance-before.json')==read('dojo-governance-after.json')==json.load(open(P/'dojo-governance-after.json'))
assert read('dojo-current-report-prerequisites-before.json')==read('dojo-current-report-prerequisites-after.json')
oldlocal=json.load(open(P/'local-config-before.json'));utm=oldlocal['files']['utmConfig'];assert sha(Path(utm['path']).read_bytes())==utm['sha256']
save('storage-config-preservation.json',{'classification':'READ_ONLY_CONFIG_AND_METADATA_COMPARISON','podAndPvcIdentityUnchanged':True,'statefulsetAndEnvConfigUnchanged':True,'filesystemCapacityUnchanged':True,'dbSizeBlocksDeviceInodeMtimeUnchanged':True,'dbMetadataHashesUnchanged':dbmeta(O,'after')['metadataSha256'],'matchesPreviousSealedDbMetadata':True,'fullDbContentShaRecomputed':False,'guaranteeLimit':'No updater invoked; metadata and metadata.json hashes preserved; not a new full SQLite content checksum','dojoSelectedMetadataUnchanged':True,'utmConfigByteHashUnchanged':True,'refreshes':0,'guardChanges':0,'storageChanges':0,'dojoWrites':0,'proxyWrites':0,'proxyRestarts':0})
observations=[read('observation-'+n+'.json') for n in ['T0','T1','T2','T3']]
stability={}
for i,f in enumerate(observations[0]['files']):
 stability[f['name']]={k:len({x['files'][i][k] for x in observations})==1 for k in ['rawSha256','allFieldsCanonicalAnalysisDigest','bytes','mtimeNs','inode']}
for x in observations:
 assert x['listenerCheckExit']==0 and '127.0.0.1:10808 (LISTEN)' in x['listenerOutput'] and '127.0.0.1:10812 (LISTEN)' in x['listenerOutput']
 assert not x['activeRuntimeSummary']['lanExposure']
 assert x['activeRuntimeSummary']==observations[0]['activeRuntimeSummary']
for f in observations[-1]['files']:assert sha(Path(f['path']).read_bytes())==f['rawSha256']
elapsed=(datetime.datetime.fromisoformat(observations[-1]['sampledAt'])-datetime.datetime.fromisoformat(observations[0]['sampledAt'])).total_seconds()
save('observation-comparison.json',{'samples':[{'sample':x['sample'],'at':x['sampledAt'],'files':x['files']} for x in observations],'elapsedSeconds':elapsed,'stabilityByField':stability,'currentRuntimeSummaryStableAtSamples':True,'currentMainListeners':['127.0.0.1:10808','127.0.0.1:10812'],'sampling':'Four sparse diagnostic samples across work/continuation; not continuous monitoring, no sleeps imposed','spanExceedsThirtyMinutes':elapsed>=1800,'automaticRefreshExecutionCovered':False,'guiMetadataReplacementObserved':not stability['guiSourceMutable']['inode'],'historicalSemanticEquivalenceProven':False,'acceptanceWindow':False,'warning':'Later stability cannot explain historical drift. GUI metadata change is recorded, not treated as a failed product test or excluded by a new checkpoint rule.'})
j=next(j for j in read('live-jenkins-final.json')['jobs'] if j['job']=='petclinic-ci');assert j['latestBuild']==270 and j['result']=='SUCCESS' and not j['building'] and j['summarySha256']=='ec9ee51a06d4b9f61c6c0eaf50b374d1e25e6d3ca687908b7596d3a2c794f5d8'
live=read('live-protected-final.json');health=read('health-final.json');nodes=read('node-lease-postflight.json')['nodes']
assert live['argocdSync']=='Synced' and live['argocdHealth']=='Healthy' and live['deploymentSpecUnchanged'] and live['http']['status']==200
assert health['deployment']['generation']==175 and health['deployment']['revision']=='164' and health['deployment']['ready']==3
assert len(nodes)==3 and all(next(c['status'] for c in n['conditions'] if c['type']=='Ready')=='True' for n in nodes)
save('protected-state.json',{'productionJenkins':{'build':270,'result':j['result'],'newBuildsTriggered':0},'v1SummarySha256':j['summarySha256'],'v1Unchanged':True,'policyBaselineUnchanged':True,'frozenGateSourceHashesUnchanged':True,'localImplementationUnchanged':True,'nodesReady':[n['name'] for n in nodes],'petclinicReady':3,'readyEndpoints':3,'HTTP':200,'argocdSync':live['argocdSync'],'argocdHealth':live['argocdHealth'],'deploymentGeneration':175,'deploymentRevision':'164','release':0,'rollout':0,'proxyAgentWrites':0,'proxyRestarts':0,'current10808StillLoopback':True,'entireHistoricalProxySemantics':'UNKNOWN','TrivyGuardChanges':0,'TrivyRefreshes':0,'DojoWrites':0,'CosignNewRuns':0,'validationArchivesUnchanged':read('validation-archives-recheck.json')})
changed=observations[-1]['files'][0]['path']
verdict={'V2RAYN_CHANGED_FILE':changed,'V2RAYN_DRIFT_CLASS':'UNEXPLAINED','PROXY_RUNTIME_SEMANTICS_CHANGED':'UNKNOWN','CHECKPOINT_HASH_CONTRACT':'REQUIRES_SEMANTIC_NORMALIZATION','RUNTIME_14_OF_16_CHECKPOINT':'FAILED','TRIVY_DISK_GUARD_ORIGIN':'CALCULATED_FROM_FILESYSTEM_STATE','TRIVY_DISK_GUARD_VALIDITY':'GUARD_REQUIRES_REVALIDATION','TRIVY_DISK_GUARD_REVALIDATION_REQUIRED':'YES','TRIVY_STORAGE_ENVIRONMENT':'ENVIRONMENT_BLOCKED','TRIVY_RUNTIME_FACT_CAPTURE':'INCOMPLETE','DEFECTDOJO_RUNTIME_DEPENDENCY':'BLOCKED_BY_TRIVY','DEFECTDOJO_RUNTIME_FACT_CAPTURE':'INCOMPLETE','COSIGN_RUNTIME_FACT_CAPTURE':'VERIFIED','FINAL_WIRED_CAPABILITY':'14/16','REAL_RUNTIME_FACT_CAPTURE':'INCOMPLETE','REAL_POLICY_OWNER':'INCOMPLETE','IMMUTABLE_ARTIFACT_RUNTIME':'INCOMPLETE','SUMMARY_V2_MIGRATION':'INCOMPLETE'}
save('verdict.json',verdict)
save('stop-receipt.json',{'status':'STOPPED_AT_UNEXPLAINED_PROXY_DRIFT','checkpointReacceptanceAttempted':False,'checkpointImplementationChanged':False,'oldCheckpointAnchor':read('checkpoint-digest.json'),'resumeAllowed':False,'remainingBlocker':'Pre-drift config content/complete trusted semantics and historical writer/trigger proof unavailable','nextPermittedAction':'Read-only retrieval of trusted old content and historical write evidence. Any new future baseline requires explicit authorization, cannot retroactively pass the failed checkpoint.','releases':0,'rollouts':0,'newBuilds':0,'TrivyDbRefreshes':0,'DojoWrites':0,'summaryV2Activation':0,'pluginRegistryImplementation':0,'resultRouterImplementation':0,'completeRuntimeArtifactGenerated':False})
save('git-identity.json',{'branch':subprocess.check_output(['git','branch','--show-current'],text=True).strip(),'HEAD':subprocess.check_output(['git','rev-parse','HEAD'],text=True).strip(),'newCommits':0,'trackedFilesChangedByThisReview':0,'preexistingDirtyFilesPreserved':True})
print(json.dumps({'localChecks':sum(x['tests'] for x in counts.values()),'frozenReferences':len(checks),'uniqueFrozenFiles':len(set(x['path'] for x in checks)),'implementationFiles':len(read('implementation-before.json')),'sealedPriorFiles':sum(s['verifiedFiles'] for s in seals),'observationSeconds':elapsed,'checkpoint':'FAILED','resumeAllowed':False}))
