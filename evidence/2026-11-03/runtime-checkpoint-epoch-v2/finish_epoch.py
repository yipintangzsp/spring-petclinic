"""Build one versioned checkpoint; preserve old epoch and incomplete capabilities."""
from pathlib import Path
import json,re
from epoch_proxy import sha,validate_samples
from epoch_engine import verify_epoch,validate_blocker,references
O=Path(__file__).resolve().parent;R=O.parents[2];P=O.parent/'runtime-14-checkpoint-guard-review'
def read(n):return json.loads((O/n).read_text())
def save(n,x):(O/n).write_text(json.dumps(x,ensure_ascii=False,indent=2)+'\n')
def ref(p):return {'path':str(p.relative_to(R)),'sha256':sha(p.read_bytes())}
if (O/'checkpoint.json').exists():raise SystemExit('REFUSE_CHECKPOINT_OVERWRITE')
old=json.load(open(P/'checkpoint.json'));start=read('epoch-start.json');matrix=read('source-hash-matrix.json')
counts={}
for name,n in [('runtime-tests',143),('candidate-tests',40),('completeness-negative',11),('policy-core-tests',5),('regression-tests',147)]:
 t=(O/(name+'.log')).read_text();r={k:int(v) for k,v in re.findall(r'(?m)^(?:#|ℹ) (tests|pass|fail|skipped|cancelled) (\d+)$',t)};assert r.get('tests')==r.get('pass')==n and r.get('fail')==r.get('skipped')==r.get('cancelled')==0,(name,r);counts[name]=r
for name,n in [('proxy-tests',25),('epoch-tests',19)]:
 assert re.search(r'Ran '+str(n)+r' tests.*\n\nOK\s*$',(O/(name+'.log')).read_text(),re.S);counts[name]={'tests':n,'pass':n,'fail':0}
assert read('policy-contract.json')['ready'] and len(read('policy-contract.json')['checks'])==10
counts['policy-contract']={'tests':10,'pass':10,'fail':0};save('test-counts-before-integrity.json',counts)
for p,h in {**matrix['implementationHashes'],**matrix['frozenGateHashes']}.items():assert sha((R/p).read_bytes())==h,p
for r in start['historicalFailedCheckpointRefs']['priorSeals']:
 b=R/r['path'];assert sha(b.read_bytes())==r['sha256'];m=json.loads(b.read_text())
 for p,h in m['files'].items():assert sha((b.parent/p).read_bytes())==h,(str(b),p)
j=next(x for x in read('live-jenkins-final.json')['jobs'] if x['job']=='petclinic-ci');live=read('live-protected-final.json');health=read('health-final.json');nodes=read('node-lease-postflight.json')['nodes']
assert j['latestBuild']==270 and j['result']=='SUCCESS' and not j['building'] and j['summarySha256']==old['productionJenkinsIdentity']['summarySha256']
assert len(nodes)==3 and all(next(c['status'] for c in n['conditions'] if c['type']=='Ready')=='True' for n in nodes)
assert live['argocdSync']=='Synced' and live['argocdHealth']=='Healthy' and live['http']['status']==200 and live['deploymentSpecUnchanged']
assert health['deployment']['ready']==3 and health['deployment']['generation']==175 and health['deployment']['revision']=='164'
def dbmeta(base):
 t=(base/'trivy-filesystem-after.stdout').read_text();files={l.split('|')[0]:l for l in t.splitlines() if l.startswith('/home/scanner/.cache/trivy/') and len(l.split('|'))==7};hashes={p:h for h,p in re.findall(r'(?m)^([a-f0-9]{64})  (/home/scanner/.cache/trivy/(?:db|java-db)/metadata.json)$',t)};assert files and len(hashes)==2;return {'files':files,'metadataHashes':hashes}
before=O.parent/'runtime-proxy-history-delta';assert dbmeta(O)==dbmeta(before)
for k in ['pod','pvcs','volumes','statefulsetSpecSha256','environmentConfigurationSha256']:assert read('trivy-storage-after.json')[k]==json.load(open(before/'trivy-storage-after.json'))[k]
assert read('dojo-governance-after.json')==json.load(open(before/'dojo-governance-after.json'))
protected={'productionUnchanged':True,'jenkinsBuild':270,'jenkinsResult':'SUCCESS','v1SummarySha256':j['summarySha256'],'nodesReady':[n['name'] for n in nodes],'petclinicReady':3,'readyEndpoints':3,'HTTP':200,'argocd':'Synced/Healthy','productionSignaturePolicyUnchanged':True,'CosignProductionSecretReads':0,'CosignValidationArchivesUnchanged':True,'TrivyStorageAndDbMetadataUnchanged':True,'fullDbContentChecksumRecomputed':False,'DojoSelectedMetadataUnchanged':True,'proxyAgentWrites':0,'proxyAgentRestarts':0,'release':0,'rollout':0,'newBuilds':0}
save('protected-state.json',protected)
blockers=[]
for source,typ,state,reason,origin in [('trivy','ENVIRONMENT','ENVIRONMENT_BLOCKED','Storage/backup capacity unavailable; guard unchanged and requires revalidation',old['trivyBlockerReceipt']),('defectdojo','DEPENDENCY','BLOCKED_BY_TRIVY','Hard dependency on current Trivy-native report, currently absent',old['dojoDependencyReceipt'])]:
 b={'kind':'EngineeringBlockerReceipt','sourceId':source,'blockerType':typ,'state':state,'reason':reason,'runtimeResult':None,'runtimeResultPresent':False,'policyResult':None,'policyEvaluations':0,'blockerIsNotPolicyResult':True,'frozenOriginalReceipt':origin,'guardThresholdChanges':0,'newExecutions':0}
 validate_blocker(b);p=O/('blocker-'+source+'.json');save(p.name,b);blockers.append({'sourceId':source,'blockerType':typ,'receipt':ref(p)})
contract=read('proxy-contract.json');samples=[read('samples/T'+str(i)+'.json') for i in range(5)];stability=validate_samples(samples,contract);assert stability==read('stability-result.json')
accepted=stability['status']=='VERIFIED'
c={'checkpointSchemaVersion':2,'kind':'CurrentStateRuntimeCapabilityEpochCheckpoint','epochId':start['epochId'],'createdAt':start['createdAt'],'gitRevision':start['gitRevision'],'gitBranch':start['gitBranch'],'pipelineState':old['productionJenkinsIdentity'],'v1SummaryIdentity':{'summarySha256':j['summarySha256'],'producer':{'path':old['v1SummaryProducer']['path'],'sha256':old['v1SummaryProducer']['liveSha256']}},'policyIdentity':old['policyBaseline'],'canonicalSourceManifest':old['sourceManifest'],'runtimeCapabilities':old['sources'],'acceptedWiredCount':14,'blockerReceipts':blockers,'proxyBaseline':ref(O/'samples/T0.json'),'proxySemanticDigest':samples[0].get('proxySemanticDigest'),'proxyContract':ref(O/'proxy-contract.json'),'proxyObservations':[ref(O/('samples/T'+str(i)+'.json')) for i in range(5)],'stabilityEvidence':ref(O/'stability-result.json'),'implementationHashes':matrix['implementationHashes'],'sourceHashMatrix':ref(O/'source-hash-matrix.json'),'sourcePreservationVerified':True,'historicalContinuity':'NOT_PROVEN','newEpochBaseline':'CURRENT_STATE_ONLY','oldCheckpointStatus':'FAILED','oldCheckpointReason':'UNEXPLAINED_PROXY_DRIFT','historicalFailedCheckpointRefs':start['historicalFailedCheckpointRefs'],'oldCheckpointIntegrity':ref(O/'old-checkpoint-integrity.json'),'protectedState':ref(O/'protected-state.json'),'acceptanceStatus':'VERIFIED' if accepted else 'FAILED','acceptanceScope':'Current 14/16 capability wiring checkpoint only; original source branches/bindings retained, no new same-run scanner execution','runtimeVerdicts':old['currentRuntimeVerdicts'],'sameRun16Proven':False,'completeRuntimeArtifactGenerated':False,'newPolicyEvaluations':0,'release':0,'rollout':0,'guardDebt':{'TRIVY_DISK_GUARD_ORIGIN':'CALCULATED_FROM_FILESYSTEM_STATE','TRIVY_DISK_GUARD_VALIDITY':'GUARD_REQUIRES_REVALIDATION','TRIVY_DISK_GUARD_REVALIDATION_REQUIRED':'YES','thresholdUnchanged':'filesystem_capacity * 15% + 12GiB (8GiB + 4GiB)'},'dojoDebt':{'DOJO_INPUT_DEPENDENCY':'TRIVY_HARD_DEPENDENCY','DOJO_DECOUPLING_REQUIRED':'YES'},'resumeContract':{'resumeAllowed':accepted,'resumeFromWiredCount':14,'TrivyAutomaticResumeAllowed':False,'TrivyCondition':'Environment capacity/backup condition changes, or separately approved guard revalidation; not resumed here','DojoAutomaticResumeAllowed':False,'DojoCondition':'Current Trivy report exists or separately authorized decoupling stage','SummaryV2Allowed':False,'automaticWorkAfterThisEpoch':False}}
save('checkpoint.json',c)
files={str((O/'checkpoint.json').relative_to(R)):sha((O/'checkpoint.json').read_bytes())}
for r in references(c):files[r['path']]=r['sha256']
for p,h in {**matrix['implementationHashes'],**matrix['frozenGateHashes']}.items():files[p]=h
for p in [O/'epoch-start.json',O/'proxy-tests.log',O/'epoch-tests.log',O/'protected-state.json',O/'validation-archives-recheck.json',O/'active-v1-selection-identity.json']:files[str(p.relative_to(R))]=sha(p.read_bytes())
save('checkpoint-integrity-manifest.json',{'schemaVersion':2,'epochId':start['epochId'],'files':files})
anchor={'checkpointPath':str((O/'checkpoint.json').relative_to(R)),'checkpointSha256':sha((O/'checkpoint.json').read_bytes()),'integrityManifestPath':str((O/'checkpoint-integrity-manifest.json').relative_to(R)),'integrityManifestSha256':sha((O/'checkpoint-integrity-manifest.json').read_bytes())};save('checkpoint-digest.json',anchor)
result=verify_epoch(R,anchor['checkpointPath'],anchor['checkpointSha256'],anchor['integrityManifestPath'],anchor['integrityManifestSha256']);save('checkpoint-verification.json',result)
print(json.dumps(result))
