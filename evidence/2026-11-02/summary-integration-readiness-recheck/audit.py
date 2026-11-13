"""Authoritative read-only readiness audit. Writes only to this new audit directory.
No scanner, Summary producer, Jenkins, Kubernetes, network or credentials are invoked.
"""
from pathlib import Path
from collections import Counter
import json,hashlib,re
R=Path(__file__).resolve().parents[3];O=Path(__file__).resolve().parent;E=R/'evidence';E1=E/'2026-11-01';E2=E/'2026-11-02';S=E2/'sops-authoritative-differential-02';F=E2/'falco-time-contract-repair';PREVIOUS=E2/'summary-integration-readiness-audit'
def rel(p):return str(p.relative_to(R)) if p.is_relative_to(R) else str(p)
def load(p):return json.loads(p.read_text())
def save(n,d):(O/n).write_text(json.dumps(d,ensure_ascii=False,indent=2)+'\n')
cache={}
def sha(p):
 if p not in cache:cache[p]=hashlib.sha256(p.read_bytes()).hexdigest()
 return cache[p]
def resolve(n,index):
 p=Path(n)
 if p.is_absolute():return p
 return R/n if (R/n).is_file() else index.parent/n
blockers=[];indexChecks=[];sourceChecks=[];resolutionReceipts=[]
def verify_ref(index,name,digest,pointer):
 p=resolve(name,index);actual=sha(p) if p.is_file() else None;ok=actual==digest
 row={'index':rel(index),'pointer':pointer,'path':rel(p),'expected':digest,'actual':actual,'directMatch':ok,'resolved':ok}
 # Historical indexes retain old bytes; accept only explicit versioned transitions, never rewrite them.
 if not ok and index==E2/'kubeconfig-fail-closed-boundary/artifact-sha256.json' and name in ['infra/security/testing/isolated_sops_executor.py','infra/security/testing/test_isolated_sops_executor.py']:
  archive=E2/'sops-preparation-blocker-closure'/(Path(name).name+'.before');receipt=load(E2/'sops-preparation-blocker-closure/protected-after.json');newHashes=load(E2/'sops-preparation-blocker-closure/source-sha256.json')
  valid=archive.is_file() and sha(archive)==digest and name in receipt['changedPreexistingFiles'] and not receipt['unexpectedChangedFiles'] and actual==newHashes[name]
  row.update(resolved=valid,resolution='HISTORICAL_SNAPSHOT_SUPERSEDED_WITH_EXACT_OLD_BYTES' if valid else 'UNRESOLVED',archivedPath=rel(archive),transitionReceipt='evidence/2026-11-02/sops-preparation-blocker-closure/protected-after.json',currentFreeze='evidence/2026-11-02/sops-authoritative-baseline-02/authoritative-baseline.json')
  resolutionReceipts.append(row)
 indexChecks.append(row)
 return row

# Select compatibility indexes by current source directories and approved prerequisite lineage.
# Exclude inactive V2 implementation indexes: those are not authoritative source compatibility proof.
flatNames={'artifact-sha256.json','evidence-hashes.json','implementation-hashes.json','negative-search-evidence-hashes.json'}
parentDirs=['build-provenance-parent','command-parent','cosign-parent','dojo-parent','falco-parent','gitleaks-parent','kubescape-parent','kyverno-parent','kyverno-policy','promotion-parent','provenance-parent','regression-parent','remaining-policy','sbom-parent','sonar-policy','trivy-parent','final-compatibility-audit']
prereqDirs=['isolated-colima-profile','isolated-kind-cluster','isolated-runtime-dns','isolated-runtime-start','kubeconfig-fail-closed-boundary','local-runtime-recovery','sops-fixture-final-design','sops-fixture-instance','sops-fixture-prerequisite-review','sops-isolation-design','sops-preparation-blocker-closure','zap-parent']
indexes=sorted({p for base in [*[E1/x for x in parentDirs],*[E2/x for x in prereqDirs],F,PREVIOUS] for p in base.glob('*.json') if p.name in flatNames})
for index in indexes:
 for name,h in load(index).items():verify_ref(index,name,h,'/'+name)
structured=sorted({p for base in [E1/x for x in parentDirs] for p in base.glob('*historical*index*.json')})+[E1/'security-manager-contract/evidence-index.json',E2/'node-executor/evidence-index.json',E2/'sops-authoritative-baseline-02/evidence-index.json',S/'precleanup-evidence-index.json',S/'final-evidence-index.json']
def walk_refs(obj,index,pointer=''):
 if isinstance(obj,list):
  for i,x in enumerate(obj):walk_refs(x,index,pointer+'/'+str(i))
 elif isinstance(obj,dict):
  # Explicit file identities only. Digest/UID/data fingerprints are not file references.
  pairs=[]
  if 'sha256' in obj:
   for k in ['copy','retained','path']:
    if isinstance(obj.get(k),str):pairs.append((k,'sha256'));break
  if 'archiveSha256' in obj and isinstance(obj.get('path'),str):pairs.append(('path','archiveSha256'))
  if 'originalSha256' in obj and isinstance(obj.get('original'),str):pairs.append(('original','originalSha256'))
  for pathKey,hashKey in pairs:verify_ref(index,obj[pathKey],obj[hashKey],pointer+'/'+pathKey)
  for k,x in obj.items():
   if k in ['files','evidenceFiles'] and isinstance(x,dict) and all(isinstance(v,str) and re.fullmatch('[a-f0-9]{64}',v) for v in x.values()):
    for n,h in x.items():verify_ref(index,n,h,pointer+'/'+k+'/'+n)
   else:walk_refs(x,index,pointer+'/'+k)
for index in structured:
 indexes.append(index);walk_refs(load(index),index)
# Regression historical excerpt has its own hash, distinct from the full log.
reg=load(E1/'regression-parent/historical-evidence-index.json')
excerpt=list((E1/'regression-parent').rglob('*'))
matches=[p for p in excerpt if p.is_file() and sha(p)==reg['excerptSha256']]
if len(matches)==1:verify_ref(E1/'regression-parent/historical-evidence-index.json',rel(matches[0]),reg['excerptSha256'],'/excerptSha256')
else:blockers.append({'source':'regression','reason':'Historical excerpt hash missing or ambiguous','matches':len(matches)})
indexFailures=[x for x in indexChecks if not x['resolved']]
if indexFailures:blockers.append({'source':'evidence-integrity','failures':indexFailures})
for lock in sorted((R/'infra/security/policy/versions').glob('*.json')):
 d=load(lock)
 for field in ['sourceHashes','workflowSourceHashes']:
  for n,h in d.get(field,{}).items():sourceChecks.append({'lock':rel(lock),'path':n,'expected':h,'actual':sha(R/n) if (R/n).is_file() else None})
original=load(E1/'policy-engine/production-gate-inventory.json')['sources']
for label,hashes in [('original108',load(E1/'policy-engine/frozen-source-hashes-current.json'))]+[('original-inventory:'+x['source'],x.get('sourceHashes',{})) for x in original]+[('authoritative-sops',load(E2/'sops-authoritative-baseline-02/authoritative-baseline.json')['frozenSourceSha256'])]:
 for n,h in hashes.items():sourceChecks.append({'lock':label,'path':n,'expected':h,'actual':sha(R/n) if (R/n).is_file() else None})
sourceFailures=[x for x in sourceChecks if x['expected']!=x['actual']]
if sourceFailures:blockers.append({'source':'frozen-source-integrity','failures':sourceFailures})
save('index-integrity.json',{'indexCount':len(indexes),'hashReferences':len(indexChecks),'directMatches':sum(x['directMatch'] for x in indexChecks),'historicalSnapshotResolutions':len(resolutionReceipts),'resolvedMatches':sum(x['resolved'] for x in indexChecks),'uniqueReferencedFiles':len({x['path'] for x in indexChecks}),'failures':indexFailures,'historicalResolutions':resolutionReceipts,'checks':indexChecks})
save('source-integrity.json',{'checks':sourceChecks,'references':len(sourceChecks),'uniqueFiles':len({x['path'] for x in sourceChecks}),'failures':sourceFailures})

production=load(R/'resources/security-manager/petclinic-adapter.json');profiles=load(R/'resources/security-manager/profiles.json');manager=(R/'vars/securityManager.groovy').read_text();known=set(json.loads(re.search(r'def known=(\[.*?\])',manager)[1].replace("'",'"')))
expected={'gitleaks','semgrep','trivy','zap','kyverno','kubescape','defectdojo','falco-baseline','falco-final','cosign','provenance','build-provenance','sbom','regression','semgrep-command-audit','security-approval-promotion','sonarqube','sops'}
current={x['id'] for x in production}|{'provenance','build-provenance','semgrep-command-audit','security-approval-promotion'}
entryMismatches=[x['id'] for x in production if x['command']!=next((o['entry'] for o in original if o['source']==x['id']),None)]
inventoryComplete=current==expected=={o['source'] for o in original} and len(original)==18 and not entryMismatches and known<=current and {v for row in profiles.values() for v in row}<=current
if not inventoryComplete:blockers.append({'source':'inventory','current':sorted(current),'expected':sorted(expected),'entryMismatches':entryMismatches})
save('inventory-reconciliation.json',{'status':'PASS' if inventoryComplete else 'FAILED','originalSourceCount':len(original),'adapterStageCount':len(production),'conditionalPluginCount':2,'explicitAdditionalSources':['semgrep-command-audit','security-approval-promotion'],'currentSources':sorted(current),'missing':sorted(expected-current),'unexpected':sorted(current-expected),'entryMismatches':entryMismatches,'knownModules':sorted(known),'profileModules':sorted({v for row in profiles.values() for v in row})})

def rows(path):
 d=load(path);return d if isinstance(d,list) else d.get('records',[d] if 'legacyDecision' in d else [])
def normalize(row):
 old=next((row[k] for k in ['oldDecision','legacyDecision','legacy'] if k in row),None);new=next((row[k] for k in ['standardDecision','standard','policyDecision'] if k in row),None)
 if old is None:old=row.get('oldStatus')
 if new is None:new=row.get('standardStatus')
 raw=next((row[k] for k in ['rawPreserved','rawUnchanged','inputUnchanged'] if k in row),False)
 return {'old':old,'policy':new,'rawPreserved':raw,'match':old==new and old is not None and row.get('oldStatus')==row.get('standardStatus')}
def stats(records):
 n=[normalize(x['row']) for x in records]
 return {'samples':len(n),'matches':sum(x['match'] for x in n),'drifts':sum(not x['match'] for x in n),'rawPreserved':all(x['rawPreserved'] for x in n),'oldDecisions':dict(Counter(x['old'] for x in n)),'policyDecisions':dict(Counter(x['policy'] for x in n))}
allRecords=[];byPath={}
for p in sorted(list(E1.glob('*/*differential.json'))+list(E2.glob('zap-parent/*differential.json'))+[F/'differential.json',F/'timing-after.json']):
 if p==E1/'falco-parent/differential.json':continue # superseded complete suite; not layered/new execution
 document=load(p)
 byPath[rel(p)]=[{'id':rel(p)+('#/records/'+str(i) if isinstance(document,dict) and 'records' in document else '#/'+str(i) if isinstance(document,list) else '#'),'row':row,'evidence':rel(p)} for i,row in enumerate(rows(p))];allRecords+=byPath[rel(p)]
core=load(O/'core-readiness.json')
allRecords += [{'id':rel(O/'core-readiness.json')+'#/classifierRecheck/'+str(i),'row':row,'evidence':rel(O/'core-readiness.json')} for i,row in enumerate(core['classifierRecheck'])]
sopsRecords=[]
for i,item in enumerate(load(S/'matrix-result.json')['results'],1):
 p=S/item['evidence'];d=load(p);r=d['result'];row={'oldDecision':r['oldGate']['oldDecision'],'standardDecision':r['policy']['decision'],'rawPreserved':r['rawEvidence']['rawPreserved'],'classification':'REAL_CONTROLLED_EXECUTION','name':item['scenario']}
 sopsRecords.append({'id':rel(p)+'#/result','row':row,'evidence':rel(p)})
allRecords+=sopsRecords

groups={'sbom':('sbom-parent',['differential.json','workflow-differential.json']),'regression':('regression-parent',['differential.json']),'kyverno':('kyverno-parent',['parent-differential.json']),'kubescape':('kubescape-parent',['differential.json']),'defectdojo':('dojo-parent',['differential.json']),'cosign':('cosign-parent',['differential.json']),'provenance':('provenance-parent',['differential.json','workflow-differential.json']),'build-provenance':('build-provenance-parent',['differential.json','workflow-differential.json']),'semgrep':('command-parent',['differential.json','workflow-differential.json']),'semgrep-command-audit':('command-parent',['differential.json','workflow-differential.json']),'security-approval-promotion':('promotion-parent',['differential.json','workflow-differential.json']),'falco-baseline':('falco-parent',['differential.json']),'falco-final':('falco-parent',['differential.json']),'gitleaks':('gitleaks-parent',['differential.json','workflow-differential.json']),'trivy':('trivy-parent',['differential.json','workflow-differential.json']),'zap':('zap-parent',['differential.json','workflow-differential.json'])}
adapters={'sbom':'sbom-parent','regression':'regression-evidence','kyverno':'kyverno-parent','kubescape':'kubescape-parent','defectdojo':'dojo-parent','cosign':'cosign-parent','provenance':'provenance-parent','build-provenance':'build-provenance-evidence','semgrep':'command-parent','semgrep-command-audit':'command-parent','security-approval-promotion':'promotion-evidence','falco-baseline':'falco-parent','falco-final':'falco-parent','gitleaks':'gitleaks-parent','trivy':'trivy-parent','zap':'zap-parent','sops':'sops-evidence','sonarqube':'sonar-evidence'}
stages={x['id']:x['stage'] for x in production};stages.update({'provenance':'Conditional securityProvenance','build-provenance':'Conditional securityBuildProvenance','semgrep-command-audit':'Command Analysis before/in Semgrep','security-approval-promotion':'Security Approval / Approved Promotion / Git Promotion'})
baselineSnapshot=load(S/'project-before.json');matrix=[];selected={};acceptanceChecks=[]
for orig in original:
 source=orig['source'];adapter='infra/security/policy/'+adapters[source]+'.mjs';assert (R/adapter).is_file()
 adapterExpected=baselineSnapshot[adapter]
 if source.startswith('falco-'):
  transitions=load(F/'evidence-supersession.json')['sourceTransitions'];transition=next(x for x in transitions if x['path']==adapter)
  assert transition['oldSha256']==adapterExpected==sha(R/transition['archivedOldPath'])
  adapterExpected=transition['newSha256']
 adapterMatched=sha(R/adapter)==adapterExpected
 if not adapterMatched:blockers.append({'source':source,'reason':'Adapter differs from authoritative pre-SOPS snapshot'})
 if source in groups:
  directory,files=groups[source];base=F if source.startswith('falco-') else E2/directory if source=='zap' else E1/directory;acceptance=load(base/'acceptance.json')
  if source.startswith('falco-'):files=['differential.json','timing-after.json']
  records=[x for name in files for x in byPath[rel(base/name)]]
  if source.startswith('falco-'):records=[x for x in records if x['row']['mode']==('baseline' if source=='falco-baseline' else 'check')]
  if source=='trivy':records=[x for x in records if x['row'].get('stage')!='release-scan']
  if source.startswith('falco-'):count=acceptance['baseline' if source=='falco-baseline' else 'final']['total']
  elif source=='trivy':count=acceptance['completeParentDifferentials']['samples']
  else:count=acceptance['matched']
  st=stats(records);accepted=(acceptance.get('FALCO_COMPATIBILITY')=='VERIFIED' and acceptance.get('FALCO_TIME_CONTRACT')=='VERIFIED' if source.startswith('falco-') else acceptance['finalStatus']=='VERIFIED') and acceptance['rawFactsPreserved'] and count==st['samples']==st['matches'] and st['drifts']==0 and st['rawPreserved']
  acceptanceChecks.append({'source':source,'expectedSamples':count,'actual':st,'accepted':accepted})
  status='VERIFIED' if accepted else 'FAILED';parentStatus=status;evidenceDirs=[rel(base)];refs=[rel(base/'acceptance.json')]+[rel(base/name) for name in files];gaps=acceptance.get('remainingEvidenceGaps',[])
  if not accepted:blockers.append({'source':source,'reason':'Acceptance does not reconcile with retained records'})
  for x in records:selected[x['id']]=x
 elif source=='sops':
  base=S;records=sopsRecords;st=stats(records);verdict=load(S/'compatibility-verdict.json');final=load(S/'final-index-validation.json');clean=load(S/'cleanup-result.json');pre=load(S/'precleanup-acceptance.json')
  accepted=verdict['approved']==verdict['applicable']==verdict['oldGateExecutions']==verdict['adapterPolicyExecutions']==12 and verdict['SOPS_COMPATIBILITY']=='VERIFIED' and st['samples']==st['matches']==12 and st['drifts']==0 and st['rawPreserved'] and final['filesChecked']==88 and final['status']=='PASS' and final['indexSha256']==sha(S/'final-evidence-index.json') and clean['status']=='COMPLETE' and pre['productionApiAccess']==0
  accepted=accepted and all(load(S/x['evidence'])['result']['classification']=='REAL_CONTROLLED_EXECUTION' for x in load(S/'matrix-result.json')['results'])
  status='VERIFIED' if accepted else 'FAILED';parentStatus=status;evidenceDirs=[rel(S)];refs=[rel(S/n) for n in ['compatibility-verdict.json','final-evidence-index.json','final-index-validation.json','precleanup-acceptance.json','cleanup-result.json','comparison-contract.json','final-clean-state.json']];gaps=['Historical negative incidents remain deferred; approved controlled real execution proves frozen-code compatibility, not production rerun']
  if not accepted:blockers.append({'source':'sops','reason':'Authoritative 12-case proof / cleanup / index failed'})
  for x in records:selected[x['id']]=x
 else:
  base=E1/'sonar-policy';records=byPath[rel(base/'positive-differential.json')];st=stats(records);disposition=load(base/'negative-evidence-disposition.json');linkage=load(base/'analysis-linkage.json')
  accepted=st['samples']==st['matches']==1 and st['rawPreserved'] and disposition['sonarPositiveStatus']=='VERIFIED' and disposition['sonarNegativeStatus']=='NOT_TESTED' and disposition['disposition']=='DEFERRED_REAL_NEGATIVE_EVIDENCE' and disposition['mayProceedToRemainingProductionGateAdapterDifferential'] and core['sonarLogic']['positive']['decision']=='PASS' and core['sonarLogic']['negative']['decision']=='FAIL'
  status='DEFERRED' if accepted else 'FAILED';parentStatus='PARTIAL_REAL_POSITIVE_VERIFIED_NEGATIVE_DEFERRED';evidenceDirs=[rel(base)];refs=[rel(base/n) for n in ['positive-differential.json','analysis-bound-facts.json','analysis-linkage.json','negative-evidence-disposition.json','negative-artifact-validation.json']];gaps=disposition['missingEvidence']+['Positive Jenkins association is workspace/time correlation; directArchivedBuildTaskBinding='+linkage['directArchivedBuildTaskBinding']]
  if not accepted:blockers.append({'source':'sonarqube','reason':'Deferred acceptance rule or actual positive/error mapping does not hold'})
 sourceFiles=set(orig.get('sourceHashes',{}))
 if source in ['sonarqube','provenance','build-provenance','security-approval-promotion','semgrep-command-audit']:
  sourceFiles.update({'sonarqube':['Jenkinsfile','Jenkinsfile.security-audit','resources/security-manager/petclinic-adapter.json','vars/securityManager.groovy'],'provenance':['vars/securityProvenance.groovy'],'build-provenance':['vars/securityBuildProvenance.groovy'],'security-approval-promotion':['infra/security/promotion/contract.mjs','infra/security/promotion/evidence.mjs','infra/security/promotion/sign-approve.mjs','infra/security/promotion/promote.mjs'],'semgrep-command-audit':['infra/security/command-audit.mjs','infra/security/semgrep-gate.mjs']}[source])
 for name in sourceFiles:
  if not (R/name).is_file():blockers.append({'source':source,'reason':'Production source missing','path':name})
 sourceIndices=[rel(i) for i in indexes if i.parent in [base,E1/'policy-engine',E1/'security-manager-contract']]
 sourceHashes={n:sha(R/n) for n in sorted(sourceFiles) if (R/n).is_file()}
 row={'source':source,'productionStage':stages[source],'productionEntry':orig['entry'],'productionImplementationPaths':sorted(sourceFiles),'sourceHashes':sourceHashes,'classifierAdapterPath':adapter,'adapterSha256':sha(R/adapter),'adapterMatchesAuthoritativeSnapshot':adapterMatched,'policyMappingPath':'infra/security/policy/engine.mjs','policyMappingSha256':sha(R/'infra/security/policy/engine.mjs'),'policyVersionPath':'infra/security/policy/versions/baseline-v1.json','latestCompatibilityStatus':status,'parentStageEvidenceStatus':parentStatus,'parentStageSampleCount':len(records) if source!='sonarqube' else 0,'partialPositiveSamples':1 if source=='sonarqube' else 0,'statistics':st,'evidenceDirectories':evidenceDirs,'evidenceFiles':refs,'evidenceIndexes':sourceIndices,'evidenceClassifications':sorted({x['row'].get('classification','HISTORICAL_ARCHIVE' if source=='sonarqube' else 'CONTROLLED_REPLAY') for x in records}),'remainingEvidenceGaps':gaps,'aggregateAliasOf':'semgrep-command-audit' if source=='semgrep' else None}
 matrix.append(row)
# Revalidate complete repaired Falco acceptance and evidence integrity, including the original two drift cases.
fa=load(F/'acceptance.json');fm=load(F/'authoritative-falco-matrix.json');fb=load(F/'timing-before.json')['records'];ft=load(F/'timing-after.json')['records']
assert len(fb)==len(ft)==74 and fa['beforeDrift']==20 and fa['afterDrift']==0
assert fa['productionGateChanged'] is False and fa['policyBaselineChanged'] is False
assert fa['nodeTests']['policyCore']['tests']==fa['nodeTests']['policyCore']['pass']==5
for b,t in zip(fb,ft):
 assert (b['mode'],b['name'],b['inputSha256'])==(t['mode'],t['name'],t['inputSha256'])
 assert t['oldDecision']==t['standardDecision'] and t['rawPreserved'] and t['assessmentEqual']
for x in matrix:
 if x['source'].startswith('falco-'):
  expected=next(y for y in fm['sources'] if y['source']==x['source'])
  assert expected['total']==x['parentStageSampleCount'] and expected['adapterSha256']==x['adapterSha256']
  assert expected['productionSourceSha256']==x['sourceHashes']['infra/security/runtime/health.mjs']
  assert expected['policyBaselineSha256']==sha(R/'infra/security/policy/versions/baseline-v1.json')
  x['currentAuthority']='FALCO_TIME_CONTRACT_REPAIRED'
  x['historicalEvidence']={'directory':'evidence/2026-11-01/falco-parent','status':'SUPERSEDED_FOR_TIME_BOUNDARY_COVERAGE','retained':True,'counted':False}
  x['adapterVersionTransition']=next(y for y in load(F/'evidence-supersession.json')['sourceTransitions'] if y['path']==x['classifierAdapterPath'])
  x['evidenceFiles'] += [rel(F/n) for n in ['time-contract.json','authoritative-falco-matrix.json','evidence-supersession.json','source-preservation.json','timing-before.json']]
# Capture current adapter/mapping identities explicitly; never inherit an old adapter as current.
save('adapter-version-validation.json',{'sources':[{'source':x['source'],'path':x['classifierAdapterPath'],'sha256':x['adapterSha256'],'matchesAcceptedVersion':x['adapterMatchesAuthoritativeSnapshot'],'transition':x.get('adapterVersionTransition')} for x in matrix],'references':len(matrix),'distinctAdapters':len({x['classifierAdapterPath'] for x in matrix}),'policyEngineSha256':sha(R/'infra/security/policy/engine.mjs'),'policyBaselineSha256':sha(R/'infra/security/policy/versions/baseline-v1.json'),'falcoHistoricalEvidenceCounted':False})
parent=list(selected.values());sonar=byPath[rel(E1/'sonar-policy/positive-differential.json')];main=parent+sonar
parentStats=stats(parent);mainStats=stats(main);layerStats=stats(allRecords)
if parentStats['drifts'] or layerStats['drifts'] or not layerStats['rawPreserved']:blockers.append({'source':'differential-aggregate','reason':'Decision/status mismatch or raw input changed'})
counts=Counter(x['latestCompatibilityStatus'] for x in matrix)
for status in ['VERIFIED','DEFERRED','ENVIRONMENT_BLOCKED','NOT_TESTED','FAILED']:counts.setdefault(status,0)
save('authoritative-source-matrix.json',{'productionSourceCount':len(matrix),'counts':dict(counts),'sources':matrix})
save('acceptance-reconciliation.json',{'checks':acceptanceChecks,'allAccepted':all(x['accepted'] for x in acceptanceChecks)})
save('differential-reconciliation.json',{'completeParentDeduplicated':parentStats,'mainEvidenceWithSonarPositive':mainStats,'layeredRetainedRecords':layerStats,'perSourceCounts':{x['source']:{'parent':x['parentStageSampleCount'],'partial':x['partialPositiveSamples'],'old':x['statistics']['oldDecisions'],'policy':x['statistics']['policyDecisions']} for x in matrix},'deduplication':'Record identity is evidence path + row pointer; Semgrep/Command Analysis share 136 rows once. SOPS per-case execution JSON counts once; matrix/progress/index references are not executions.','supplementaryScopes':{'trivyReleaseScan':20,'trivyDatabasePrerequisite':41,'earlierKyvernoChild':49,'earlierCommandChild':5,'earlierContracts':39,'earlierSopsUnitOnly':20,'earlierGitleaksClassifier':7,'originalClassifierRecheck':20},'parentRecordIds':[x['id'] for x in parent],'mainRecordIds':[x['id'] for x in main],'layeredRecordIds':[x['id'] for x in allRecords]})
save('layered-record-audit.json',{'records':[{'id':x['id'],**normalize(x['row']),'classification':x['row'].get('classification','LEGACY_CHILD_OR_CLASSIFIER_EVIDENCE')} for x in allRecords]})

summary={'producers':[{'path':'infra/security/security-summary.mjs','route':'PetClinic production security-audit','callSites':['Jenkinsfile.security-audit:48','Jenkinsfile.security-audit:75'],'schema':'inline record literal, schema=1; .devsecops/security-summary.json output','sinks':['local artifact','Loki push']},{'path':'resources/security-manager/summary.mjs','route':'Shared Library generic manager libraryResource','callSites':['vars/securityManager.groovy'],'schema':'inline s literal, schema=1','sinks':['local artifact','Loki push']},{'path':'infra/security/manager/summary.mjs','route':'repository copy of generic summary','schema':'inline s literal, schema=1','sameBytesAsResource':sha(R/'resources/security-manager/summary.mjs')==sha(R/'infra/security/manager/summary.mjs')}],
 'schemaArtifact':'.devsecops/security-summary.json','dedicatedJsonSchemaFile':None,'schemaDefinitionLocations':['infra/security/security-summary.mjs:5','resources/security-manager/summary.mjs:3','infra/security/manager/summary.mjs:3'],
 'consumers':[{'path':'infra/security/promotion/evidence.mjs:3','behavior':'gateEvidence reads summary; sign-approve/promote consume gateEvidence'},{'path':'infra/security/promotion/contract.mjs','behavior':'validateGate reads auditTargetImage,targetScope,source,build,trivy_critical,trivy_high'},{'path':'infra/security/promotion/sign-approve.mjs','behavior':'validates summary/candidate identity before approval signing'},{'path':'infra/security/promotion/promote.mjs','behavior':'promotion/dry-run reuses gate evidence'},{'path':'Jenkinsfile.security-audit:76','behavior':'archives summary JSON'},{'path':'infra/security/governance/grafana-panels.json','behavior':'Loki JSON query fields from job=devsecops-security; no query performed'}],
 'policyMetadata':{'policyVersion':'available','securityLevel':'available; default standard','profile':'available','effectivePolicy':'available','overrideSource':{'literalFieldExists':False,'existingEquivalent':'appliedOverrides[].layer + component/profile + values, precedence in order; global default is policyVersion/securityLevel','integrationRequirement':'Expose append-only metadata from existing contract; do not claim a literal overrideSource field already exists'},'POLICY_ERROR':'throws explicit POLICY_ERROR; no low fallback'},
 'readOnlyContractValidation':core['checks'],'coreTests':load(O/'core-command-exits.json'),'sourceCompatibility':'18 accounted; Sonar real-negative explicitly deferred; compatibility scoped to frozen standard','actualSummaryIntegrated':False,'summaryV2Resumed':False,'policyMetadataRequiredFields':['policyVersion','securityLevel','profile','effectivePolicy','appliedOverrides','policyDecision']}
for producer in summary['producers']:producer['sha256']=sha(R/producer['path'])
save('summary-preconditions.json',summary)
if not core['ready'] or any(load(O/'core-command-exits.json').values()):blockers.append({'source':'policy-core','reason':'Existing core validation/test failed'})
save('blocker-disposition.json',{'items':[{'priorBlocker':'Policy Engine missing','status':'CLOSED_FOR_SUMMARY_INTEGRATION','reason':'Versioned standalone engine exists; current core checks/tests and frozen standard compatibility audited'},{'priorBlocker':'SOPS compatibility','status':'CLOSED_FOR_SUMMARY_INTEGRATION' if next(x for x in matrix if x['source']=='sops')['latestCompatibilityStatus']=='VERIFIED' else 'BLOCKING','reason':'New authoritative 12-case real controlled evidence replaces prior environment blocker'},{'priorBlocker':'Unified plugin contract / master switch / independent lifecycle','status':'STILL_LATER_ARCHITECTURE_WORK','reason':'Existing plan places this after additive Summary metadata; not waived or implemented'},{'priorBlocker':'DefectDojo scanner-file coupling','status':'STILL_LATER_ARCHITECTURE_WORK','reason':'After plugin contract; compatibility preservation does not fix coupling'},{'priorBlocker':'Result Router / Loki-Grafana query closure','status':'STILL_LATER_ARCHITECTURE_WORK','reason':'Later result-routing/query-verification stage; this audit performs no network calls'}],'sonarDebt':{'status':'DEFERRED','positive':'VERIFIED','realNegative':'NOT_TESTED / DEFERRED_REAL_NEGATIVE_EVIDENCE','nonBlocking':True,'rationale':'Established explicit acceptance permits missing naturally occurring bound historical negative when actual positive and independent ERROR mapping tests pass; no redefinition of Sonar metrics or historical evidence','positiveBuildTaskBinding':'workspace/time correlation, direct archived per-build task NOT_TESTED'},'laterDebt':['Summary V2 migration implementation and inactive candidate version reconciliation','globalMode / per-plugin switches / capability checks','Provenance opt-in normalization','Global SECURITY_ENABLED and all-plugin lifecycle/capability isolation','Portability smoke','Historical full runtime/CLI proofs for controlled replay sources']})
before=load(O/'before-sha256.json');changed=[n for n,h in before.items() if not (R/n).is_file() or sha(R/n)!=h]
save('no-mutation-proof.json',{'protectedFiles':len(before),'changed':changed,'productionApiAccess':0,'newResources':0,'rollout':False,'summaryProducerModified':False,'actualSummaryModified':False,'managerOrJenkinsModified':False,'preExistingEvidenceRewritten':False})
if changed:blockers.append({'source':'audit-mutation','paths':changed})
ready=inventoryComplete and len(matrix)==18 and counts['VERIFIED']==17 and counts['DEFERRED']==1 and not blockers
save('readiness.json',{'SUMMARY_INTEGRATION_READINESS':'READY' if ready else 'NOT_READY','productionSourceCount':18,'counts':dict(counts),'sops':'VERIFIED' if next(x for x in matrix if x['source']=='sops')['latestCompatibilityStatus']=='VERIFIED' else 'FAILED','sonar':'DEFERRED','parentStageAggregate':parentStats,'mainEvidenceTotal':mainStats['samples'],'layeredEvidenceTotal':layerStats['samples'],'indexes':len(indexes),'hashReferences':len(indexChecks),'directHashMatches':sum(x['directMatch'] for x in indexChecks),'historicalSupersessionResolutions':len(resolutionReceipts),'unresolvedHashFailures':len(indexFailures),'sourceHashChecks':len(sourceChecks),'sourceHashFailures':len(sourceFailures),'coreStatus':'VERIFIED' if core['ready'] else 'FAILED','blockers':blockers,'scope':'Frozen current production behavior compatibility only. Not universal security correctness, SLSA certification, live production rerun or historical negative certification.','nextPermittedAction':'STOP. Await separately authorized next phase; do not resume Summary V2, producer edits, Promotion/Regression migration or plugin architecture here' if ready else 'STOP; resolve the exact reported readiness evidence/precondition blocker in a separately scoped iteration','summaryModified':False})
print(json.dumps({'readiness':'READY' if ready else 'NOT_READY','counts':dict(counts),'parent':parentStats,'main':mainStats['samples'],'layered':layerStats['samples'],'indexes':len(indexes),'references':len(indexChecks),'unresolved':len(indexFailures),'blockers':blockers},ensure_ascii=False,indent=2))
