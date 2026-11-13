from pathlib import Path
import json,hashlib,datetime,re
O=Path(__file__).resolve().parent;R=O.parents[2]
read=lambda n:json.loads((O/n).read_text())
sha=lambda b:hashlib.sha256(b).hexdigest()
def save(n,x):(O/n).write_text(json.dumps(x,ensure_ascii=False,indent=2)+'\n')
assert len(read('report-items.json'))==78
for name,c in read('test-counts.json').items():assert c['tests']==c['pass'] and c['fail']==0,name
assert all(x['status']=='VERIFIED' for x in read('policy-contract.json')['checks'])
assert read('source-hash-preservation.json')['failures']==[]
assert read('dojo-governance-comparison.json')['unexpectedProductionMutation']==0
jobs=read('live-jenkins-final.json')['jobs'];j=next(x for x in jobs if x['job']=='petclinic-ci');before=next(x for x in read('live-jenkins.json.before')['jobs'] if x['job']=='petclinic-ci');assert j==before
assert j['latestBuild']==270 and j['result']=='SUCCESS' and j['summarySha256']=='ec9ee51a06d4b9f61c6c0eaf50b374d1e25e6d3ca687908b7596d3a2c794f5d8'
ws=read('live-workspace-hashes-final.json')['workspaces'][0]['files'];assert ws['vars/securityManager.groovy']['sha256']=='6854436a43b347fc94e895eada0b2048be238668817a4af33a228396f1c57c32';assert ws['infra/security/security-summary.mjs']['sha256']=='038320f04c67fb1fe5ff711c11d445c2de88cc50b2230eb4c971bf46142f5b34';assert ws['infra/security/summary-v2/owner.mjs']['exists']==False
protected=read('live-protected-final.json');assert protected['argocdSync']=='Synced' and protected['argocdHealth']=='Healthy';assert protected['http']['status']==200
assert all(next(c['status'] for c in n['conditions'] if c['type']=='Ready')=='True' for n in read('node-lease-postflight.json')['nodes'])
assert read('health-final.json')['deployment']['ready']==3
assert read('jenkins-build-33.json')['result']=='SUCCESS';assert read('jenkins-build-33.json')['regression'][0]['counts']['pass']==147
assert read('private-material-audit.json')['privateKeyMarkersFound']==0
# Dedicated pipeline restored, matching exact saved text; path explicit to avoid ancestor ambiguity.
assert (O/'Jenkinsfile.runtime-facts.before').read_bytes()==Path('Jenkinsfile.runtime-facts').read_bytes()
co=read('cosign-source-receipt.json');assert co['runtimeAcceptance']=='VERIFIED' and co['evaluationCount']==1 and co['resultDigest']==co['GateInputDigest']
assert read('runtime-source-matrix.json')['acceptedBoundaryCapabilities']==14
assert read('trivy-engineering-blocker.json')['runtimeResultPresent']==False
assert read('defectdojo-source-receipt.json')['resultDigest'] is None
save('final-protected-state.json',{'classification':'READ_ONLY_LIVE_POSTFLIGHT_AND_OPERATION_AUDIT','productionBuild':270,'productionResult':'SUCCESS','v1Active':True,'summarySha256':j['summarySha256'],'managerSha256':ws['vars/securityManager.groovy']['sha256'],'producerSha256':ws['infra/security/security-summary.mjs']['sha256'],'policyBaselineSha256':'02c3f5499dc39a53009a69e8f267dbbd247b4d89d4de14fafaa4dd5cff974f1a','frozenSourcesPreserved':True,'gitopsSpecUnchanged':True,'argocdSync':'Synced','argocdHealth':'Healthy','petclinicReady':3,'readyEndpoints':3,'httpStatus':200,'nodesReady':3,'productionSignatureMutation':0,'productionPrivateKeyReads':0,'unexpectedProductionDojoMutation':0,'temporaryKubernetesObjectsRemaining':0,'temporaryWebhookObjectsRemaining':0,'privateCredentialDirectoryRemoved':True,'validationArtifactsRetained':5,'release':0,'rollout':0,'trivyStorageChanges':0,'proxyChanges':0,'trivyDBRefreshes':0,'trivyOperationsEvidence':'No Trivy/storage/proxy/DB command or API mutation in this iteration; no assertion of bytewise database immutability against background activity','summaryV2Activated':False,'completePreApprovalArtifactGenerated':False,'productionChanges':[]})
# Generated Python bytecode belongs only to this new evidence helper.
for p in (O/'__pycache__').glob('*') if (O/'__pycache__').exists() else []:p.unlink()
if (O/'__pycache__').exists():(O/'__pycache__').rmdir()
files={str(p.relative_to(O)):sha(p.read_bytes()) for p in sorted(O.rglob('*')) if p.is_file() and not p.is_symlink() and p.name not in ['evidence-sha256.json','seal-verification.json']}
save('evidence-sha256.json',{'schema':1,'kind':'ENGINEERING_EVIDENCE_DIRECTORY_MANIFEST_NOT_PREAPPROVAL_ARTIFACT','validationRunId':read('run.json')['validationRunId'],'createdAt':datetime.datetime.now(datetime.timezone.utc).isoformat(),'completeImmutablePreApprovalArtifactGenerated':False,'exclusions':['evidence-sha256.json','seal-verification.json','symbolic links and their existing targets'],'files':files})
assert all(sha((O/p).read_bytes())==h for p,h in files.items())
save('seal-verification.json',{'checkedFiles':len(files),'failures':0,'reportItems':78,'canonicalRuntimeArtifact':'NOT_GENERATED','verdict':read('verdict.json'),'stop':True})
print(json.dumps({'sealedFiles':len(files),'failures':0,'reportItems':78,'verdict':read('verdict.json'),'stop':True}))
