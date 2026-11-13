from pathlib import Path
import json,hashlib,datetime,re
O=Path(__file__).resolve().parent
read=lambda n:json.loads((O/n).read_text())
def save(n,x):(O/n).write_text(json.dumps(x,ensure_ascii=False,indent=2)+'\n')
sha=lambda b:hashlib.sha256(b).hexdigest()
assert len(read('report-items.json'))==68
for name,c in read('test-counts.json').items():assert c['tests']==c['pass'] and c['fail']==0,name
c={k:int(n) for k,n in re.findall(r'(?m)^(?:#|ℹ) (tests|pass|fail|cancelled|skipped|todo) (\d+)$',(O/'dependency-contract-tests.log').read_text())};assert c['pass']==8 and c['fail']==0
counts=read('test-counts.json');counts['dependency-contract-tests']=c;save('test-counts.json',counts)
assert len(read('policy-contract.json')['checks'])==10 and all(x['status']=='VERIFIED' for x in read('policy-contract.json')['checks'])
assert read('source-hash-preservation.json')['failures']==[]
for p,h in read('source-baseline.json').items():assert sha(Path(p).read_bytes())==h,p
# Recheck the authoritative previous evidence; never rewrite its manifest.
prior=O.parent/'runtime-independent-boundaries';seal=json.loads((prior/'evidence-sha256.json').read_text());assert all(sha((prior/p).read_bytes())==h for p,h in seal['files'].items())
active=read('active-v1-selection-identity.json');assert not active['files']['vars/securityManager.groovy']['equal'];assert active['files']['vars/securityManager.groovy']['liveSha256']=='6854436a43b347fc94e895eada0b2048be238668817a4af33a228396f1c57c32'
for x in active['files'].values():assert sha((O/x['snapshot']).read_bytes())==x['liveSha256']
assert active['files']['infra/security/governance/defectdojo.mjs']['equal'];assert active['files']['resources/security-manager/petclinic-adapter.json']['equal']
assert read('dojo-report-contract.json')['trivyMandatory'];assert read('dojo-dependency-receipt.json')['DOJO_INPUT_DEPENDENCY']=='TRIVY_HARD_DEPENDENCY'
assert read('runtime-disposition.json')['evaluationCount']==0 and read('runtime-disposition.json')['resultDigest'] is None
assert len(read('runtime-dependency-graph.json')['nodes'])==16
assert read('dojo-governance-before.json')==read('dojo-governance-after.json')
assert read('protected-state.json')['unexpectedProductionDojoMutation']==0
assert read('verdict.json')['FINAL_WIRED_CAPABILITY']=='14/16'
assert read('validation-archives-recheck.json')['latestBuild']==33
save('stop-receipt.json',{'state':'STOP','reviewComplete':True,'reason':'TRIVY_HARD_DEPENDENCY established; regression and protected-state checks complete','nextPermittedAction':'Wait for separate authorization of future Dojo decoupling review or environment recovery; neither implemented here','newRuntimeAcceptances':0,'newJenkinsBuilds':0,'productionWrites':0,'release':0,'rollout':0,'trivyRuntimeExecutions':0,'completeRuntimeArtifactGenerated':False})
files={str(p.relative_to(O)):sha(p.read_bytes()) for p in sorted(O.rglob('*')) if p.is_file() and not p.is_symlink() and p.name not in ['evidence-sha256.json','seal-verification.json']}
save('evidence-sha256.json',{'kind':'ENGINEERING_DEPENDENCY_REVIEW_EVIDENCE_NOT_PREAPPROVAL_ARTIFACT','reviewId':read('run.json')['reviewId'],'sealedAt':datetime.datetime.now(datetime.timezone.utc).isoformat(),'completeImmutablePreApprovalArtifactGenerated':False,'files':files,'exclusions':['evidence-sha256.json','seal-verification.json','symbolic links and pre-existing targets']})
assert all(sha((O/p).read_bytes())==h for p,h in files.items())
save('seal-verification.json',{'filesChecked':len(files),'failures':0,'reportItems':68,'canonicalGraphSources':16,'priorEvidenceFilesRechecked':len(seal['files']),'stopped':True})
print(json.dumps({'sealedFiles':len(files),'failures':0,'reportItems':68,'verdicts':read('verdict.json'),'stop':True}))
