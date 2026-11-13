from pathlib import Path
import json,hashlib,datetime,re,subprocess
O=Path(__file__).resolve().parent;sha=lambda b:hashlib.sha256(b).hexdigest()
read=lambda n:json.loads((O/n).read_text())
def save(n,x):(O/n).write_text(json.dumps(x,ensure_ascii=False,indent=2)+'\n')
assert len(read('report-items.json'))==68
assert read('verdict.json')['RUNTIME_14_OF_16_CHECKPOINT']=='FAILED'
assert read('checkpoint-integrity.json')['status']=='FAILED' and read('checkpoint-integrity.json')['integrityStatus']=='VERIFIED'
assert read('checkpoint-verifier-execution.json')['exitStatus']==2
assert read('checkpoint.json')['authoritativeAcceptance']=='FAILED'
assert read('checkpoint.json')['acceptedWiredCount']==14 and len(read('checkpoint.json')['sources'])==16
assert sha((O/'checkpoint.json').read_bytes())==read('checkpoint-digest.json')['sha256']
for c in read('test-counts.json').values():assert c['tests']==c['pass'] and c['fail']==0
assert read('test-counts.json')['checkpoint-integrity-tests']['pass']==12
assert len(read('policy-contract.json')['checks'])==10 and read('policy-contract.json')['ready']
for p,h in read('implementation-before.json').items():assert sha(Path(p).read_bytes())==h,p
assert read('source-hash-preservation.json')['failures']==[]
assert read('observed-protection-drift.json')['unresolved'] and read('observed-protection-drift.json')['agentProxyWrites']==0
assert read('protected-state.json')['allProtectedChecksPassed']==False
assert read('guard-analysis.json')['newApprovedGuard'] is None and not read('guard-analysis.json')['thresholdModified']
assert read('resume-contract.json')['TRIVY_RESUME_ALLOWED']==False
assert read('peak-space-model.json')['PEAK_EXPECTED_BYTES'] is None
assert read('dojo-governance-before.json')==read('dojo-governance-after.json')
# Re-run verifier only; expected return2 protects against treating integrity-only success as authorized resume.
p=subprocess.run(['node',str(O/'verify-checkpoint.mjs')],capture_output=True,text=True);assert p.returncode==2;assert json.loads(p.stdout)['status']=='FAILED'
save('stop-receipt.json',{'state':'STOP','RUNTIME_14_OF_16_CHECKPOINT':'FAILED','checkpointFileIntegrity':'VERIFIED','checkpointAcceptanceBlocker':'UNEXPLAINED_PROXY_CONFIG_DRIFT','guardValidity':'GUARD_REQUIRES_REVALIDATION','TRIVY_RESUME_ALLOWED':False,'guardModified':False,'dbRefreshCount':0,'dbPathChanges':0,'storageChanges':0,'proxyWritesByAgent':0,'proxyFileChangedDuringWindow':True,'unexplainedProxyChangeRestored':False,'productionCosignPrivateKeyReads':0,'dojoWrites':0,'newRuntimeSourceWiring':0,'newRuntimePolicyEvaluations':0,'newJenkinsBuilds':0,'release':0,'rollout':0,'COMPLETE_RuntimeArtifactGenerated':False,'SummaryV2Activated':False,'nextPermittedAction':'Separately authorized read-only provenance/approved-baseline confirmation for proxy drift; then new checkpoint acceptance. Guard peak experiment requires separate approval; original guard remains active.'})
files={str(p.relative_to(O)):sha(p.read_bytes()) for p in sorted(O.rglob('*')) if p.is_file() and not p.is_symlink() and p.name not in ['evidence-sha256.json','seal-verification.json']}
save('evidence-sha256.json',{'kind':'FAILED_CHECKPOINT_AND_READ_ONLY_GUARD_REVIEW_EVIDENCE_NOT_PREAPPROVAL_ARTIFACT','reviewId':read('run.json')['reviewId'],'sealedAt':datetime.datetime.now(datetime.timezone.utc).isoformat(),'checkpointAuthoritativeStatus':'FAILED','checkpointFileIntegrity':'VERIFIED','completeRuntimeArtifactGenerated':False,'files':files,'exclusions':['evidence-sha256.json','seal-verification.json','symbolic links and pre-existing targets']})
assert all(sha((O/p).read_bytes())==h for p,h in files.items())
save('seal-verification.json',{'evidenceFilesChecked':len(files),'integrityFailures':0,'reportItems':68,'authorityCheckFailure':'UNEXPLAINED_PROXY_CONFIG_DRIFT','checkpointByteSha256':read('checkpoint-digest.json')['sha256'],'checkpointAuthoritativeStatus':'FAILED','verdicts':read('verdict.json'),'stop':True})
print(json.dumps({'sealedFiles':len(files),'evidenceIntegrityFailures':0,'reportItems':68,'checkpointAuthoritativeStatus':'FAILED','checkpointFileIntegrity':'VERIFIED','guardOrigin':'CALCULATED_FROM_FILESYSTEM_STATE','guardValidity':'GUARD_REQUIRES_REVALIDATION','guardUnchanged':True,'resumeAllowed':False,'stop':True}))
