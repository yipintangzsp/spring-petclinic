"""Read-only validation; no CI execution or historical-evidence repair."""
from pathlib import Path
import json,hashlib
O=Path(__file__).resolve().parent;R=O.parents[2]
read=lambda n:json.loads((O/n).read_text())
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
b=read('baseline.json')
for name,h in b['protectedFilesAtStart'].items():assert sha(R/name)==h,name
pre=read('ci-inventory.json');post=read('ci-inventory-after.json')
assert pre==post,'Jenkins Job/Agent/config inventory changed'
assert len(post['computers'])==1 and post['computers'][0]['name']==''
assert not any(j['name']=='security-manager-v2-gitleaks-validation' for j in post['jobs'])
assert not post['queue']
identity=read('builtin-identity.json');assert identity['uid']==1000 and 988 in identity['groups'] and identity['dockerSocket']['readable']
resource=read('agent-resource-observation.json');assert len(resource['existingUid65534Processes'])>0
assert any('kyverno' in z['name'] for z in resource['existingUid65534Processes'])
assert read('definition-final-validation.json')['jobImported'] is False
assert read('clean-checkout-final-execution.json')['exit']==0
verdict=read('verdict.json');assert verdict['actualBuildNumber'] is None and verdict['realScansThisRound']==0
assert verdict['executionReadiness']=='CI_EXECUTION_NOT_READY'
assert read('pre-live-jenkins-final.json')['jobs']==read('live-jenkins-final.json')['jobs']
j=read('live-jenkins-final.json')['jobs'][0];assert j['latestBuild']==270 and j['result']=='SUCCESS'
assert j['summarySha256']=='ec9ee51a06d4b9f61c6c0eaf50b374d1e25e6d3ca687908b7596d3a2c794f5d8'
assert read('pre-health-final.json')['deployment']==read('health-final.json')['deployment']
assert read('health-final.json')['http']=={'status':'200','exit':0}
assert read('pre-final-production-verification.json')['objects']==read('final-production-verification.json')['objects']
assert read('final-production-verification.json')['readyEndpoints']==3
a=read('host-before.json');z=read('host-after.json')
assert a['socket']==z['socket'] and z['socket']['mode']=='0660'
assert a['dockerService']==z['dockerService'] and 'NRestarts=0' in z['dockerService']
assert all(n['ready']=='True' for n in z['nodes'])
def stable(rows):
 normalized=[]
 for row in rows:
  row=json.loads(json.dumps(row));row['state'].get('Health',{}).pop('Log',None);normalized.append(row)
 return sorted(normalized,key=lambda x:x['id'])
assert stable(a['containers'])==stable(z['containers'])
assert a['defectdojoPods']==z['defectdojoPods']==[]
for key in ['volumes','statefulsetSpecSha256','environmentConfigurationSha256','pvcs','refreshes']:
 assert read('trivy-storage-before.json')[key]==read('trivy-storage-after.json')[key]
f=(O/'trivy-filesystem-before.stdout').read_text();g=(O/'trivy-filesystem-after.stdout').read_text()
assert f.split('\nFS\n')[0]==g.split('\nFS\n')[0]
assert f.split('\nTEMP_NAMES\n')[1]==g.split('\nTEMP_NAMES\n')[1]
manifest=json.loads((R/'infra/jenkins/gitleaks-validation/manifest.json').read_text())
assert all(sha(R/name)==h for name,h in manifest['files'].items())
result={'protectedFilesUnchanged':len(b['protectedFilesAtStart']),'oldEvidenceAndGateUnchanged':True,'previousLocalVerdictsUnchanged':True,'onlyExistingBuiltinAgent':True,'builtinRejected':True,'sharedUid65534Rejected':True,'jenkinsJobsCreated':0,'jenkinsAgentsCreated':0,'jenkinsBuildsTriggered':0,'realScans':0,'remoteTestResourcesCreated':0,'cleanup':'NOT_REQUIRED_REMOTE; LOCAL_TEMPORARIES_REMOVED','productionSnapshotBeforeAfter':'VERIFIED','continuousProductionHealth':'NOT_CLAIMED','dockerDaemonRestarts':0,'dbRefreshes':0,'dojoExecutions':0,'release':0,'rollout':0,'CI_EXECUTION_READINESS':'CI_EXECUTION_NOT_READY','originalEvidenceIntegrity':'FAILED','canonicalRuntime':'14/16'}
target=O/'verification.json'
if target.exists():assert read('verification.json')==result
else:target.write_text(json.dumps(result,indent=2)+'\n')
print(json.dumps(result))
