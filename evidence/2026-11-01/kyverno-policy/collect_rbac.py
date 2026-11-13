import subprocess,json,shlex
from pathlib import Path
script=r'''
import subprocess,json
sa='system:serviceaccount:devsecops-system:kyverno-admission-controller'
def k(args):
 p=subprocess.run(['sudo','-n','kubectl','--request-timeout=5s']+args,capture_output=True,text=True,timeout=7)
 if p.returncode:raise RuntimeError('Read-only command failed: '+str(p.returncode))
 return p.stdout
checks=[]
for resource in ['customresourcedefinitions.apiextensions.k8s.io/clusterpolicies.kyverno.io','customresourcedefinitions.apiextensions.k8s.io/policies.kyverno.io']:
 checks.append({'resource':resource,'value':k(['auth','can-i','get',resource,'--as='+sa])})
x={'deployment':json.loads(k(['-n','devsecops-system','get','deploy','kyverno-admission-controller','-o','json'])),'readChecks':checks,'role':json.loads(k(['get','clusterrole','kyverno:admission-controller','-o','json'])),'application':json.loads(k(['-n','argocd','get','application','platform-devsecops','-o','json']))}
# Keep only actual fields consumed by unchanged rbac-contract; never export Pod env or Secret.
x['deployment']={'metadata':{'uid':x['deployment']['metadata']['uid']},'status':{'availableReplicas':x['deployment']['status'].get('availableReplicas')}}
x['application']={'status':{'sync':{'status':x['application']['status']['sync']['status']},'health':{'status':x['application']['status']['health']['status']}}}
x['role']={'metadata':{'uid':x['role']['metadata']['uid']},'rules':x['role']['rules']}
print(json.dumps(x))
'''
p=subprocess.run(['ssh','-o','BatchMode=yes','-o','ConnectTimeout=5','-o','StrictHostKeyChecking=yes','-o','HostName=192.168.64.11','-o','HostKeyAlias=192.168.1.58','zhang@192.168.1.58','python3 -'],input=script,capture_output=True,text=True,timeout=45)
if p.returncode:raise RuntimeError(p.stderr[-400:])
x=json.loads(p.stdout);Path(__file__).with_name('current-rbac-facts.json').write_text(json.dumps(x,indent=2));print('Collected existing RBAC facts; no resources changed.')
