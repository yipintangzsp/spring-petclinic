"""Check whether the approved unprivileged writer can independently read real Gate proof."""
import json,runpy
from pathlib import Path
OUT=Path(__file__).resolve().parent
prior=OUT.parents[1]/'2026-11-05'
m=runpy.run_path(str(prior/'security-manager-v2-loki/inspect-production.py'))
code=r'''
import json,pathlib,subprocess,urllib.request,urllib.error,datetime
root=pathlib.Path('/var/tmp/security-manager-gitleaks-v2-linux-20261105/outputs')
run=root/'web-655884ff-c600-400f-95e8-e7b92df6340a'
files=[str(v.relative_to(run)) for v in run.rglob('gitleaks.result.json')]
assert len(files)==1
target=str(run/files[0])
probe="import os,json; p="+repr(target)+"; print(json.dumps({'uid':os.getuid(),'gid':os.getgid(),'groups':os.getgroups(),'canReadGateResult':os.access(p,os.R_OK),'canTraverseOutput':os.access("+repr(str(root))+",os.X_OK)}))"
r=json.loads(subprocess.check_output(['/usr/bin/setpriv','--reuid=24022','--regid=24022','--clear-groups','--no-new-privs','/usr/bin/python3','-I','-c',probe],text=True,timeout=5))
svcs=json.loads(subprocess.check_output(['kubectl','-n','ns-devops','get','services','-o','json'],text=True,timeout=10))['items']
svc=next(v for v in svcs if v['metadata']['name']=='jenkins')
port=next(v['port'] for v in svc['spec']['ports'] if v['port']==8080)
op=urllib.request.build_opener(urllib.request.ProxyHandler({}))
url='http://'+svc['spec']['clusterIP']+':'+str(port)+'/job/security-gitlab-push-demo/4/artifact/gitleaks-clean-4/evidence/jenkins-gitleaks-receipt.json'
# Real archive path is also tested without any credential, never reusing Jenkins admin auth.
paths=['/job/security-gitlab-push-demo/4/api/json','/job/security-gitlab-push-demo/4/artifact/evidence/jenkins-gitleaks-receipt.json']
statuses=[]
for path in paths:
 try:
  with op.open('http://'+svc['spec']['clusterIP']+':'+str(port)+path,timeout=5) as response:status=response.status
 except urllib.error.HTTPError as e:status=e.code
 except (OSError,urllib.error.URLError):status='UNAVAILABLE'
 statuses.append({'path':path,'unauthenticatedHttp':status})
print(json.dumps({'observedAt':datetime.datetime.now(datetime.timezone.utc).isoformat(),'newIdentityKernelProbe':r,
 'authoritativeResultPath':target,'outputRootMode':oct(root.stat().st_mode&511),'jenkinsUnauthenticatedReads':statuses,
 'accountsCreated':0,'credentialsCreated':0,'gitWrites':0,'scansStarted':0}))
'''
r=json.loads(m['remote']('sudo -n python3 -',code,35))
with (OUT/'proof-access.json').open('x') as f:json.dump(r,f,indent=2)
print(json.dumps(r))
