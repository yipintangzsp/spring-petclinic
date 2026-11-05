"""Create only the fixed demo Application; Argo creates the ConfigMap from Git."""
import json
import runpy
from pathlib import Path
OUT=Path(__file__).resolve().parent
p=runpy.run_path(str(OUT.parent/'security-manager-v2-loki/inspect-production.py'))
plan=json.loads((OUT/'prepared.json').read_text())
assert json.loads((OUT/'push-baseline.json').read_text())['commit']==plan['commits']['baseline']['commit']
app=json.loads((OUT/'application.json').read_text())
code=r'''
import json,subprocess,datetime
app=json.loads(@APP@)
assert app['metadata']['name']=='petclinic-gitops-demo' and app['metadata']['namespace']=='argocd'
assert not app['metadata'].get('finalizers')
assert app['spec']['source']=={'repoURL':'http://gitlab-service.ns-devops.svc.cluster.local/root/petclinic-platform.git','targetRevision':'security-demo/gitops-20261105','path':'infra/devops-lab/gitops-demo','directory':{'recurse':False,'include':'configmap.yaml'}}
assert app['spec']['destination']=={'server':'https://kubernetes.default.svc','namespace':'devsecops-test'}
assert app['spec']['syncPolicy']['automated']['prune'] is False
def k(args,input=None):return subprocess.check_output(['kubectl']+args,input=input,text=True,timeout=15)
assert not json.loads(k(['-n','argocd','get','application','petclinic-gitops-demo','--ignore-not-found','-o','json']) or 'null')
k(['create','--dry-run=server','-f','-','-o','name'],json.dumps(app))
result=json.loads(k(['create','-f','-','-o','json'],json.dumps(app)))
print(json.dumps({'createdAt':datetime.datetime.now(datetime.timezone.utc).isoformat(),'namespace':'argocd','name':result['metadata']['name'],'uid':result['metadata']['uid'],'spec':result['spec'],'configMapDirectWrite':False}))
'''.replace('@APP@',repr(json.dumps(app)))
result=json.loads(p['remote']('sudo -n python3 -',code,45))
with (OUT/'application-created.json').open('x') as f:json.dump(result,f,indent=2)
print(json.dumps(result))
