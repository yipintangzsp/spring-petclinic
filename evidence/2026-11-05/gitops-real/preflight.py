"""Read-only check of existing rights, exact name collisions and branch isolation."""
import json
import runpy
from pathlib import Path
OUT = Path(__file__).resolve().parent
p = runpy.run_path(str(OUT.parent/'gitlab-push-demo/preflight.py'))
code = p['PREFIX'] + r'''
def project=api('/projects/12')
assert project.path_with_namespace=='root/petclinic-platform'
def branch='security-demo/gitops-20261105'
def exists=api('/projects/12/repository/branches?search=security-demo%2Fgitops-20261105').any{it.name==branch}
def hooks=api('/projects/12/hooks').collect{[id:it.id,branch:it.push_events_branch_filter,strategy:it.branch_filter_strategy,push:it.push_events]}
assert hooks.every{!it.push || it.branch in ['main','security-demo/gitlab-push-20261105']}
println(JsonOutput.toJson([project:project.path_with_namespace,projectId:project.id,branch:branch,branchExists:exists,
 main:api('/projects/12/repository/branches/main').commit.id,autoDevops:project.auto_devops_enabled,hooks:hooks,
 productionJobLastBuild:j.lastBuild.number,productionJobBuilding:j.isBuilding()]))
'''
gitlab = p['script'](code)
assert not gitlab['branchExists'] and not gitlab['productionJobBuilding']
host = r'''
import json,subprocess,hashlib,datetime,os,urllib.request,urllib.error
def k(a):return json.loads(subprocess.check_output(['kubectl']+a,text=True,timeout=12))
def allowed(a):return subprocess.check_output(['kubectl','auth','can-i']+a,text=True,timeout=10).strip()=='yes'
ns=k(['get','namespace','devsecops-test','-o','json'])
apps=k(['-n','argocd','get','applications','-o','json'])
cms=k(['-n','devsecops-test','get','configmaps','-o','json'])
project=k(['-n','argocd','get','appproject','default','-o','json'])
d=k(['-n','petclinic','get','deployment','petclinic','-o','json'])
a=next(v for v in apps['items'] if v['metadata']['name']=='petclinic')
assert ns['status']['phase']=='Active'
assert not any(v['metadata']['name']=='petclinic-gitops-demo' for v in apps['items'])
assert not any(v['metadata']['name']=='petclinic-gitops-demo' for v in cms['items'])
assert not any(r.get('namespace')=='devsecops-test' and r.get('kind')=='ConfigMap' and r.get('name')=='petclinic-gitops-demo' for a in apps['items'] for r in a.get('status',{}).get('resources',[]))
rights={'createApplication':allowed(['create','applications.argoproj.io','-n','argocd']),
 'createConfigMap':allowed(['create','configmaps','-n','devsecops-test']),
 'readConfigMap':allowed(['get','configmaps','-n','devsecops-test'])}
assert all(rights.values())
nodes=k(['get','nodes','-o','json'])
try:
 with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(urllib.request.Request('http://192.168.64.11/',headers={'Host':'petclinic.devops.local'}),timeout=5) as r:http=r.status
except urllib.error.HTTPError as e:http=e.code
except (OSError,urllib.error.URLError):http='UNAVAILABLE'
print(json.dumps({'observedAt':datetime.datetime.now(datetime.timezone.utc).isoformat(),
 'namespace':{'name':ns['metadata']['name'],'uid':ns['metadata']['uid'],'phase':ns['status']['phase']},
 'rights':rights,'appProject':project['spec'],
 'quota':[v['status'] for v in k(['-n','devsecops-test','get','resourcequotas','-o','json'])['items']],
 'production':{'uid':d['metadata']['uid'],'generation':d['metadata']['generation'],'specSha256':hashlib.sha256(json.dumps(d['spec'],sort_keys=True).encode()).hexdigest(),
 'ready':d['status'].get('readyReplicas',0),'desired':d['spec']['replicas'],'image':[v['image'] for v in d['spec']['template']['spec']['containers']],
 'argoRevision':a['status']['sync']['revision'],'argoSync':a['status']['sync']['status'],'argoHealth':a['status']['health']['status'],
 'argoSpecSha256':hashlib.sha256(json.dumps(a['spec'],sort_keys=True).encode()).hexdigest(),
 'nodes':{v['metadata']['name']:next(c['status'] for c in v['status']['conditions'] if c['type']=='Ready') for v in nodes['items']},'http':http,'dockerSocketMode':format(os.stat('/run/docker.sock').st_mode&511,'04o')},'writes':0}))
'''
state = json.loads(p['m']['remote']('sudo -n python3 -',host,70))
assert state['production']['ready']==3 and state['production']['http']==200
with (OUT/'preflight.json').open('x') as f:
    json.dump({'gitlab':gitlab,'host':state},f,indent=2)
print(json.dumps({'gitlab':gitlab,'host':state}))
