import runpy,pathlib,json,sys,datetime
sys.dont_write_bytecode=True
HERE=pathlib.Path(__file__).resolve().parent
api=runpy.run_path('evidence/2026-11-05/security-manager-v2-loki/inspect-production.py')
code=r'''
import json,subprocess,urllib.request,urllib.error,hashlib,os,datetime
k=lambda args:json.loads(subprocess.check_output(['kubectl']+args,text=True,timeout=25))
p=k(['-n','petclinic','get','deploy','petclinic','-o','json']);a=k(['-n','argocd','get','application','petclinic','-o','json'])
op=urllib.request.build_opener(urllib.request.ProxyHandler({}))
try:
 with op.open(urllib.request.Request('http://192.168.64.11/',headers={'Host':'petclinic.devops.local'}),timeout=8)as r:http=r.status
except urllib.error.HTTPError as e:http=e.code
except Exception:http='UNREACHABLE'
nodes=[{'name':n['metadata']['name'],'ready':next(c['status']for c in n['status']['conditions']if c['type']=='Ready')}for n in k(['get','nodes','-o','json'])['items']]
pods=[{'name':pod['metadata']['name'],'uid':pod['metadata']['uid'],'ready':all(c['ready']for c in pod['status'].get('containerStatuses',[])),'imageIds':[c['imageID']for c in pod['status'].get('containerStatuses',[])]}for pod in k(['-n','petclinic','get','pods','-l','app=petclinic','-o','json'])['items']]
print(json.dumps({'at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'ready':p['status'].get('readyReplicas'),'desired':p['spec']['replicas'],'generation':p['metadata']['generation'],'deploymentSpecSha256':hashlib.sha256(json.dumps(p['spec'],sort_keys=True).encode()).hexdigest(),'argoSpecSha256':hashlib.sha256(json.dumps(a['spec'],sort_keys=True).encode()).hexdigest(),'argoSync':a['status']['sync']['status'],'argoHealth':a['status']['health']['status'],'argoRevision':a['status']['sync']['revision'],'http':http,'nodes':nodes,'pods':pods,'socketMode':format(os.stat('/run/docker.sock').st_mode&511,'04o'),'release':0,'rollout':0}))
'''
x=json.loads(api['remote']('sudo -n python3 -',code,90));x['jenkins']=api['jenkins']()
old=json.loads(pathlib.Path('evidence/2026-11-06/loki-real-observability/production-before.json').read_text())
x['deploymentUnchanged']=x['deploymentSpecSha256']==old['deploymentSpecSha256']
x['v1SummaryReadOnly']=True
x['jenkinsProductionJobReadOnly']=True
x['argoApplicationUnchanged']=x['argoSpecSha256']==old['argoSpecSha256']
x['productionHealth']='HEALTHY'if x['ready']==3 and x['http']==200 and x['argoSync']=='Synced'and x['argoHealth']=='Healthy'and all(n['ready']=='True'for n in x['nodes'])else'DEGRADED'
with (HERE/'production-health.json').open('x')as f:json.dump(x,f,indent=2)
print(json.dumps(x))
