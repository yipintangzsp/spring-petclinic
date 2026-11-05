"""Read live Application/Deployment/Pod/EndpointSlice state without mutations."""
import runpy,json
from pathlib import Path
OUT=Path(__file__).resolve().parent
m=runpy.run_path(str(OUT.parent/'security-manager-v2-loki/inspect-production.py'))
code=r'''
import json,subprocess,datetime,urllib.request,os
k=lambda a:json.loads(subprocess.check_output(['kubectl']+a,text=True,timeout=15))
a=k(['-n','argocd','get','application','petclinic','-o','json'])
d=k(['-n','petclinic','get','deployment','petclinic','-o','json'])
ns=k(['get','nodes','-o','json'])
ps=k(['-n','petclinic','get','pods','-l','app=petclinic','-o','json'])
e=k(['-n','petclinic','get','endpointslices','-l','kubernetes.io/service-name=petclinic','-o','json'])
pods=[]
for p in ps['items']:
 pods.append({'name':p['metadata']['name'],'uid':p['metadata']['uid'],'node':p['spec'].get('nodeName'),
 'deletionTimestamp':p['metadata'].get('deletionTimestamp'),'phase':p['status'].get('phase'),
 'owners':p['metadata'].get('ownerReferences'),
 'containers':[{'name':c['name'],'desiredImage':c['image'],'running':next(({'image':s.get('image'),'imageID':s.get('imageID'),'ready':s.get('ready'),'restartCount':s.get('restartCount'),'startedAt':s.get('state',{}).get('running',{}).get('startedAt')} for s in p['status'].get('containerStatuses',[]) if s['name']==c['name']),None)} for c in p['spec']['containers']]})
try:
 with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(urllib.request.Request('http://192.168.64.11/',headers={'Host':'petclinic.devops.local'}),timeout=6) as r:http=r.status
except Exception:http='UNAVAILABLE'
print(json.dumps({'observedAt':datetime.datetime.now(datetime.timezone.utc).isoformat(),'classification':'LIVE_READ_ONLY_QUERY_SNAPSHOT',
 'argo':{'source':a['spec'].get('source'),'destination':a['spec'].get('destination'),'sync':a['status']['sync'],'health':a['status']['health'],
 'reconciledAt':a['status'].get('reconciledAt'),'operationPhase':a['status'].get('operationState',{}).get('phase'),
 'lastSyncRevision':a['status'].get('operationState',{}).get('syncResult',{}).get('revision'),'history':a['status'].get('history',[])[-2:]},
 'deployment':{'uid':d['metadata']['uid'],'generation':d['metadata']['generation'],'revision':d['metadata']['annotations'].get('deployment.kubernetes.io/revision'),
 'observedGeneration':d['status'].get('observedGeneration'),'ready':d['status'].get('readyReplicas'),'desired':d['spec']['replicas'],
 'containers':[{k:c[k] for k in ['name','image']} for c in d['spec']['template']['spec']['containers']]},
 'nodes':{n['metadata']['name']:{'arch':n['status']['nodeInfo']['architecture'],'os':n['status']['nodeInfo']['operatingSystem'],'ready':next(c['status'] for c in n['status']['conditions'] if c['type']=='Ready')} for n in ns['items']},
 'pods':pods,'endpoints':[{'addresses':ep['addresses'],'conditions':ep.get('conditions'),'pod':ep.get('targetRef',{}).get('name')} for s in e['items'] for ep in s.get('endpoints',[])],
 'http':http,'dockerSocketMode':format(os.stat('/run/docker.sock').st_mode&511,'04o'),'release':0,'rollout':0}))
'''
r=json.loads(m['remote']('sudo -n python3 -',code,65))
with (OUT/'host.json').open('x') as f:json.dump(r,f,indent=2)
print(json.dumps(r))
