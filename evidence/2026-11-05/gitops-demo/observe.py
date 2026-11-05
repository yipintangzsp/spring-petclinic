"""Bounded GET-only GitOps demo inventory and production state observation."""
import json
import runpy
from pathlib import Path

OUT = Path(__file__).resolve().parent
m = runpy.run_path(str(OUT.parent / 'security-manager-v2-loki/inspect-production.py'))
CODE = r'''
import json,subprocess,datetime,hashlib,urllib.request,urllib.error
def k(args):return json.loads(subprocess.check_output(['kubectl']+args,text=True,timeout=12))
apps=k(['-n','argocd','get','applications','-o','json'])
namespaces=k(['get','namespaces','-o','json'])
quotas=k(['get','resourcequotas','-A','-o','json'])
d=k(['-n','petclinic','get','deployment','petclinic','-o','json'])
pods=k(['-n','petclinic','get','pods','-l','app=petclinic','-o','json'])
endpoints=k(['-n','petclinic','get','endpointslices','-l','kubernetes.io/service-name=petclinic','-o','json'])
events=k(['-n','petclinic','get','events','--field-selector','type=Warning','-o','json'])
nodes=k(['get','nodes','-o','json'])
op=urllib.request.build_opener(urllib.request.ProxyHandler({}))
try:
 with op.open(urllib.request.Request('http://192.168.64.11/',headers={'Host':'petclinic.devops.local'}),timeout=5) as r:http=r.status
except urllib.error.HTTPError as e:http=e.code
except (OSError,urllib.error.URLError):http='UNAVAILABLE'
a=next(v for v in apps['items'] if v['metadata']['name']=='petclinic')
result={'observedAt':datetime.datetime.now(datetime.timezone.utc).isoformat(),
 'applications':[{'name':v['metadata']['name'],'project':v['spec'].get('project'),
 'source':v['spec'].get('source'),'sources':v['spec'].get('sources'),'destination':v['spec'].get('destination'),
 'syncPolicy':v['spec'].get('syncPolicy'),'sync':v.get('status',{}).get('sync'),'health':v.get('status',{}).get('health'),
 'managedResources':[{'kind':r.get('kind'),'namespace':r.get('namespace'),'name':r.get('name')} for r in v.get('status',{}).get('resources',[])]} for v in apps['items']],
 'namespaceNames':[v['metadata']['name'] for v in namespaces['items']],
 'resourceQuotas':[{'namespace':v['metadata']['namespace'],'name':v['metadata']['name'],'status':v.get('status')} for v in quotas['items']],
 'production':{'deploymentUid':d['metadata']['uid'],'generation':d['metadata']['generation'],
 'specSha256':hashlib.sha256(json.dumps(d['spec'],sort_keys=True).encode()).hexdigest(),
 'desired':d['spec']['replicas'],'ready':d['status'].get('readyReplicas',0),'image':[c['image'] for c in d['spec']['template']['spec']['containers']],
 'pods':[{'name':v['metadata']['name'],'node':v['spec'].get('nodeName'),'phase':v['status']['phase'],'deletionTimestamp':v['metadata'].get('deletionTimestamp'),
 'containers':[{'ready':c['ready'],'restartCount':c['restartCount'],'imageID':c.get('imageID')} for c in v['status'].get('containerStatuses',[])]} for v in pods['items']],
 'readyEndpoints':sum(1 for sl in endpoints['items'] for ep in sl.get('endpoints',[]) if ep.get('conditions',{}).get('ready') is True),
 'warningEvents':[{'reason':v.get('reason'),'lastTimestamp':v.get('lastTimestamp'),'count':v.get('count'),'object':v['involvedObject'].get('name')} for v in events['items']][-10:],
 'nodes':{v['metadata']['name']:next(c['status'] for c in v['status']['conditions'] if c['type']=='Ready') for v in nodes['items']},
 'argo':{'revision':a['status']['sync']['revision'],'sync':a['status']['sync']['status'],'health':a['status']['health']['status'],
 'history':[{'id':h.get('id'),'revision':h.get('revision'),'deployedAt':h.get('deployedAt')} for h in a['status'].get('history',[])][-4:]},'http':http},
 'mutations':0,'releaseCount':0,'rolloutCount':0}
print(json.dumps(result))
'''
result = json.loads(m['remote']('sudo -n python3 -', CODE, 70))
with (OUT / 'observation.json').open('x') as f:
    json.dump(result, f, indent=2)
print(json.dumps(result))
