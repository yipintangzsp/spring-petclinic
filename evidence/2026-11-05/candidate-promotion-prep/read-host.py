"""Fresh narrow K3s health and eligible-node pull route observation; no Secret reads."""
import json,runpy
from pathlib import Path
OUT=Path(__file__).resolve().parent
m=runpy.run_path(str(OUT.parent/'security-manager-v2-loki/inspect-production.py'))
code=r'''
import subprocess,json,datetime,urllib.request,urllib.error,shutil
k=lambda a:json.loads(subprocess.check_output(['kubectl']+a,text=True,timeout=12))
d=k(['-n','petclinic','get','deploy','petclinic','-o','json']);a=k(['-n','argocd','get','application','petclinic','-o','json']);n=k(['get','nodes','-o','json']);e=k(['-n','petclinic','get','endpointslices','-l','kubernetes.io/service-name=petclinic','-o','json'])
p=d['spec']['template']['spec'];c=next(v for v in p['containers'] if v['name']=='petclinic')
op=urllib.request.build_opener(urllib.request.ProxyHandler({}))
def get(url,headers):
 try:
  with op.open(urllib.request.Request(url,headers=headers,method='GET' if headers.get('Host') else 'HEAD'),timeout=5) as r:return r.status
 except urllib.error.HTTPError as e:return e.code
 except (OSError,urllib.error.URLError):return 'UNAVAILABLE'
base='http://127.0.0.1:30050/v2/petclinic/petclinic/manifests/'
digests=['sha256:2fbaea65ab030c56c60c62e3ee9fbe362deb8bbbb8216a891ef4c7bbbcea6d55',c['image'].split('@')[-1]]
print(json.dumps({'observedAt':datetime.datetime.now(datetime.timezone.utc).isoformat(),
 'argo':{'revision':a['status']['sync']['revision'],'sync':a['status']['sync']['status'],'health':a['status']['health']['status'],'source':a['spec']['source']},
 'deployment':{'image':c['image'],'imagePullPolicy':c['imagePullPolicy'],'ready':d['status'].get('readyReplicas',0),'desired':d['spec']['replicas'],'generation':d['metadata']['generation'],
 'observedGeneration':d['status'].get('observedGeneration'),'strategy':d['spec']['strategy'],'resources':c['resources'],'startupProbe':c['startupProbe'],'readinessProbe':c['readinessProbe'],'livenessProbe':c['livenessProbe'],
 'nodeSelector':p.get('nodeSelector'),'imagePullSecretNames':[v['name'] for v in p.get('imagePullSecrets',[])]},
 'nodes':{v['metadata']['name']:{'arch':v['status']['nodeInfo']['architecture'],'conditions':{q['type']:q['status'] for q in v['status']['conditions'] if q['type'] in ['Ready','MemoryPressure','DiskPressure','PIDPressure']}} for v in n['items']},
 'readyEndpoints':sum(1 for sl in e['items'] for ep in sl.get('endpoints',[]) if ep.get('conditions',{}).get('ready') is True),
 'http':get('http://192.168.64.11/',{'Host':'petclinic.devops.local'}),'devopsMirrorHead':{dg:get(base+dg,{'Accept':'application/vnd.oci.image.index.v1+json'}) for dg in digests},
 'devopsRootFreeBytes':shutil.disk_usage('/').free,'noColdPullPerformed':True}))
'''
r=json.loads(m['remote']('sudo -n python3 -',code,50))
with (OUT/'host.json').open('x') as f:json.dump(r,f,indent=2)
print(json.dumps(r))
