"""Small fresh production health receipt; no database, scanner or service mutation."""
import json
import runpy
from pathlib import Path

OUT = Path(__file__).resolve().parent
m = runpy.run_path(str(OUT.parent / 'security-manager-v2-loki/inspect-production.py'))
code = r'''
import json,subprocess,datetime,hashlib,os,urllib.request,urllib.error
def k(args):return json.loads(subprocess.check_output(['kubectl']+args,text=True,timeout=10))
d=k(['-n','petclinic','get','deploy','petclinic','-o','json'])
a=k(['-n','argocd','get','application','petclinic','-o','json'])
n=k(['get','nodes','-o','json'])
try:
 with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(urllib.request.Request('http://192.168.64.11/',headers={'Host':'petclinic.devops.local'}),timeout=5) as r:status=r.status
except urllib.error.HTTPError as e:status=e.code
except (OSError,urllib.error.URLError):status='UNAVAILABLE'
print(json.dumps({'observedAt':datetime.datetime.now(datetime.timezone.utc).isoformat(),
 'ready':d['status'].get('readyReplicas',0),'desired':d['spec']['replicas'],'image':[c['image'] for c in d['spec']['template']['spec']['containers']],
 'deploymentUid':d['metadata']['uid'],'generation':d['metadata']['generation'],'specSha256':hashlib.sha256(json.dumps(d['spec'],sort_keys=True).encode()).hexdigest(),
 'argo':{'sync':a['status']['sync']['status'],'health':a['status']['health']['status'],'revision':a['status']['sync']['revision']},
 'nodes':{v['metadata']['name']:next(c['status'] for c in v['status']['conditions'] if c['type']=='Ready') for v in n['items']},
 'http':status,'dockerSocketMode':format(os.stat('/run/docker.sock').st_mode&511,'04o'),'releaseCount':0,'rolloutCount':0}))
'''
result = json.loads(m['remote']('sudo -n python3 -', code, 45))
with (OUT / 'health.json').open('x') as f:
    json.dump(result, f, indent=2)
print(json.dumps(result))
