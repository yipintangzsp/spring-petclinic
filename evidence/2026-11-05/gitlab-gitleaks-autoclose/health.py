"""Fresh minimal production health observation, no workload writes or scans."""
import json,datetime,runpy
from pathlib import Path
OUT=Path(__file__).resolve().parent
m=runpy.run_path(str(OUT.parent/'security-manager-v2-loki/inspect-production.py'))
code=r'''
import json,subprocess,os,urllib.request,datetime,hashlib
k=lambda a:json.loads(subprocess.check_output(['kubectl']+a,text=True,timeout=15))
p=k(['get','deploy','petclinic','-n','petclinic','-o','json'])
a=k(['get','application','petclinic','-n','argocd','-o','json'])
nodes=k(['get','nodes','-o','json'])
http='NOT_VERIFIED'
try:
 with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(urllib.request.Request('http://192.168.64.11/',headers={'Host':'petclinic.devops.local'}),timeout=8) as r:http=r.status
except Exception:pass
print(json.dumps({'at':datetime.datetime.now(datetime.timezone.utc).isoformat(),
 'ready':p['status'].get('readyReplicas'), 'generation':p['metadata']['generation'],
 'images':[c['image'] for c in p['spec']['template']['spec']['containers']],
 'argoSync':a['status']['sync']['status'],'argoHealth':a['status']['health']['status'],'argoRevision':a['status']['sync']['revision'],
 'nodes':{n['metadata']['name']:next(c['status'] for c in n['status']['conditions'] if c['type']=='Ready') for n in nodes['items']},
 'dockerSocketMode':format(os.stat('/run/docker.sock').st_mode&511,'04o'),'http':http,'mutations':0}))
'''
try:r=json.loads(m['remote']('sudo -n python3 -',code,timeout=65))
except Exception as e:r={'at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'health':'NOT_VERIFIED','error':str(e)[:300]}
with (OUT/'production-health.json').open('x') as f:json.dump(r,f,indent=2)
print(json.dumps(r))
