"""Bounded read-only followup. Preserve UNKNOWN instead of aborting partial evidence."""
from pathlib import Path
import json,runpy,concurrent.futures,datetime
O=Path(__file__).resolve().parent;a=runpy.run_path(str(O/'inspect-production.py'))
code=r'''
import subprocess,json,datetime,os,urllib.request,urllib.error
r={'at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'classification':'BOUNDED_READ_ONLY_HEALTH_FOLLOWUP','mutations':0,'checks':{}}
def run(name,args,timeout=10):
 try:
  p=subprocess.run(args,text=True,capture_output=True,timeout=timeout);r['checks'][name]={'exit':p.returncode,'stdout':p.stdout,'stderr':p.stderr[:600]}
 except subprocess.TimeoutExpired:r['checks'][name]={'status':'UNKNOWN','error':'TIMEOUT'}
run('uptime',['uptime']);run('memory',['free','-m']);run('disk',['df','-h','/']);run('k3s',['systemctl','show','k3s','-p','ActiveState','-p','SubState','-p','NRestarts','-p','MainPID']);run('nodes',['kubectl','get','nodes','--request-timeout=5s','-o','json']);run('petclinic',['kubectl','-n','petclinic','get','deploy','petclinic','--request-timeout=5s','-o','json']);run('argo',['kubectl','-n','argocd','get','application','petclinic','--request-timeout=5s','-o','json'])
for name,url,host in [('petclinicHTTP','http://192.168.64.11/','petclinic.devops.local')]:
 try:
  q=urllib.request.Request(url,headers={'Host':host});s=urllib.request.build_opener(urllib.request.ProxyHandler({})).open(q,timeout=5);status=s.status;s.close()
 except urllib.error.HTTPError as e:status=e.code
 except (urllib.error.URLError,TimeoutError):status='UNREACHABLE'
 r['checks'][name]={'status':status}
print(json.dumps(r))
'''
r={'classification':'READ_ONLY_PRODUCTION_FOLLOWUP','recordedAt':datetime.datetime.now(datetime.timezone.utc).isoformat()}
with concurrent.futures.ThreadPoolExecutor(max_workers=2)as ex:
 tasks={'host':ex.submit(a['remote'],'sudo -n python3 -',code,75),'jenkins':ex.submit(a['jenkins'])}
 for name,t in tasks.items():
  try:r[name]=json.loads(t.result())if name=='host'else t.result()
  except Exception as e:r[name]={'status':'UNKNOWN','errorClass':type(e).__name__}
a['save']('health-followup.json',r);print(json.dumps(r))
