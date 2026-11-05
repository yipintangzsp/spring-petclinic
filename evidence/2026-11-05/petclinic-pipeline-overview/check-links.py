"""Small unauthenticated navigation checks plus existing read-only observability endpoints."""
import concurrent.futures,json,subprocess,runpy,urllib.parse
from pathlib import Path
OUT=Path(__file__).resolve().parent
m=runpy.run_path(str(OUT.parent/'security-manager-v2-loki/inspect-production.py'))
URLS={
'security':'http://security.devops.local:17862',
'gitlab':'http://gitlab.devops.local/root/petclinic-platform',
'commit':'http://gitlab.devops.local/root/petclinic-platform/-/commit/9a78cc89f22fa98fb1ffcc43e2ae279299471793',
'jenkins':'http://jenkins.devops.local/job/petclinic-ci/270/',
'harbor':'http://harbor.devops.local/harbor/projects',
'argocd':'http://argocd.devops.local/applications/argocd/petclinic',
'grafana':'http://grafana.devops.local/d/devsecops-control',
'petclinic':'http://petclinic.devops.local/'
}
def check(kv):
 name,url=kv
 p=subprocess.run(['curl','--noproxy','*','-4','--connect-timeout','3','--max-time','6','-sS',
 '-o','/dev/null','-w','%{http_code}',url],capture_output=True,text=True,timeout=8)
 return name,{'url':url,'http':int(p.stdout) if p.stdout.isdigit() else None,'curlExit':p.returncode,
 'classification':'HTTP_REACHABLE' if p.returncode==0 else 'UNAVAILABLE',
 'authenticatedContentVerified':name in ['security','petclinic'] and p.stdout=='200'}
HOST=r"""
import json,subprocess,urllib.request,urllib.parse,time
def query(service,port,path):
 svc=json.loads(subprocess.check_output(['kubectl','-n','monitoring','get','svc',service,'-o','json'],text=True,timeout=8))
 try:
  with urllib.request.build_opener(urllib.request.ProxyHandler({})).open('http://'+svc['spec']['clusterIP']+':'+str(port)+path,timeout=6) as r:return r.status,json.load(r)
 except Exception:return 'UNAVAILABLE',{}
end=int(time.time()*1e9)
s,v=query('loki',3100,'/loki/api/v1/query_range?'+urllib.parse.urlencode({'query':'{namespace="petclinic"}','start':str(end-300*10**9),'end':str(end),'limit':'1'}))
loki={'http':s,'status':v.get('status'),'streams':len(v.get('data',{}).get('result',[])),
 'query':'{namespace="petclinic"}','windowSeconds':300,'limit':1}
s,v=query('kube-stack-kube-prometheus-prometheus',9090,'/api/v1/query?'+urllib.parse.urlencode({'query':'up{namespace="petclinic"}'}))
prom={'http':s,'status':v.get('status'),'targets':[{'job':v['metric'].get('job'),'up':v['value'][1]} for v in v.get('data',{}).get('result',[])]}
cm=json.loads(subprocess.check_output(['kubectl','-n','monitoring','get','configmap','devsecops-dashboard','-o','json'],text=True,timeout=8))
dash=json.loads(next(iter(cm['data'].values())))
print(json.dumps({'loki':loki,'prometheus':prom,'grafanaProvisionedDashboard':{'uid':dash.get('uid'),'title':dash.get('title')}}))
"""
with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
 links=dict(pool.map(check,URLS.items()))
obs=json.loads(m['remote']('sudo -n python3 -',HOST,35))
result={'links':links,'observability':obs}
with (OUT/'links-observability.json').open('x') as f:json.dump(result,f,indent=2)
print(json.dumps(result))
