import pathlib,runpy,json,sys,shlex
sys.dont_write_bytecode=True
h=pathlib.Path(__file__).resolve().parent;sys.path.insert(0,str(pathlib.Path('evidence/2026-11-06/grafana-v2-real').resolve()));from keychain_store import operation
api=runpy.run_path('evidence/2026-11-05/security-manager-v2-loki/inspect-production.py');run=json.loads(pathlib.Path('evidence/2026-11-07/timeout60/real-run.json').read_text())
code=r'''
import sys,json,urllib.request,urllib.parse,datetime
x=json.load(sys.stdin);run=x['run'];o=urllib.request.build_opener(urllib.request.ProxyHandler({}));base='http://10.43.55.143'
def q(path,body=None):
 r=urllib.request.Request(base+path,data=None if body is None else json.dumps(body).encode(),headers={'Authorization':'Bearer '+x['token'],'Content-Type':'application/json'})
 with o.open(r,timeout=15)as f:return json.load(f)
user=q('/api/user');assert not user.get('isGrafanaAdmin');d=q('/api/dashboards/uid/security-manager-v2-candidate');v=urllib.parse.parse_qs(urllib.parse.urlparse(run['lokiDelivery']['grafanaUrl']).query);target=d['dashboard']['panels'][0]['targets'][0];expr=target['expr']
for key in ['project','run','resultDigest']:expr=expr.replace('${'+key+':json}',json.dumps(v['var-'+key][0]))
r=q('/api/ds/query',{'from':v['from'][0],'to':v['to'][0],'queries':[{'refId':'A','datasource':{'type':'loki','uid':'loki'},'expr':expr,'queryType':'range','range':True,'instant':False,'intervalMs':1000,'maxLines':2,'maxDataPoints':20}]});a=r['results']['A'];assert not a.get('error');values=json.dumps([f.get('data',{}).get('values',[])for f in a.get('frames',[])]);assert run['runId']in values and run['resultDigest']in values
print(json.dumps({'at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'dashboardApi':200,'grafanaLokiQuery':200,'sameRunAndDigestFound':True,'runId':run['runId'],'resultDigest':run['resultDigest'],'nonAdminIdentity':True,'url':run['lokiDelivery']['grafanaUrl'],'writes':0,'newScans':0}))
'''
token=operation('get')
try:x=json.loads(api['remote']('python3 -c '+shlex.quote(code),json.dumps({'run':run,'token':token}),30))
finally:del token
with(h/'grafana-check.json').open('x')as f:json.dump(x,f,indent=2)
print(json.dumps(x))
