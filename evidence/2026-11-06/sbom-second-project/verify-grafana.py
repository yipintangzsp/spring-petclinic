import pathlib,json,sys,runpy,shlex,urllib.parse
sys.dont_write_bytecode=True
HERE=pathlib.Path(__file__).resolve().parent;sys.path.insert(0,str(HERE.parent/'grafana-v2-real'))
from keychain_store import operation
api=runpy.run_path('evidence/2026-11-05/security-manager-v2-loki/inspect-production.py')
run=json.loads((HERE/'real-result.json').read_text());assert run['lokiDelivery']['state']=='DELIVERED'
code=r'''
import json,sys,urllib.request,urllib.error,urllib.parse,datetime
p=json.load(sys.stdin);run=p['run'];op=urllib.request.build_opener(urllib.request.ProxyHandler({}));base='http://10.43.55.143'
def query(path,body=None):
 req=urllib.request.Request(base+path,data=None if body is None else json.dumps(body).encode(),headers={'Authorization':'Bearer '+p['token'],'Content-Type':'application/json'})
 try:
  with op.open(req,timeout=25)as r:return json.load(r)
 except urllib.error.HTTPError as e:raise RuntimeError('GRAFANA_HTTP_'+str(e.code))from None
user=query('/api/user');assert user.get('isGrafanaAdmin')is False
saved=query('/api/dashboards/uid/security-manager-v2-candidate');assert saved['meta']['folderUid']=='security-manager-v2'
variables=urllib.parse.parse_qs(urllib.parse.urlparse(run['lokiDelivery']['grafanaUrl']).query)
assert variables['var-run']==[run['runId']]and variables['var-resultDigest']==[run['resultDigest']]
start=variables['from'][0];end=variables['to'][0];period=str((int(end)-int(start))//1000)+'s'
models=[];panelByRef={}
for panel in saved['dashboard']['panels']:
 for target in panel.get('targets',[]):
  expr=target['expr']
  for key in ['project','run','resultDigest']:expr=expr.replace('${'+key+':json}',json.dumps(variables['var-'+key][0]))
  expr=expr.replace('$__range',period);ref=str(panel['id'])+'-'+target['refId'];panelByRef[ref]=panel['id']
  models.append({'refId':ref,'datasource':{'type':'loki','uid':'loki'},'expr':expr,'queryType':target['queryType'],'instant':target['queryType']=='instant','range':target['queryType']=='range','intervalMs':1000,'maxLines':50,'maxDataPoints':200})
response=query('/api/ds/query',{'from':start,'to':end,'queries':models});panels={str(n):{'rows':0,'state':'NO_DATA'}for n in range(1,8)}
for ref,result in response['results'].items():
 assert not result.get('error'),'GRAFANA_PANEL_ERROR'
 rows=sum(max([len(a)for a in f.get('data',{}).get('values',[])]+[0])for f in result.get('frames',[]))
 pan=panels[str(panelByRef[ref])];pan['rows']+=rows
 if rows:pan['state']='DATA'
wrong={**models[0],'refId':'WRONG_PROJECT','expr':models[0]['expr'].replace(json.dumps(run['projectId']),json.dumps('java-sbom-demo'))};negative=query('/api/ds/query',{'from':start,'to':end,'queries':[wrong]});assert run['runId']not in json.dumps([f.get('data',{}).get('values',[])for v in negative.get('results',{}).values()for f in v.get('frames',[])]),'CROSS_PROJECT_GRAFANA_LEAK'
actual=json.dumps([f.get('data',{}).get('values',[])for f in response['results']['1-A'].get('frames',[])])
assert run['runId']in actual and run['resultDigest']in actual and 'REAL_CONTROLLED_EXECUTION'in actual,'NEW_REAL_RUN_NOT_FOUND_IN_GRAFANA'
req=urllib.request.Request(base+urllib.parse.urlparse(run['lokiDelivery']['grafanaUrl']).path,headers={'Authorization':'Bearer '+p['token']})
with op.open(req,timeout=10)as r:assert r.status==200
print(json.dumps({'verifiedAt':datetime.datetime.now(datetime.timezone.utc).isoformat(),'dashboardApiStatus':200,'grafanaQueryApiStatus':200,'dashboardHttpStatus':200,'nonAdminServiceAccount':True,'dashboardUid':saved['dashboard']['uid'],'url':run['lokiDelivery']['grafanaUrl'],'runId':run['runId'],'pluginId':run['pluginId'],'policyDecision':run['policyDecision'],'resultDigest':run['resultDigest'],'sourceClassification':'REAL_CONTROLLED_EXECUTION','panelResults':panels,'dataPanelCount':sum(pan['state']=='DATA'for pan in panels.values()),'totalPanelCount':8,'queryPanelCount':7,'staticPanel':8,'wrongProjectDoesNotReturnRun':True,'projectId':run['projectId'],'dashboardChanged':False,'permissionsChanged':False,'newScansInVerifier':0}))
'''
token=operation('get')
try:x=json.loads(api['remote']('python3 -c '+shlex.quote(code),json.dumps({'token':token,'run':run}),70))
finally:del token
with (HERE/'grafana-query.json').open('x')as f:json.dump(x,f,indent=2)
print(json.dumps(x))
