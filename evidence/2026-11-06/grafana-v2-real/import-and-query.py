"""One independent dashboard import and bounded queries, using only the Viewer SA."""
import json,pathlib,sys,runpy,datetime,hashlib
sys.dont_write_bytecode=True
HERE=pathlib.Path(__file__).resolve().parent;sys.path.insert(0,str(HERE))
from keychain_store import operation
api=runpy.run_path('evidence/2026-11-05/security-manager-v2-loki/inspect-production.py')
pref=json.loads((HERE/'preflight.json').read_text());event=pref['lokiRun']['event']
source=pathlib.Path('infra/security/manager-v2/observability/dashboard.json');dash=json.loads(source.read_text())
assert len(dash['panels'])==8 and dash['uid']=='security-manager-v2-candidate'
when=datetime.datetime.fromisoformat(event['timestamp'].replace('Z','+00:00'))
start=when-datetime.timedelta(seconds=60);end=when+datetime.timedelta(seconds=300)
d=event['resultDigest'];run=event['runId'];project=event['projectId']
def stamp(t):return t.isoformat(timespec='milliseconds').replace('+00:00','Z')
dash['version']=0;dash['id']=None
dash['description']='Historical real controlled scan, from sealed artifact replay into existing Loki. Live Grafana queries; no new scan or production Security Manager activation.'
dash['time']={'from':stamp(start),'to':stamp(end)}
for variable in dash['templating']['list']:
 val={'DS_LOKI':'loki','project':project,'run':run,'resultDigest':d}[variable['name']]
 variable['current']={'text':val,'value':val}
 if variable['name']=='project':
  for option in variable['options']:option['selected']=option['value']==project
p1=dash['panels'][0];p1['title']='Plugin execution — historical REAL validation (REPLAY delivery)'
p1['description']='Actual controlled Semgrep scan; original completedAt preserved. This event is a sealed artifact replay, not a new scan.'
dash['panels'][7]['options']['content']='**CANDIDATE — historical REAL controlled validation**\n\nSource: sealed Semgrep result replayed into existing Loki. Scanner completed **'+event['timestamp']+'**. Default view is fixed to that execution window; Grafana queries existing Loki. No new scanner invocation.\n\nProduction Security Manager **NOT_ACTIVE** · Canonical Runtime **14/16** · Trivy / DefectDojo Runtime **INCOMPLETE** · Summary V2 Migration **INCOMPLETE** · Original Evidence Integrity **FAILED**.\n\nEmpty availability/delivery panels mean **No data**, not PASS or delivery success. This static notice is not a data panel.'
prepared=HERE/'dashboard-import.json'
if prepared.exists():assert json.loads(prepared.read_text())==dash,'PREPARED_DASHBOARD_CHANGED'
else:
 with prepared.open('x')as f:json.dump(dash,f,indent=2)
models=[];panelByRef={}
for p in dash['panels']:
 for target in p.get('targets',[]):
  ref=str(p['id'])+'-'+target['refId'];panelByRef[ref]=p['id']
  expr=target['expr'].replace('${project:json}',json.dumps(project)).replace('${run:json}',json.dumps(run)).replace('${resultDigest:json}',json.dumps(d)).replace('$__range','360s')
  models.append({'refId':ref,'datasource':{'type':'loki','uid':'loki'},'expr':expr,'queryType':target['queryType'],'instant':target['queryType']=='instant','range':target['queryType']=='range','intervalMs':1000,'maxDataPoints':200,'maxLines':50})
params={'dashboard':dash,'queries':{'from':str(int(start.timestamp()*1000)),'to':str(int(end.timestamp()*1000)),'queries':models},'panelByRef':panelByRef,'runId':run,'resultDigest':d}
token=operation('get')
code='import json\nTOKEN='+json.dumps(token)+'\nPARAMS=json.loads('+repr(json.dumps(params))+')\n'+r'''
import json,urllib.request,urllib.error,datetime,hashlib
op=urllib.request.build_opener(urllib.request.ProxyHandler({}));base='http://10.43.55.143'
def call(path,method='GET',body=None):
 req=urllib.request.Request(base+path,data=None if body is None else json.dumps(body).encode(),method=method,headers={'Authorization':'Bearer '+TOKEN,'Content-Type':'application/json'})
 try:
  with op.open(req,timeout=35)as r:return r.status,r.read()
 except urllib.error.HTTPError as e:return e.code,b''
def must(path,method='GET',body=None,expected=(200,)):
 status,body=call(path,method,body)
 if status not in expected:raise RuntimeError('GRAFANA_HTTP_'+str(status)+' '+method+' '+path)
 return json.loads(body)
u=must('/api/user');assert u['isGrafanaAdmin']is False
assert call('/api/dashboards/uid/security-manager-v2-candidate')[0]==404,'EXISTING_DASHBOARD_REFUSE_OVERWRITE'
negativeStatus,_=call('/api/dashboards/db','POST',{'dashboard':dict(PARAMS['dashboard'],uid='security-v2-denied-scope-probe'),'folderUid':'','overwrite':False})
assert negativeStatus==403,'OUTSIDE_FOLDER_PERMISSION_UNEXPECTED'
imported=must('/api/dashboards/db','POST',{'dashboard':PARAMS['dashboard'],'folderUid':'security-manager-v2','overwrite':False,'message':'Independent V2 controlled-validation dashboard; existing dashboards unchanged.'},expected=(200,201))
saved=must('/api/dashboards/uid/security-manager-v2-candidate');assert saved['meta']['folderUid']=='security-manager-v2' and saved['meta']['canSave']is True and len(saved['dashboard']['panels'])==8
actual=must('/api/ds/query','POST',PARAMS['queries'])
results=actual['results'];panels={str(p):{'data':False,'queryErrors':[],'rows':0}for p in range(1,8)}
for ref,r in results.items():
 assert ref in PARAMS['panelByRef']
 p=panels[str(PARAMS['panelByRef'][ref])]
 if r.get('error'):p['queryErrors'].append(r['error'])
 for frame in r.get('frames',[]):
  vals=frame.get('data',{}).get('values',[]);rows=max([len(v)for v in vals]+[0]);p['rows']+=rows;p['data']=p['data']or rows>0
assert not any(p['queryErrors']for p in panels.values()),'PANEL_QUERY_FAILED'
first=json.dumps(results.get('1-A',{}));assert PARAMS['runId']in first and PARAMS['resultDigest']in first,'EXACT_RUN_NOT_FOUND_VIA_GRAFANA'
for p in panels.values():p['status']='DATA'if p['data']else'NO_DATA'
htmlStatus,html=call(imported['url']);assert htmlStatus==200 and b'<!doctype html' in html.lower()
print(json.dumps({'classification':'HISTORICAL_REAL_QUERY_VERIFICATION','queriedAt':datetime.datetime.now(datetime.timezone.utc).isoformat(),'dashboardUid':saved['dashboard']['uid'],'dashboardUrl':'http://grafana.devops.local'+imported['url'],'dashboardApiStatus':200,'dashboardHttpStatus':htmlStatus,'folderUid':saved['meta']['folderUid'],'canSave':saved['meta']['canSave'],'nonAdmin':True,'outsideFolderCreateStatus':negativeStatus,'runId':PARAMS['runId'],'resultDigest':PARAMS['resultDigest'],'panelResults':panels,'dataPanelCount':sum(p['data']for p in panels.values()),'queryPanelCount':7,'totalPanelCount':8,'staticNoticePanel':8,'lokiDatasourceUid':'loki','grafanaQueryApiStatus':200,'matchingRunObserved':True,'executionTime':'2026-11-06T04:31:25.265Z','sourceClassification':'SEALED_ARTIFACT_REPLAY_NOT_NEW_SCAN','productionSecurityManager':'NOT_ACTIVE','realScanThisRound':False,'release':0,'rollout':0}))
'''
try:result=json.loads(api['remote']('python3 -',code,110))
finally:del token,code
result['candidateDashboardSource']={'path':str(source),'sha256':hashlib.sha256(source.read_bytes()).hexdigest()}
with (HERE/'dashboard-result.json').open('x')as f:json.dump(result,f,indent=2)
print(json.dumps(result))
