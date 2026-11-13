import json,pathlib,runpy,sys
sys.dont_write_bytecode=True
HERE=pathlib.Path(__file__).resolve().parent
sys.path.insert(0,str(HERE));from keychain_store import probe
probe()
api=runpy.run_path('evidence/2026-11-05/security-manager-v2-loki/inspect-production.py')
code=r'''
import json,subprocess,base64,urllib.request,urllib.error,urllib.parse,datetime
k=lambda args:json.loads(subprocess.check_output(['kubectl']+args,text=True,timeout=20))
s=k(['-n','monitoring','get','secret','kube-stack-grafana','-o','json'])['data']
auth='Basic '+base64.b64encode(base64.b64decode(s['admin-user'])+b':'+base64.b64decode(s['admin-password'])).decode();del s
op=urllib.request.build_opener(urllib.request.ProxyHandler({}))
base='http://'+k(['-n','monitoring','get','svc','kube-stack-grafana','-o','json'])['spec']['clusterIP']
def get(path):
 try:
  with op.open(urllib.request.Request(base+path,headers={'Authorization':auth}),timeout=12)as r:return {'status':r.status,'body':json.load(r)}
 except urllib.error.HTTPError as e:return {'status':e.code}
u=get('/api/user');assert u['status']==200 and u['body']['isGrafanaAdmin'],'MANAGEMENT_AUTH_NOT_VALID'
sa=get('/api/serviceaccounts/search?query=security-manager-v2-dashboard');assert sa['status']==200
folder=get('/api/folders/security-manager-v2');dash=get('/api/dashboards/uid/security-manager-v2-candidate');ds=get('/api/datasources/uid/loki');assert ds['status']==200 and ds['body']['type']=='loki'
selector='{service_name="security-manager-v2",environment="validation",schema_version="1",job="devsecops-security-v2"}'
run='web-a6dff8bd-0534-479b-bdb3-8c2c39fb4de8';q=selector+' |= '+json.dumps(run)
params=urllib.parse.urlencode({'query':q,'start':'1793939484000000000','end':'1793939487000000000','limit':10})
loki='http://'+k(['-n','monitoring','get','svc','loki','-o','json'])['spec']['clusterIP']+':3100'
with op.open(loki+'/loki/api/v1/query_range?'+params,timeout=15)as r:response=json.load(r)
events=[json.loads(v[1])for stream in response['data']['result']for v in stream['values']]
assert events,'REAL_LOKI_RUN_UNAVAILABLE'
assert all(e['runId']==run and e['pluginId']=='semgrep' and e['policyDecision']=='PASS'and e['resultDigest']=='ac9af2aed118135532fa5468fdeecf912399f4bf31790f5e2de568e9bbed06c2'for e in events)
print(json.dumps({'at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'managementEntry':'strict SSH / existing Grafana deployment administrator, credential stays on host','managementAuthenticated':True,'keychainStorageProbe':'VERIFIED','serviceAccounts':[{'id':a['id'],'name':a['name'],'role':a['role']}for a in sa['body'].get('serviceAccounts',[])],'folderStatus':folder['status'],'dashboardStatus':dash['status'],'datasource':{'uid':ds['body']['uid'],'type':ds['body']['type'],'url':ds['body']['url']},'lokiRun':{'runId':run,'matches':len(events),'event':events[0]},'grafanaWrites':0}))
'''
x=json.loads(api['remote']('sudo -n python3 -',code,90))
with (HERE/'preflight.json').open('x')as f:json.dump(x,f,indent=2)
print(json.dumps(x))
