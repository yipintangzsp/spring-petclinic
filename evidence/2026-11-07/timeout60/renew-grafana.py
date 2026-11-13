# Only run after explicit approval to replace the SAME account's short-lived token.
import pathlib,sys,runpy,json,datetime
sys.dont_write_bytecode=True
h=pathlib.Path(__file__).resolve().parent;old=pathlib.Path('evidence/2026-11-06/grafana-v2-real');sys.path.insert(0,str(old.resolve()));from keychain_store import operation,SERVICE,ACCOUNT
api=runpy.run_path('evidence/2026-11-05/security-manager-v2-loki/inspect-production.py');identity=json.loads((old/'identity.json').read_text());sid=int(identity['serviceAccount']['id']);context=(old/'grafana_admin_context.py').read_text()
code=context+r'''
sa=must('/api/serviceaccounts/@SA@');assert sa['name']=='security-manager-v2-dashboard'and sa['role']=='Viewer'and not sa.get('isDisabled',False)
folderBefore=must('/api/folders/security-manager-v2/permissions');dashboardBefore=must('/api/dashboards/uid/security-manager-v2-candidate')['dashboard']
assert any(p.get('userId')==@SA@and p['permission']==2 for p in folderBefore)
token=must('/api/serviceaccounts/@SA@/tokens','POST',{'name':'security-manager-v2-dashboard-20261107-renew','secondsToLive':86400},expected=(200,201));auth='Bearer '+token['key']
try:
 user=must('/api/user',authorization=auth);assert not user.get('isGrafanaAdmin',False)
 rights=must('/api/access-control/user/permissions',authorization=auth);assert rights.get('dashboards:create')and not any(v=='folders:*'for v in rights['dashboards:create'])
 assert must('/api/datasources/uid/loki',authorization=auth)['type']=='loki'
 assert must('/api/folders/security-manager-v2/permissions')==folderBefore
 assert must('/api/dashboards/uid/security-manager-v2-candidate')['dashboard']==dashboardBefore
 print(json.dumps({'serviceAccountId':@SA@,'serviceAccountName':sa['name'],'role':sa['role'],'tokenId':token['id'],'secondsToLive':86400,'sameAccount':True,'permissionsChanged':False,'dashboardChanged':False,'token':token['key']}))
except BaseException:
 request('/api/serviceaccounts/@SA@/tokens/'+str(token['id']),'DELETE');raise
'''.replace('@SA@',str(sid))
x=json.loads(api['remote']('sudo -n python3 -',code,75));token=x.pop('token');previous=operation('get')
try:
 operation('delete')
 try:operation('add',secret=token)
 except BaseException:operation('add',secret=previous);raise
except BaseException:
 api['remote']('sudo -n python3 -',context+"\nrequest('/api/serviceaccounts/"+str(sid)+"/tokens/"+str(x['tokenId'])+"','DELETE')\n",45);raise
finally:del token;del previous
x['credentialReference']={'store':'macOS Login Keychain','service':SERVICE,'account':ACCOUNT};x['renewedAt']=datetime.datetime.now(datetime.timezone.utc).isoformat();x['tokenInEvidence']=False;x['adminCredentialExported']=False
with(h/'grafana-renewal.json').open('x')as f:json.dump(x,f,indent=2)
print(json.dumps(x))
