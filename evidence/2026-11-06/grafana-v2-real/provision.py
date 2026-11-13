import runpy,pathlib,json,sys,datetime
sys.dont_write_bytecode=True
HERE=pathlib.Path(__file__).resolve().parent
sys.path.insert(0,str(HERE));from keychain_store import operation,SERVICE,ACCOUNT
api=runpy.run_path('evidence/2026-11-05/security-manager-v2-loki/inspect-production.py')
context=(HERE/'grafana_admin_context.py').read_text()
code=context+r'''
assert must('/api/user')['isGrafanaAdmin']
assert not must('/api/serviceaccounts/search?query=security-manager-v2-dashboard').get('serviceAccounts'),'ACCOUNT_ALREADY_EXISTS_STOP'
assert request('/api/folders/security-manager-v2')[0]==404,'FOLDER_ALREADY_EXISTS_STOP'
sa=None;folder=None
try:
 sa=must('/api/serviceaccounts','POST',{'name':'security-manager-v2-dashboard','role':'Viewer','isDisabled':False},expected=(200,201))
 assert sa['role']=='Viewer'and not sa.get('isGrafanaAdmin',False)
 folder=must('/api/folders','POST',{'uid':'security-manager-v2','title':'Security Manager V2 — Controlled Validation'},expected=(200,201))
 must('/api/folders/security-manager-v2/permissions','POST',{'items':[{'role':'Admin','permission':4},{'userId':sa['id'],'permission':2}]})
 permissions=must('/api/folders/security-manager-v2/permissions')
 assert any(p.get('userId')==sa['id']and p.get('permission')==2 for p in permissions)
 assert not any(p.get('role')in ['Viewer','Editor']for p in permissions)
 token=must('/api/serviceaccounts/'+str(sa['id'])+'/tokens','POST',{'name':'security-manager-v2-dashboard-20261106','secondsToLive':86400},expected=(200,201))
 bearer='Bearer '+token['key']
 user=must('/api/user',authorization=bearer);assert user.get('isGrafanaAdmin')is False
 own=must('/api/folders/security-manager-v2',authorization=bearer);assert own.get('canSave')is True and own.get('canAdmin')is False,'FOLDER_SCOPE_NOT_SUFFICIENT'
 rights=must('/api/access-control/user/permissions',authorization=bearer)
 assert rights.get('dashboards:create')and any('security-manager-v2'in s for s in rights['dashboards:create']),'NO_SCOPED_DASHBOARD_CREATE'
 assert not any(s=='folders:*'for s in rights.get('dashboards:create',[])),'GLOBAL_DASHBOARD_CREATE_FORBIDDEN'
 ds=must('/api/datasources/uid/loki',authorization=bearer);assert ds['uid']=='loki'and ds['type']=='loki'
 print(json.dumps({'serviceAccount':{'id':sa['id'],'name':sa['name'],'role':sa['role'],'isGrafanaAdmin':False},'folder':{'uid':folder['uid'],'title':folder['title'],'canSave':own['canSave'],'canAdmin':own['canAdmin']},'tokenMetadata':{'id':token['id'],'name':token['name'],'secondsToLive':86400},'permissions':{key:val for key,val in rights.items()if key in ['dashboards:create','dashboards:write','folders:write','folders:permissions:write','datasources:query','datasources:read']},'folderPermissions':[{key:p.get(key)for key in ['userId','role','permission','permissionName','inherited']}for p in permissions],'token':token['key']}))
except BaseException:
 if sa:request('/api/serviceaccounts/'+str(sa['id']),'DELETE')
 if folder:request('/api/folders/security-manager-v2','DELETE')
 raise
'''
x=json.loads(api['remote']('sudo -n python3 -',code,110))
token=x.pop('token')
try:operation('add',secret=token)
except BaseException:
 rollback=context+f"\nrequest('/api/serviceaccounts/{int(x['serviceAccount']['id'])}','DELETE')\nrequest('/api/folders/security-manager-v2','DELETE')\nprint('PROVISIONING_ROLLED_BACK')\n"
 api['remote']('sudo -n python3 -',rollback,60)
 raise
finally:del token
x['credentialReference']={'store':'macOS Login Keychain','service':SERVICE,'account':ACCOUNT}
x['createdAt']=datetime.datetime.now(datetime.timezone.utc).isoformat();x['adminCredentialExported']=False;x['tokenInRepository']=False
with (HERE/'identity.json').open('x')as f:json.dump(x,f,indent=2)
print(json.dumps(x))
