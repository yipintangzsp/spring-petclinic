"""Installed public API code and unauthenticated GET probes only. No credential reads."""
from pathlib import Path
import runpy,json,base64,hashlib
O=Path(__file__).resolve().parent;api=runpy.run_path(str(O/'inspect-production.py'))
code=r'''
import pathlib,json,hashlib,base64,urllib.request,urllib.error
root=None
for proc in pathlib.Path('/proc').glob('[0-9]*'):
 try:
  p=proc/'root/app'
  if (p/'dojo/tools/generic/json_parser.py').is_file():root=p;break
 except (FileNotFoundError,PermissionError,ProcessLookupError):pass
assert root
names=['dojo/__init__.py','dojo/urls.py','dojo/api_v2/urls.py','dojo/api_v2/serializers.py','dojo/api_v2/views.py','dojo/api_v2/permissions.py','dojo/api_v2/filters.py','dojo/api_v2/prefetch.py','dojo/tools/generic/json_parser.py']
files={}
for n in names:
 p=root/n
 if p.is_file() and p.stat().st_size<2000000:
  b=p.read_bytes();files[n]={'sha256':hashlib.sha256(b).hexdigest(),'bytes':len(b),'base64':base64.b64encode(b).decode()}
opener=urllib.request.build_opener(urllib.request.ProxyHandler({}));probes=[]
for url in ['http://127.0.0.1/api/v2/products/','http://127.0.0.1/api/v2/engagements/','http://127.0.0.1/api/v2/tests/','http://127.0.0.1/api/v2/findings/','http://127.0.0.1/api/v2/test_types/']:
 try:
  r=opener.open(urllib.request.Request(url,headers={'Host':'defectdojo.devops.local','Accept':'application/json'}),timeout=10)
  status=r.status;auth=r.headers.get('WWW-Authenticate');body=r.read(1024)
 except urllib.error.HTTPError as e:status=e.code;auth=e.headers.get('WWW-Authenticate');body=e.read(1024)
 probes.append({'path':url.split('127.0.0.1')[1],'method':'GET','status':status,'authChallenge':auth,'bodySha256':hashlib.sha256(body).hexdigest(),'credentialUsed':False})
compose=pathlib.Path('/opt/defectdojo/compose.json')
print(json.dumps({'classification':'INSTALLED_PUBLIC_API_SOURCE_AND_UNAUTHENTICATED_GET_ONLY','files':files,'probes':probes,'composeSha256':hashlib.sha256(compose.read_bytes()).hexdigest(),'credentialsRead':False,'realDojoWrites':0,'nonprodProduct':'UNKNOWN','nonprodIdentity':'NOT_READY'}))
'''
x=json.loads(api['remote']('sudo -n python3 -',code,120))
for n,record in x['files'].items():
 b=base64.b64decode(record.pop('base64'));assert hashlib.sha256(b).hexdigest()==record['sha256'];p=O/'installed-api'/n;p.parent.mkdir(parents=True,exist_ok=True)
 with p.open('xb') as f:f.write(b)
api['save']('installed-api-inspection.json',x);print(json.dumps({'sources':list(x['files']),'probes':x['probes'],'nonprodProduct':x['nonprodProduct'],'nonprodIdentity':x['nonprodIdentity'],'credentialsRead':False,'realDojoWrites':0}))
