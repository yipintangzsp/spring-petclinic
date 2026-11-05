from pathlib import Path
import json,runpy,hashlib,base64
O=Path(__file__).resolve().parent;api=runpy.run_path(str(O/'inspect-production.py'))
code=r'''
import pathlib,json,base64,hashlib,re
root=None
for proc in pathlib.Path('/proc').glob('[0-9]*'):
 try:
  p=proc/'root/app'
  if (p/'dojo/tools/generic/json_parser.py').is_file():root=p;break
 except (FileNotFoundError,PermissionError,ProcessLookupError):pass
assert root
files={}
for n in ['dojo/api_v2/__init__.py','dojo/test/api/serializer.py','dojo/test/api/views.py','dojo/test/api/filters.py','dojo/finding/api/serializer.py','dojo/finding/api/filters.py','dojo/product/api/serializer.py','dojo/engagement/api/serializer.py','dojo/api_v2/authentication.py']:
 p=root/n
 if p.is_file() and p.stat().st_size<1000000:
  b=p.read_bytes();files[n]={'sha256':hashlib.sha256(b).hexdigest(),'bytes':len(b),'base64':base64.b64encode(b).decode()}
# Extract only public authentication-class names from distribution source;
# do not read process environment, settings overrides, .env or database.
auth=[]
for n in ['dojo/settings/settings.py','dojo/settings/common.py','dojo/settings/base.py']:
 p=root/n
 if p.is_file():
  for line in p.read_text().splitlines():
   if re.search(r'authentication\.[A-Za-z_]*Authentication',line):auth.append({'source':n,'publicClassDeclaration':line.strip()})
print(json.dumps({'files':files,'publicAuthenticationDeclarations':auth,'credentialsRead':False,'authenticatedAPIRequests':0,'databaseQueries':0}))
'''
x=json.loads(api['remote']('sudo -n python3 -',code,90))
for n,record in x['files'].items():
 b=base64.b64decode(record.pop('base64'));assert hashlib.sha256(b).hexdigest()==record['sha256'];p=O/'installed-api'/n;p.parent.mkdir(parents=True,exist_ok=True)
 with p.open('xb') as f:f.write(b)
api['save']('installed-api-supplement.json',x);print(json.dumps({'sources':list(x['files']),'authClasses':x['publicAuthenticationDeclarations'],'credentialsRead':False,'authenticatedAPIRequests':0}))
