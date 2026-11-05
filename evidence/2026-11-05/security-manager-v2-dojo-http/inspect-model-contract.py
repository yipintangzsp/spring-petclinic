from pathlib import Path
import runpy,json,base64,hashlib
O=Path(__file__).resolve().parent;api=runpy.run_path(str(O/'inspect-production.py'))
code=r'''
from pathlib import Path
import json,base64,hashlib
root=None
for proc in Path('/proc').glob('[0-9]*'):
 try:
  p=proc/'root/app'
  if (p/'dojo/tools/generic/json_parser.py').is_file():root=p;break
 except (FileNotFoundError,PermissionError,ProcessLookupError):pass
assert root
files={}
for n in ['dojo/test/models.py','dojo/test/api/urls.py','dojo/product/api/urls.py','dojo/engagement/api/urls.py','dojo/finding/api/urls.py','dojo/importers/default_importer.py','dojo/importers/base_importer.py']:
 p=root/n
 if p.is_file() and p.stat().st_size<1000000:
  b=p.read_bytes();files[n]={'sha256':hashlib.sha256(b).hexdigest(),'bytes':len(b),'base64':base64.b64encode(b).decode()}
print(json.dumps({'files':files,'credentialsRead':False,'databaseQueries':0,'httpRequests':0}))
'''
x=json.loads(api['remote']('sudo -n python3 -',code,90))
for n,record in x['files'].items():
 b=base64.b64decode(record.pop('base64'));assert hashlib.sha256(b).hexdigest()==record['sha256'];p=O/'installed-api'/n;p.parent.mkdir(parents=True,exist_ok=True)
 with p.open('xb') as f:f.write(b)
api['save']('installed-model-contract.json',x);print(json.dumps({'sources':list(x['files']),'credentialsRead':False,'databaseQueries':0}))
