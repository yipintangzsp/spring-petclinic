"""Read public installed parser source via process root. Never read env/token/config secrets."""
from pathlib import Path
import runpy,json,hashlib,base64
O=Path(__file__).resolve().parent;api=runpy.run_path(str(O/'inspect-production.py'))
code=r'''
import pathlib,json,os,hashlib,base64
compose=json.loads(pathlib.Path('/opt/defectdojo/compose.json').read_text());images={n:s.get('image') for n,s in compose.get('services',{}).items()}
found={}
for proc in pathlib.Path('/proc').glob('[0-9]*'):
 try:
  for base in ['app','usr/src/app']:
   f=proc/'root'/base/'dojo/tools/generic/parser.py'
   if f.is_file():
    found={'pid':int(proc.name),'base':str(proc/'root'/base)};break
  if found:break
 except (FileNotFoundError,PermissionError,ProcessLookupError):pass
assert found,'Installed Generic parser source not reachable using authorized host context'
root=pathlib.Path(found['base']);files={}
for rel in ['dojo/tools/generic/parser.py','dojo/tools/generic/json_parser.py','dojo/tools/generic/__init__.py','dojo/tools/generic/csv_parser.py','dojo/tools/gitleaks/parser.py','dojo/tools/semgrep/parser.py','dojo/VERSION','dojo/__init__.py']:
 p=root/rel
 if p.is_file() and p.stat().st_size<100000:
  data=p.read_bytes();files[rel]={'sha256':hashlib.sha256(data).hexdigest(),'bytes':len(data),'base64':base64.b64encode(data).decode()}
print(json.dumps({'classification':'REAL_READ_ONLY_INSTALLED_PARSER_SOURCE_NOT_API_IMPORT','images':images,'sourceProcessPid':found['pid'],'files':files,'credentialsRead':False,'httpWrites':0,'dockerAPIUsed':False}))
'''
x=json.loads(api['remote']('sudo -n python3 -',code,90));files=x['files'];dest=O/'installed-dojo-parser'
for n,record in files.items():
 b=base64.b64decode(record.pop('base64'));assert hashlib.sha256(b).hexdigest()==record['sha256'];p=dest/n;p.parent.mkdir(parents=True,exist_ok=True)
 with p.open('xb') as f:f.write(b)
api['save']('installed-parser-inspection.json',x);print(json.dumps({'images':x['images'],'parserFiles':list(files),'credentialsRead':False,'writes':0}))
