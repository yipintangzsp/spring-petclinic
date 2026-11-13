"""Check review artifacts for accidental current proxy private-value disclosure.
Never emits values, lengths or digests of matching private values.
This is a scoped check, not a claim to detect every possible secret.
"""
from pathlib import Path
import json,sqlite3,re
O=Path(__file__).resolve().parent;root=Path('/Users/zhangsir/Library/Application Support/v2rayN')
private=set()
def add(v):
 if isinstance(v,str) and len(v)>=8 and v not in ['127.0.0.1','localhost'] and not v.endswith('.invalid'):private.add(v)
def walk(x):
 if isinstance(x,dict):
  for k,v in x.items():
   if re.search(r'^(address|server|password|username|id|uuid|privatekey|publickey|url)$',k,re.I):add(v)
   walk(v)
 elif isinstance(x,list):
  for y in x:walk(y)
walk(json.loads((root/'binConfigs/config.json').read_text()))
gui=json.loads((root/'guiConfigs/guiNConfig.json').read_text());add(gui.get('IndexId'))
con=sqlite3.connect('file:'+str(root/'guiConfigs/guiNDB.db')+'?mode=ro',uri=True)
con.execute('PRAGMA query_only=ON');con.execute('BEGIN')
for row in con.execute('SELECT Url,MoreUrl FROM SubItem'):
 for v in row:add(v)
for row in con.execute('SELECT Address,Id,Password,Username FROM ProfileItem WHERE IndexId=?',(gui.get('IndexId'),)):
 for v in row:add(v)
con.rollback();con.close()
scanned=0;violations=[]
for p in sorted(O.rglob('*')):
 if not p.is_file() or p.is_symlink() or '__pycache__' in p.parts or 'v1-tree' in p.parts:continue
 if p.name in ['private-value-check.json','evidence-sha256.json']:continue
 if p.stat().st_size>10*1024**2:continue
 text=p.read_text(errors='replace');scanned+=1
 if any(v in text for v in private):violations.append(str(p.relative_to(O)))
result={'classification':'SCOPED_IN_MEMORY_KNOWN_CURRENT_PROXY_PRIVATE_VALUE_CHECK','filesScanned':scanned,'matchingArtifactPaths':violations,'privateValuesPrinted':False,'privateValuesArchivedByCheck':False,'rawConfigOrDatabaseArchived':False,'scopeLimit':'Current runtime identity/credential fields, selected local profile, subscription URLs only; no claim about unknown historical secret values','passed':not violations}
(O/'private-value-check.json').write_text(json.dumps(result,indent=2)+'\n')
print(json.dumps({'passed':not violations,'filesScanned':scanned,'matchCount':len(violations)}))
if violations:raise SystemExit(1)
