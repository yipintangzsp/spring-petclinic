"""Repair our accidental replay-output write, ONLY on a pre-round SHA match.

These are synthetic replay fixtures, not production/runtime facts. Their two
VM report wall-clock strings are the only changing bytes. Candidate recovery
bytes are accepted solely if the full file SHA equals the captured original.
No historical hash manifest or real execution timestamp is edited.
"""
from pathlib import Path
import json,re,hashlib,datetime,time,subprocess
OUT=Path(__file__).resolve().parent;ROOT=OUT.parents[2]
incident=json.loads((OUT/'legacy-evidence-incident.json').read_text());wanted=incident['preRoundHashes']
rows=json.loads((OUT/'legacy-regression-generated-output/evidence/2026-11-01/command-parent/differential.json').read_text())['records']
regex=re.compile(rb'2026-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z')
parse=lambda s:int(datetime.datetime.fromisoformat(s.replace('Z','+00:00')).timestamp()*1000)
fmt=lambda t:datetime.datetime.fromtimestamp(t/1000,datetime.timezone.utc).isoformat(timespec='milliseconds').replace('+00:00','Z').encode()
recovered={};anchors={}
for catalog,filename in [('semgrep-pass','historical-audit-report-replayed'),('semgrep-fail','semgrep-create-failed')]:
 target='evidence/2026-11-01/command-parent/fixtures/'+filename+'.json'
 current=json.loads((ROOT/target).read_text());raw=json.loads((ROOT/'infra/security/manager-v2/fixtures'/ (catalog+'.json')).read_text());value={'input':current['input'],'raw':raw}
 # V8 JSON formatting, including floats and string escaping, must match original.
 data=subprocess.check_output(['node','--input-type=module','-e',"let s='';for await(const b of process.stdin)s+=b;process.stdout.write(JSON.stringify(JSON.parse(s),null,2));"],input=json.dumps(value).encode())
 assert hashlib.sha256(data).hexdigest()==wanted[target]
 recovered[target]=(data,{'method':'unchanged catalog raw + unchanged replay input; full original SHA match'})
 times=regex.findall(data);anchors[filename]=parse(times[-2].decode())
previous=min(anchors.values())-15000
start=time.monotonic();miss=[]
for index,row in enumerate(rows):
 target='evidence/2026-11-01/command-parent/fixtures/'+row['fixture']
 if target not in wanted:continue
 name=row['fixture'].removesuffix('.json')
 if target in recovered:previous=anchors[name];continue
 data=(OUT/'legacy-regression-generated-output'/target).read_bytes();matches=list(regex.finditer(data))
 if len(matches)!=2:miss.append({'path':target,'reason':'not exactly two replay clock strings','count':len(matches)});continue
 first,second=matches;prefix=data[:first.start()];middle=data[first.end():second.start()];suffix=data[second.end():]
 future=[anchors[r['fixture'].removesuffix('.json')] for r in rows[index+1:] if r['fixture'].removesuffix('.json') in anchors]
 upper=min(future) if future else max(anchors.values())+15000
 found=None
 # A tiny VM report has zero/one millisecond duration; broader candidates remain
 # merely guesses until the entire byte sequence matches the pre-round hash.
 for delta in [0,1,2,3,4,5]:
  for t in range(previous,upper+1):
   candidate=prefix+fmt(t)+middle+fmt(t+delta)+suffix
   if hashlib.sha256(candidate).hexdigest()==wanted[target]:found=(candidate,t,delta);break
  if found:break
 if found:
  data,t,delta=found;recovered[target]=(data,{'method':'only two synthetic replay VM clock strings enumerated; full original SHA match','reportStartMs':t,'reportDurationMs':delta});previous=t
 else:miss.append({'path':target,'reason':'no exact pre-round SHA match within bounded clock search'})
 print(json.dumps({'processed':index+1,'exactByteRecoveries':len(recovered),'unresolved':len(miss),'seconds':round(time.monotonic()-start,1)}),flush=True)
# Restore only independently hash-validated original bytes; keep generated output.
for target,(data,proof) in recovered.items():
 assert hashlib.sha256(data).hexdigest()==wanted[target];(ROOT/target).write_bytes(data)
# Differential contains hashes of each fixture, not times; derive from repaired
# original fixture bytes, accept only if its own pre-round hash also matches.
if not miss:
 value=json.loads((OUT/'legacy-regression-generated-output/evidence/2026-11-01/command-parent/differential.json').read_text())
 script="""import fs from 'node:fs';import crypto from 'node:crypto';let s='';for await(const b of process.stdin)s+=b;const v=JSON.parse(s);for(const row of v.records){const f=JSON.parse(fs.readFileSync('evidence/2026-11-01/command-parent/fixtures/'+row.fixture));row.rawSha256=crypto.createHash('sha256').update(JSON.stringify(f.raw??f)).digest('hex');}process.stdout.write(JSON.stringify(v,null,2));"""
 blob=subprocess.check_output(['node','--input-type=module','-e',script],input=json.dumps(value).encode(),cwd=ROOT)
 n='evidence/2026-11-01/command-parent/differential.json'
 if hashlib.sha256(blob).hexdigest()==wanted[n]:(ROOT/n).write_bytes(blob);recovered[n]=(blob,{'method':'exact repaired raw hashes; full original differential SHA match'})
 else:miss.append({'path':n,'reason':'differential exact byte validation did not match'})
receipt={'classification':'INCIDENT_REPAIR_EXACT_PRE_ROUND_SHA_REQUIRED','restored':{n:{'sha256':hashlib.sha256(b).hexdigest(),**proof} for n,(b,proof) in recovered.items()},'unresolved':miss,'originalEvidenceIntegrity':'FAILED','noHistoricalManifestChanged':True,'newExecutionEvidenceUntouched':True,'seconds':round(time.monotonic()-start,2)}
with (OUT/'exact-byte-recovery-receipt.json').open('x') as f:json.dump(receipt,f,indent=2);f.write('\n')
print(json.dumps({'restored':len(recovered),'unresolved':len(miss),'seconds':receipt['seconds']}))
