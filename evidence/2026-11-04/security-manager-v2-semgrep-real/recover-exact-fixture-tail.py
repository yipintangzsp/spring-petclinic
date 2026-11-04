"""Finish exact-hash-only recovery of synthetic VM replay output. No test rerun."""
from pathlib import Path
import json,re,hashlib,datetime,time,subprocess
OUT=Path(__file__).resolve().parent;ROOT=OUT.parents[2];base=json.loads((OUT/'protected-before.json').read_text());allHashes=base['protected'];rows=json.loads((OUT/'legacy-regression-generated-output/evidence/2026-11-01/command-parent/differential.json').read_text())['records'];pattern=re.compile(rb'2026-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z')
parse=lambda s:int(datetime.datetime.fromisoformat(s.replace('Z','+00:00')).timestamp()*1000)
fmt=lambda t:datetime.datetime.fromtimestamp(t/1000,datetime.timezone.utc).isoformat(timespec='milliseconds').replace('+00:00','Z').encode()
start=time.monotonic();repaired={};missing=[]
# Tight intervals from adjacent already restored files; cold VM startup may take
# more than five milliseconds. A candidate is NEVER written before full SHA match.
for row in rows:
 n='evidence/2026-11-01/command-parent/fixtures/'+row['fixture'];p=ROOT/n
 if n not in allHashes or hashlib.sha256(p.read_bytes()).hexdigest()==allHashes[n]:continue
 data=(OUT/'legacy-regression-generated-output'/n).read_bytes();ms=list(pattern.finditer(data));name=row['fixture']
 if name=='healthy.json':lo=parse('2026-11-01T13:46:20.000Z');hi=parse('2026-11-01T13:46:47.094Z');deltas=range(0,51)
 elif name in ['semgrep-delete-failed.json','semgrep-replacement-UID-preserved.json']:lo=parse('2026-11-01T13:46:58.401Z');hi=parse('2026-11-01T13:46:59.316Z');deltas=[0]
 else:lo=parse('2026-11-01T13:47:11.190Z');hi=parse('2026-11-01T13:47:35.000Z');deltas=range(0,11)
 found=None
 if len(ms)==1:
  a=ms[0];pre=data[:a.start()];post=data[a.end():]
  for t in range(lo,hi+1):
   b=pre+fmt(t)+post
   if hashlib.sha256(b).hexdigest()==allHashes[n]:found=(b,t,0);break
 elif len(ms)==2:
  a,z=ms;pre=data[:a.start()];mid=data[a.end():z.start()];post=data[z.end():]
  for delta in deltas:
   for t in range(lo,hi+1):
    b=pre+fmt(t)+mid+fmt(t+delta)+post
    if hashlib.sha256(b).hexdigest()==allHashes[n]:found=(b,t,delta);break
   if found:break
 if found:
  b,t,d=found;assert hashlib.sha256(b).hexdigest()==allHashes[n];p.write_bytes(b);repaired[n]={'sha256':allHashes[n],'syntheticReportStartMs':t,'syntheticReportDurationMs':d,'fullOriginalHashMatchedBeforeWrite':True}
 else:missing.append(n)
 print(json.dumps({'file':name,'exactRestored':bool(found),'elapsed':round(time.monotonic()-start,1)}),flush=True)
if not missing:
 value=json.loads((OUT/'legacy-regression-generated-output/evidence/2026-11-01/command-parent/differential.json').read_text())
 code="""import fs from 'node:fs';import crypto from 'node:crypto';let s='';for await(const b of process.stdin)s+=b;const v=JSON.parse(s);for(const row of v.records){const f=JSON.parse(fs.readFileSync('evidence/2026-11-01/command-parent/fixtures/'+row.fixture));row.rawSha256=crypto.createHash('sha256').update(JSON.stringify(f.raw??f)).digest('hex');}process.stdout.write(JSON.stringify(v,null,2));"""
 blob=subprocess.check_output(['node','--input-type=module','-e',code],input=json.dumps(value).encode(),cwd=ROOT);n='evidence/2026-11-01/command-parent/differential.json'
 if hashlib.sha256(blob).hexdigest()==allHashes[n]:(ROOT/n).write_bytes(blob);repaired[n]={'sha256':allHashes[n],'method':'restored fixture raw hashes; full original differential SHA matched before write'}
 else:missing.append(n)
remaining=[n for n,h in allHashes.items() if hashlib.sha256((ROOT/n).read_bytes()).hexdigest()!=h]
receipt={'classification':'EXACT_SHA_MATCH_RECOVERY_NOT_EVIDENCE_REINTERPRETATION','method':'bounded enumeration of synthetic replay VM clock strings, accept only pre-round full SHA; no real runtime timestamp modified','repaired':repaired,'remainingProtectedDifferences':remaining,'historicalManifestsChanged':False,'originalEvidenceIntegrity':'FAILED','seconds':round(time.monotonic()-start,2)}
with (OUT/'exact-byte-tail-recovery-receipt.json').open('x') as f:json.dump(receipt,f,indent=2);f.write('\n')
print(json.dumps({'repaired':len(repaired),'remainingProtectedDifferences':len(remaining),'seconds':receipt['seconds']}))
