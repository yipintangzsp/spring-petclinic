"""Append-only correction: preserve the earlier seal and its original source files."""
from pathlib import Path
import sys,json,hashlib,importlib.util,tempfile
sys.dont_write_bytecode=True
O=Path(__file__).resolve().parent;R=O.parents[2];P=R/'evidence/2026-11-05/host-guest-offline-preparation'
s=importlib.util.spec_from_file_location('b',R/'infra/security/testing/evidence-boundary.py');b=importlib.util.module_from_spec(s);s.loader.exec_module(b)
base=json.loads((P/'protected-before.json').read_text());seal=json.loads((P/'seal.json').read_text());protected={**base['protected'],**seal['files'],**b.snapshot([str((P/'seal.json').relative_to(R))])}
assert all(b.snapshot([n])[n]==v for n,v in protected.items())
def put(n,v):
 with(O/n).open('x')as f:json.dump(v,f,indent=2);f.write('\n')
# Reuse immutable full manifests rather than another multi-MB copied inventory.
put('baseline-receipt.json',{'baseManifest':str((P/'protected-before.json').relative_to(R)),'baseManifestSha256':hashlib.sha256((P/'protected-before.json').read_bytes()).hexdigest(),'priorSeal':str((P/'seal.json').relative_to(R)),'priorSealSha256':hashlib.sha256((P/'seal.json').read_bytes()).hexdigest(),'sealSelfSnapshot':b.snapshot([str((P/'seal.json').relative_to(R))]),'protectedCount':len(protected),'previousOutputAndSourceNotOverwritten':True,'originalEvidenceIntegrity':'FAILED'})
p=O/'owned-canary.txt'
with p.open('x')as f:f.write('APPEND ONLY CORRECTION CANARY\n')
old=b.snapshot([str(p.relative_to(R))])
with tempfile.TemporaryDirectory(prefix='security-cosign-boundary-')as d:
 t=Path(d).resolve();code="""from pathlib import Path
import json
p=Path(CANARY);r={}
for k,f in [('overwrite',lambda:p.write_text('bad')),('delete',lambda:p.unlink()),('chmod',lambda:p.chmod(0o666))]:
 try:f();r[k]='ALLOWED'
 except PermissionError:r[k]='DENIED'
Path('ok').write_text('ok');print(json.dumps(r))
"""
 q=b.guarded(t,[sys.executable,'-B','-c','CANARY='+repr(str(p))+'\n'+code]);assert q.returncode==0,q.stderr;checks=json.loads(q.stdout);assert all(v=='DENIED'for v in checks.values())
assert b.snapshot(old)==old
put('write-boundary-preflight.json',{'status':'VERIFIED','checks':checks,'historyWriteProbes':0,'temporaryTreeRemoved':not Path(d).exists(),'protectedCount':len(protected),'originalEvidenceIntegrity':'FAILED'})
print(json.dumps({'status':'VERIFIED','protected':len(protected),'previousSealedResults':'PRESERVED'}))
