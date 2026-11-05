from pathlib import Path
import sys,importlib.util,tempfile,json,subprocess
sys.dont_write_bytecode=True
O=Path(__file__).resolve().parent;R=O.parents[2];spec=importlib.util.spec_from_file_location('b',R/'infra/security/testing/evidence-boundary.py');b=importlib.util.module_from_spec(spec);spec.loader.exec_module(b)
p=O/'owned-boundary-canary-r2.txt'
with p.open('x') as f:f.write('THIS ROUND ONLY\n')
s=p.stat();content=p.read_bytes()
with tempfile.TemporaryDirectory(prefix='security-cosign-boundary-') as d:
 t=Path(d).resolve()
 code="""from pathlib import Path
import json
p=Path(CANARY);r={}
for k,op in [('overwrite',lambda:p.write_text('bad')),('delete',lambda:p.unlink()),('chmod',lambda:p.chmod(0o666))]:
 try:op();r[k]='ALLOWED'
 except PermissionError:r[k]='DENIED'
(Path.cwd()/'local.json').write_text('{}')
print(json.dumps(r))
"""
 r=b.guarded(t,[sys.executable,'-B','-c','CANARY='+repr(str(p))+'\n'+code]);assert r.returncode==0,r.stderr;x=json.loads(r.stdout);assert all(v=='DENIED' for v in x.values())
assert p.read_bytes()==content and p.stat().st_mtime_ns==s.st_mtime_ns and p.stat().st_mode==s.st_mode
out={'classification':'REAL_OS_WRITE_BOUNDARY_PREFLIGHT_NOT_SCANNER_OR_DOJO','backend':'existing macOS sandbox-exec','checks':x,'temporaryWriteAllowed':True,'historicalWriteProbes':0,'historicalDeleteProbes':0,'temporaryDirectoryRemoved':not Path(d).exists(),'canaryContentMtimeModeUnchanged':True}
with(O/'write-boundary-preflight.json').open('x') as f:json.dump(out,f,indent=2);f.write('\n')
print(json.dumps(out))
