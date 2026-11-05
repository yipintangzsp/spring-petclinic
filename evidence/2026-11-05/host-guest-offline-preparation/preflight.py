"""New-round boundary preflight; probes only a newly owned canary."""
from pathlib import Path
import json,sys,importlib.util,tempfile,datetime,subprocess
sys.dont_write_bytecode=True
O=Path(__file__).resolve().parent;R=O.parents[2]
spec=importlib.util.spec_from_file_location('boundary',R/'infra/security/testing/evidence-boundary.py');b=importlib.util.module_from_spec(spec);spec.loader.exec_module(b)
old=R/'evidence/2026-11-05/devops-resource-observation';before=json.loads((old/'protected-before.json').read_text());names=sorted(set(before['protected'])|{str(p.relative_to(R))for p in old.iterdir()if p.is_file()})
snapshot=b.snapshot(names);assert all(snapshot[n]==v for n,v in before['protected'].items());assert len(names)==13953
assert subprocess.check_output(['git','rev-parse','HEAD'],cwd=R).decode().strip()=='879db23821961b322d1c426512b9c00a28f9d8b9'
def put(n,x):
 with(O/n).open('x')as f:json.dump(x,f,indent=2);f.write('\n')
put('protected-before.json',{'head':'879db23821961b322d1c426512b9c00a28f9d8b9','at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'priorProtectedCount':13931,'protected':snapshot,'historicalEvidenceFiles':sorted(str(p.relative_to(R))for p in(R/'evidence').rglob('*')if p.is_file()and not p.is_relative_to(O)),'originalEvidenceIntegrity':'FAILED'})
p=O/'owned-canary.txt'
with p.open('x')as f:f.write('NEW ROUND CANARY ONLY\n')
s=b.snapshot([str(p.relative_to(R))])
with tempfile.TemporaryDirectory(prefix='security-cosign-boundary-')as d:
 t=Path(d).resolve();code="""from pathlib import Path
import json
p=Path(CANARY);r={}
for k,f in [('overwrite',lambda:p.write_text('bad')),('delete',lambda:p.unlink()),('chmod',lambda:p.chmod(0o666))]:
 try:f();r[k]='ALLOWED'
 except PermissionError:r[k]='DENIED'
Path('output.json').write_text('{}');print(json.dumps(r))
"""
 proc=b.guarded(t,[sys.executable,'-B','-c','CANARY='+repr(str(p))+'\n'+code]);assert proc.returncode==0,proc.stderr
 checks=json.loads(proc.stdout);assert all(v=='DENIED'for v in checks.values())
assert b.snapshot(s)==s
put('write-boundary-preflight.json',{'status':'VERIFIED','backend':'macOS sandbox-exec; deny network; only temporary tree writable','checks':checks,'historicalWriteProbes':0,'canaryUnchanged':True,'temporaryTreeRemoved':not Path(d).exists(),'protectedCount':len(names),'originalEvidenceIntegrity':'FAILED'})
print(json.dumps({'preflight':'VERIFIED','protectedCount':len(names),'productionAccess':0}))
