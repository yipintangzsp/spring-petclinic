"""Correction tests on a new disposable no-network tree; preserve prior attempts."""
from pathlib import Path
import sys,json,tempfile,importlib.util,shutil,hashlib,time
sys.dont_write_bytecode=True
O=Path(__file__).resolve().parent;R=O.parents[2];SRC=R/'infra/observability/bounded-sampler'
s=importlib.util.spec_from_file_location('b',R/'infra/security/testing/evidence-boundary.py');b=importlib.util.module_from_spec(s);s.loader.exec_module(b)
assert json.loads((O/'write-boundary-preflight.json').read_text())['status']=='VERIFIED'
def put(n,v):
 with(O/n).open('x')as f:json.dump(v,f,indent=2);f.write('\n')
with tempfile.TemporaryDirectory(prefix='security-cosign-boundary-')as d:
 t=Path(d).resolve()
 for p in SRC.glob('*.py'):shutil.copyfile(p,t/p.name)
 pre=b.guarded(t,[sys.executable,'-B','-c',"import sampler_mach_time as c,json;s=c.DarwinMachTime().system();stop=c.original.pressure_stops(s);print(json.dumps(dict(system=s,stopReasons=stop)));raise SystemExit(1 if stop else 0)"],timeout=5)
 put('preflight-environment.json',{'exit':pre.returncode,'observation':json.loads(pre.stdout)if pre.stdout.strip().startswith('{')else None})
 if pre.returncode:raise SystemExit('TEST_ENVIRONMENT_NOT_READY')
 start=time.monotonic();p=b.guarded(t,[sys.executable,'-B','test_current.py'],timeout=30)
 with(O/'tests.log').open('x')as f:f.write(p.stdout+p.stderr)
 result=json.loads((t/'test-results.json').read_text())if(t/'test-results.json').exists()else {'status':'NO_RESULTS'};put('tests.json',result)
 if(t/'native-unit-sanity.json').exists():put('native-unit-sanity.json',json.loads((t/'native-unit-sanity.json').read_text()))
put('receipt.json',{'exit':p.returncode,'wallSeconds':time.monotonic()-start,'temporaryTreeRemoved':not Path(d).exists(),'sourceHashes':{p.name:hashlib.sha256(p.read_bytes()).hexdigest()for p in SRC.glob('*.py')},'productionConnections':0,'network':'OS_SANDBOX_DENIED','productionChanges':0,'release':0,'rollout':0,'correctedEntrypoint':'sampler_mach_time.py','priorEvidencePreserved':True})
print(json.dumps({'tests':result.get('tests'),'failures':result.get('failures'),'errors':result.get('errors'),'skip':result.get('skipped'),'exit':p.returncode,'temporaryTreeRemoved':not Path(d).exists()}));raise SystemExit(p.returncode)
