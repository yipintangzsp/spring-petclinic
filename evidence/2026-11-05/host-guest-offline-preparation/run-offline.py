"""Only sandboxed temporary copies are executable. No SSH or production probes."""
from pathlib import Path
import json,sys,importlib.util,tempfile,shutil,time,hashlib
sys.dont_write_bytecode=True
O=Path(__file__).resolve().parent;R=O.parents[2];SRC=R/'infra/observability/bounded-sampler'
spec=importlib.util.spec_from_file_location('boundary',R/'infra/security/testing/evidence-boundary.py');b=importlib.util.module_from_spec(spec);spec.loader.exec_module(b)
assert json.loads((O/'write-boundary-preflight.json').read_text())['status']=='VERIFIED'
def put(n,x):
 with(O/n).open('x')as f:json.dump(x,f,indent=2);f.write('\n')
attempt=int(sys.argv[1]);assert 1<=attempt<=4
with tempfile.TemporaryDirectory(prefix='security-cosign-boundary-')as d:
 t=Path(d).resolve()
 for n in ['sampler.py','contract.py','runner.py','test_sampler.py']:shutil.copyfile(SRC/n,t/n)
 # Read only aggregate native counters; do not query QEMU/production processes.
 code="""import sampler,json,resource
b=sampler.DarwinNative();s=b.system();stop=sampler.pressure_stops(s)
r={'system':s,'stopReasons':stop,'expectedWorkerPeakCapBytes':2*sampler.RSS_LIMIT,'minimumFreePlusInactiveBytes':512*1024*1024,'noStress':True,'noProductionGuestAccess':True}
print(json.dumps(r));raise SystemExit(1 if stop else 0)
"""
 pre=b.guarded(t,[sys.executable,'-B','-c',code],timeout=5)
 if pre.returncode:
  put(f'attempt{attempt}-preflight.json',{'status':'BLOCKED','exit':pre.returncode,'parseableOutput':json.loads(pre.stdout)if pre.stdout.strip().startswith('{')else None});raise SystemExit('ISOLATED_TEST_ENVIRONMENT_NOT_READY')
 put(f'attempt{attempt}-preflight.json',{'status':'READY','observation':json.loads(pre.stdout)})
 started=time.monotonic();p=b.guarded(t,[sys.executable,'-B','test_sampler.py'],timeout=30)
 with(O/f'attempt{attempt}-tests.log').open('x')as f:f.write(p.stdout+p.stderr)
 result=json.loads((t/'test-results.json').read_text())if(t/'test-results.json').exists()else {'status':'NO_RESULTS'}
 put(f'attempt{attempt}-tests.json',result)
 hashes={f.name:hashlib.sha256(f.read_bytes()).hexdigest()for f in SRC.glob('*.py')}
receipt={'classification':'REAL_SANDBOXED_OFFLINE_EXECUTION_NO_LINUX_NATIVE_CLAIM','exit':p.returncode,'wallSeconds':time.monotonic()-started,'temporaryTreeRemoved':not Path(d).exists(),'sourceHashes':hashes,'network':'DENIED_BY_OS_SANDBOX','productionConnections':0,'productionChanges':0,'release':0,'rollout':0}
put(f'attempt{attempt}-receipt.json',receipt);print(json.dumps({'exit':p.returncode,'tests':result.get('tests'),'failures':result.get('failures'),'errors':result.get('errors'),'skipped':result.get('skipped'),'cleanup':receipt['temporaryTreeRemoved']}));raise SystemExit(p.returncode)
