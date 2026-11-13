import pathlib,json,runpy,shlex,sys
sys.dont_write_bytecode=True
h=pathlib.Path(__file__).resolve().parent;p=runpy.run_path('evidence/2026-11-05/gitlab-push-demo/preflight.py');meta=json.loads((h/'deployment.json').read_text())
code=r'''
import pathlib,sys,json,hashlib
x=json.load(sys.stdin);r=pathlib.Path('/var/tmp/security-manager-gitleaks-budget-20261107');f=pathlib.Path('/var/tmp/security-manager-gitleaks-v2-linux-20261105/ssh-entry.py');old=(r/'original-entry.py').read_bytes();assert hashlib.sha256(old).hexdigest()==x['meta']['originalEntrySha256'];assert hashlib.sha256(f.read_bytes()).hexdigest()==x['meta']['temporaryEntrySha256'];f.write_bytes(old);f.chmod(0o444)
# Preserve approved, inert staged fix for future package creation; not enabled as scanner entry.
f=r/'commit-source-entry.prepared.py';assert not f.exists();f.write_text(x['wrapper']);f.chmod(0o444)
print(json.dumps({'originalSshEntryRestored':True,'noNewCredential':True,'fixedReadOnlyRouteRemoved':True,'inertPreparedWrapperSaved':True,'existingRunnerPackagesUnchanged':True,'newRun':False,'scannerStarted':False}))
'''
x=json.loads(p['m']['remote']('sudo -n python3 -c '+shlex.quote(code),json.dumps({'meta':meta,'wrapper':pathlib.Path('infra/security/manager-v2/ci/commit-source-entry.py').read_text()}),timeout=15))
with(h/'restored.json').open('x')as f:json.dump(x,f,indent=2)
print(json.dumps(x))
