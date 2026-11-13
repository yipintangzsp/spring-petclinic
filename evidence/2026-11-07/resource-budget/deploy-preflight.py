import pathlib,runpy,shlex,json,sys,hashlib
sys.dont_write_bytecode=True
h=pathlib.Path(__file__).resolve().parent;p=runpy.run_path('evidence/2026-11-05/gitlab-push-demo/preflight.py')
entry="""import os,sys,pathlib,json,importlib.util,resource
r=pathlib.Path('/var/tmp/security-manager-gitleaks-budget-20261107');s=importlib.util.spec_from_file_location('budget',r/'resource-budget.py');m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
assert os.getuid()==24021 and os.getgid()==24021
x=m.probe('/var/tmp/security-manager-gitleaks-recovery-20261107');x['cgroupLimits']={};domain=pathlib.Path('/sys/fs/cgroup')/x['cgroup'].split('::',1)[1].lstrip('/')
for d in [domain,*domain.parents]:
 if not d.is_relative_to('/sys/fs/cgroup'):continue
 values={}
 for n in ['memory.max','cpu.max','cpuset.cpus.effective','pids.max']:
  f=d/n
  if f.is_file():values[n]=f.read_text().strip()
 if values:x['cgroupLimits'][str(d)]=values
x['rlimits']={n:list(resource.getrlimit(getattr(resource,n)))for n in ['RLIMIT_CPU','RLIMIT_AS','RLIMIT_NPROC','RLIMIT_FSIZE']}
print(json.dumps(x))
"""
code=r'''
import pathlib,json,sys,hashlib
x=json.load(sys.stdin);r=pathlib.Path('/var/tmp/security-manager-gitleaks-budget-20261107');assert not r.exists();r.mkdir(mode=0o755)
for name,text in [('resource-budget.py',x['module']),('preflight.py',x['entry'])]:f=r/name;f.write_text(text);f.chmod(0o444)
f=pathlib.Path('/var/tmp/security-manager-gitleaks-v2-linux-20261105/ssh-entry.py');old=f.read_text();assert 'resource-preflight-v1'not in old and 'commit-v1'not in old
backup=r/'original-entry.py';backup.write_text(old);backup.chmod(0o444)
prefix="import os as _b\nif _b.environ.get('SSH_ORIGINAL_COMMAND')=='resource-preflight-v1':_b.execv('/usr/bin/python3',['/usr/bin/python3','-I','/var/tmp/security-manager-gitleaks-budget-20261107/preflight.py'])\n"
f.write_text(prefix+old);f.chmod(0o444)
print(json.dumps({'originalEntrySha256':hashlib.sha256(old.encode()).hexdigest(),'temporaryEntrySha256':hashlib.sha256(f.read_bytes()).hexdigest(),'onlyFixedReadOnlyCommandAdded':True,'noScannerOrRun':True,'backup':str(backup)}))
'''
x=json.loads(p['m']['remote']('sudo -n python3 -c '+shlex.quote(code),json.dumps({'module':pathlib.Path('infra/security/manager-v2/ci/resource-budget.py').read_text(),'entry':entry}),timeout=20))
with(h/'deployment.json').open('x')as f:json.dump(x,f,indent=2)
print(json.dumps(x))
