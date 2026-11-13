import pathlib,json,runpy,shlex,hashlib,sys
sys.dont_write_bytecode=True
p=runpy.run_path('evidence/2026-11-05/gitlab-push-demo/preflight.py');names=['resources/security-manager/petclinic-adapter.json','Jenkinsfile.security-audit','Jenkinsfile','vars/securityManager.groovy'];expected={n:hashlib.sha256(pathlib.Path(n).read_bytes()).hexdigest()for n in names}
code=r'''
import pathlib,hashlib,json,sys
expected=json.load(sys.stdin);r=pathlib.Path('/var/tmp/security-manager-gitleaks-v2-linux-20261105/package');out={}
for name,h in expected.items():
 f=r/name;s=f.lstat();assert f.resolve()==f and s.st_uid==0 and not s.st_mode&0o022;actual=hashlib.sha256(f.read_bytes()).hexdigest();assert actual==h;out[name]={'path':str(f),'sha256':actual,'alreadyDeployed':True,'rootOwnedImmutable':True,'matchesLocalGateSource':True}
print(json.dumps({'files':out,'noSourceTransferred':True,'noWriteOrCredentialCreated':True}))
'''
x=json.loads(p['m']['remote']('sudo -n python3 -c '+shlex.quote(code),json.dumps(expected),timeout=15))
with pathlib.Path('evidence/2026-11-07/real-commit-largefile/existing-package.json').open('x')as f:json.dump(x,f,indent=2)
print(json.dumps(x))
