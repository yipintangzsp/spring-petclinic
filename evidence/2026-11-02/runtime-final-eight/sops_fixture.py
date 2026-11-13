"""Approved isolated fixture management. Never opens a production kubeconfig/key.
All mutations use the unchanged guard and exactly the existing approved design.
"""
from pathlib import Path
import sys,os,json,hashlib,subprocess,tempfile,importlib.util,tarfile,io,shutil,time
import yaml
R=Path.cwd();O=R/'evidence/2026-11-02/runtime-final-eight/sops';O.mkdir(exist_ok=True)
P=R/'evidence/2026-11-02/sops-authoritative-baseline-02';D=R/'evidence/2026-11-02/sops-authoritative-differential-02'
RUN='sm-sops-runtime-20261103';IMAGE='sha256:452d707d4862f52530247495d180205e029056831160e22870e37e3f6c1ac31f'
DOCKER=['/opt/homebrew/bin/docker','--host','unix:///Users/zhangsir/.colima/security-test/docker.sock']
SSH=['ssh','-o','BatchMode=yes','-o','ConnectTimeout=6','-o','StrictHostKeyChecking=yes','-o','HostName=192.168.64.11','-o','HostKeyAlias=192.168.1.58','zhang@192.168.1.58']
sha=lambda b:hashlib.sha256(b).hexdigest()
def dump(n,x):(O/n).write_text(json.dumps(x,indent=2)+'\n')
sys.path.insert(0,str(R/'infra/security/testing'));import isolated_sops_executor as g
spec=importlib.util.spec_from_file_location('runtime_fixture_manager',P/'create_fixture.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
m.OUT=O;m.RUN=RUN;m.LEDGER=[];m.REQUESTS=0
def setup_root():
 root=Path(tempfile.mkdtemp(prefix='sm-sops-runtime-20261103-',dir='/private/tmp'));root.chmod(0o700)
 for n in ['tools','keys','plaintext','encrypted','metadata','evidence','cleanup','home']:(root/n).mkdir(mode=0o700)
 dump('root-reference.json',{'root':str(root),'run':RUN});return root
def getroot():
 root=Path(json.loads((O/'root-reference.json').read_text())['root']);assert str(root).startswith('/private/tmp/sm-sops-runtime-20261103-') and root.is_dir() and not root.is_symlink();return root
def prepare():
 root=setup_root();m.ROOT=root
 # Public executable bytes only; no Secret, kubeconfig or age private key is
 # read on the production side. Existing frozen hashes are mandatory.
 p=subprocess.run(SSH+['sudo -n kubectl exec -n ns-devops deploy/jenkins -c jenkins -- tar cf - -C /var/jenkins_home/platform-security/20261027 sops age age-keygen'],capture_output=True,timeout=60)
 if p.returncode:raise RuntimeError('PINNED_PUBLIC_TOOL_READ_FAILED')
 pins=json.loads((R/'infra/security/scanner-tools.json').read_text())['files'];pins={x['path']:x['sha256'] for x in pins if x['path'] in ['sops','age','age-keygen']}
 with tarfile.open(fileobj=io.BytesIO(p.stdout)) as t:
  assert {x.name for x in t.getmembers()}==set(pins)
  for entry in t:
   assert entry.isfile();b=t.extractfile(entry).read();assert sha(b)==pins[entry.name];g.write_private(root/'tools'/entry.name,b,0o500)
 node=Path('/private/tmp/sm-node-executor-erg_cakg/runtime/bin/node');expected='d09e299258c24f7cdf6f5d5ec185e3a56512b27a697113735dac909f1cac7b8d';assert sha(node.read_bytes())==expected
 dump('pinned-runtime.json',{'nodeSha256':expected,'publicTools':pins,'productionSecretReads':0,'productionAgeKeyReads':0,'source':'Existing pinned executable bytes, not credentials'})
 for name in ['verify_rbac.py','run_crypto.py','crypto_native.py']:shutil.copy2(P/name,O/name)
 m.main();dump('fixture-created.json',{'objects':len(m.LEDGER),'run':RUN,'productionApiMutations':0})
 # Extract the already cached base image's public kubectl. No pull/network.
 binary=subprocess.check_output(DOCKER+['run','--rm','--pull=never','--network','none','--read-only','--entrypoint','/usr/bin/python3',IMAGE,'-c',"import sys;sys.stdout.buffer.write(open('/usr/bin/kubectl','rb').read())"])
 g.write_private(root/'tools/kubectl',binary,0o500);dump('kubectl-runtime.json',{'sha256':sha(binary),'base':IMAGE})
def object_path(o):
 plural={'Namespace':'namespaces','ServiceAccount':'serviceaccounts','Secret':'secrets','Role':'roles','RoleBinding':'rolebindings','ClusterRole':'clusterroles','ClusterRoleBinding':'clusterrolebindings','Lease':'leases'}[o['kind']]
 return ('/api/v1' if o['apiVersion']=='v1' else '/apis/'+o['apiVersion'])+('/namespaces/'+o['namespace'] if o['namespace'] else '')+'/'+plural+'/'+o['name']
def cleanup():
 root=getroot();ledger=json.loads((O/'object-ledger.json').read_text()) if (O/'object-ledger.json').exists() else [];log=[]
 for o in ledger:
  code,actual=m.api('GET',object_path(o));assert code==200 and actual['metadata']['uid']==o['uid'] and actual['metadata']['labels'].get('security-manager.test/run-id')==RUN
 for ns in ['petclinic','devsecops-system','data-infra']:
  for resource in ['pods','persistentvolumeclaims','services','replicationcontrollers','configmaps','serviceaccounts','secrets']:
   code,listing=m.api('GET','/api/v1/namespaces/'+ns+'/'+resource);assert code==200
   for item in listing['items']:
    meta=item['metadata'];known=any(o['namespace']==ns and o['name']==meta['name'] and o['uid']==meta['uid'] for o in ledger)
    automatic=(resource=='configmaps' and meta['name']=='kube-root-ca.crt') or (resource=='serviceaccounts' and meta['name']=='default')
    assert known or automatic,'FOREIGN_RESOURCE_STOP '+ns+'/'+resource+'/'+meta['name']
 for kind in ['Lease','RoleBinding','ClusterRoleBinding','Role','ClusterRole','ServiceAccount','Secret','Namespace']:
  for o in [x for x in ledger if x['kind']==kind]:
   path=object_path(o);m.api('DELETE',path,{'apiVersion':'v1','kind':'DeleteOptions','preconditions':{'uid':o['uid']}})
   for _ in range(100):
    if m.api('GET',path)[0]==404:break
    time.sleep(.2)
   else:raise RuntimeError('OWNED_FIXTURE_DELETE_INCOMPLETE')
   log.append({'kind':kind,'namespace':o['namespace'],'name':o['name'],'absent':True})
 shutil.rmtree(root);dump('cleanup-result.json',{'status':'COMPLETE','objects':log,'privateRootRemoved':not root.exists(),'kindRetained':True,'productionApiMutations':0,'privateKeysOrTokenArchived':False})
def execute(binding,scenario):
 root=getroot();B=json.loads((O/'crypto-evidence.json').read_text());assert scenario in ['POSITIVE','WRONG_KEY','TOOL_MISSING']
 buf=io.BytesIO()
 with tarfile.open(fileobj=buf,mode='w') as tar:
  def add(name,data,mode=0o600):
   t=tarfile.TarInfo(name);t.size=len(data);t.mode=mode;t.uid=t.gid=65532;tar.addfile(t,io.BytesIO(data))
  def file(path,name,mode=0o600):add(name,path.read_bytes(),mode)
  for name in ['bootstrap.py','collector.mjs']:file(O/name,name)
  add('binding.json',json.dumps(binding).encode());add('case.json',json.dumps({'scenario':scenario,'holder':RUN}).encode())
  for name in ['executor.kubeconfig','executor-profile.json']:file(root/'metadata'/name,'input-'+name)
  for name in ['baseline.agekey','negative-wrong-key.agekey']:file(root/'keys'/name,'keys/'+name)
  for name in ['sops','age','age-keygen','kubectl']:file(root/'tools'/name,'tools/'+name,0o500)
  file(Path('/private/tmp/sm-node-executor-erg_cakg/runtime/bin/node'),'node/bin/node',0o500)
  file(R/'infra/security/testing/isolated_sops_executor.py','python/isolated_sops_executor.py')
  for py in Path(yaml.__path__[0]).glob('*.py'):
   file(py,'python/yaml/'+py.name);file(py,'work/infra/security/testing/yaml/'+py.name)
  for p in (R/'infra/security').rglob('*'):
   if p.is_file() and p.suffix in ['.mjs','.json','.py'] and not p.is_relative_to(R/'infra/security/secrets') and '__pycache__' not in p.parts:file(p,'work/'+str(p.relative_to(R)))
  add('work/.git-sha',(binding['source']+'\n').encode())
  for item in B['files']:file(root/item['path'],'work/infra/security/secrets/'+item['name']+'.enc.json')
  for name in ['keys','python','tools','work','results','control','boundary']:
   t=tarfile.TarInfo(name);t.type=tarfile.DIRTYPE;t.mode=0o700;t.uid=t.gid=65532;tar.addfile(t)
 boot="import sys,tarfile,os;os.umask(0o077);tarfile.open(fileobj=sys.stdin.buffer,mode='r|').extractall('/fixture');os.execv('/usr/bin/python3',['/usr/bin/python3','/fixture/bootstrap.py'])"
 name='sm-sops-runtime-'+scenario.lower().replace('_','-')
 args=DOCKER+['run','--rm','--pull=never','-i','--name',name,'--network','kind','--user','65532:65532','--read-only','--cap-drop','ALL','--security-opt','no-new-privileges','--pids-limit','128','--memory','900m','--cpus','2','--tmpfs','/fixture:rw,nosuid,nodev,exec,size=700m,mode=0700,uid=65532,gid=65532','--tmpfs','/var/jenkins_home/platform-security/20261027:rw,nosuid,nodev,exec,size=64m,mode=0700,uid=65532,gid=65532','--entrypoint','/usr/bin/python3',IMAGE,'-c',boot]
 p=subprocess.run(args,input=buf.getvalue(),capture_output=True,timeout=220)
 if p.returncode:
  dump('execution-error.json',{'scenario':scenario,'exitStatus':p.returncode,'stderrSha256':sha(p.stderr),'stderrBytes':len(p.stderr),'safeError':p.stderr.decode(errors='replace')[-1200:]});raise RuntimeError('ISOLATED_EXECUTION_FAILED')
 packet=json.loads(p.stdout);assert packet['guard']['status']=='ACCEPTED' and packet['guard']['profile']=='MIN_RBAC_EXECUTOR'
 assert packet['executionScope']=='CONTROLLED_ISOLATED_RUNTIME';return packet
if __name__=='__main__':
 if sys.argv[1]=='prepare':prepare()
 elif sys.argv[1]=='cleanup':cleanup()
 else:raise SystemExit('Unknown explicit action')
