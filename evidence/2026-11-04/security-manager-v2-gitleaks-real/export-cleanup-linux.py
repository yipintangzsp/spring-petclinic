"""Export only bounded redacted candidate artifacts, then remove this run's workspace."""
import hashlib,io,json,pathlib,subprocess,tarfile
O=pathlib.Path(__file__).resolve().parent
S=['ssh','-o','BatchMode=yes','-o','ConnectTimeout=6','-o','StrictHostKeyChecking=yes','-o','HostName=192.168.64.11','-o','HostKeyAlias=192.168.1.58','zhang@192.168.1.58']
root=json.loads((O/'linux-tool-provenance.json').read_text())['workspace']
script=r'''
import pathlib,json,hashlib,tarfile,io,sys
root=pathlib.Path(ROOT);assert root.is_dir() and root.stat().st_uid==0 and root.resolve()==root
fake='ghp_'+(root/'source-java/Main.java').read_text().split('ghp_')[1].split(chr(34))[0]
files={}
for directory in ['outputs','outputs-attempt1']:
 for p in (root/directory).rglob('*'):
  if p.is_file():
   assert not p.is_symlink();b=p.read_bytes();assert len(b)<2*1024**2 and fake.encode() not in b
   files[str(p.relative_to(root))]=b
for name in ['approval.json','tool-provenance.json','controller-results.json','controller-results.json-attempt1','normal.stdout','normal.stderr','tool-error.stdout','tool-error.stderr']:
 p=root/name;assert p.is_file() and not p.is_symlink();b=p.read_bytes();assert fake.encode() not in b;files[name]=b
assert len(files)<250 and sum(map(len,files.values()))<8*1024**2
proof={'secretLeakageCheck':'PASS','syntheticLiteralAbsentFromEveryExportedFile':True,'sourcePlaintextExported':False,'privateKeyExported':False,'files':{n:hashlib.sha256(b).hexdigest() for n,b in files.items()},'protectedSourceSnapshotUnchanged':True}
files['export-proof.json']=(json.dumps(proof,indent=2)+'\n').encode()
with tarfile.open(fileobj=sys.stdout.buffer,mode='w|gz') as tar:
 for n,b in files.items():
  m=tarfile.TarInfo(n);m.size=len(b);m.mode=0o600;tar.addfile(m,io.BytesIO(b))
'''
p=subprocess.run(S+['sudo -n python3 -'],input=('ROOT='+repr(root)+'\n'+script).encode(),capture_output=True,timeout=45)
assert p.returncode==0,p.stderr.decode()[-1000:]
dest=O/'real-linux';dest.mkdir()
with tarfile.open(fileobj=io.BytesIO(p.stdout)) as tar:
 members=tar.getmembers();assert len(members)<250 and sum(m.size for m in members)<8*1024**2
 for m in members:
  rel=pathlib.PurePosixPath(m.name);assert m.isfile() and not rel.is_absolute() and '..' not in rel.parts
  target=dest/rel;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(tar.extractfile(m).read())
proof=json.loads((dest/'export-proof.json').read_text())
assert all(hashlib.sha256((dest/n).read_bytes()).hexdigest()==h for n,h in proof['files'].items())
cleanup=r'''
import pathlib,json,shutil,os
root=pathlib.Path(ROOT);assert str(root).startswith('/var/tmp/security-manager-gitleaks-') and root.resolve()==root and root.stat().st_uid==0
live=[]
for p in pathlib.Path('/proc').glob('[0-9]*/cmdline'):
 try:
  if str(root).encode() in p.read_bytes():live.append(int(p.parent.name))
 except (PermissionError,FileNotFoundError,ProcessLookupError):pass
assert not live,live
shutil.rmtree(root)
assert not root.exists()
print(json.dumps({'workspace':str(root),'remainingProcesses':live,'workspaceRemoved':True,'temporaryBinaryRemoved':True,'fixtureSourcesAndGitRepositoriesRemoved':True,'privateReportsRemoved':True,'KubernetesResourcesCreated':0,'productionConfigurationChanged':False}))
'''
q=subprocess.run(S+['sudo -n python3 -'],input='ROOT='+repr(root)+'\n'+cleanup,text=True,capture_output=True,timeout=30)
assert q.returncode==0,q.stderr
with (O/'linux-cleanup.json').open('x') as f:json.dump(json.loads(q.stdout),f,indent=2);f.write('\n')
print(json.dumps({'exportedFiles':len(proof['files']),'exportSha256':hashlib.sha256(p.stdout).hexdigest(),'secretLeakageCheck':proof['secretLeakageCheck'],'cleanup':json.loads(q.stdout)}))
