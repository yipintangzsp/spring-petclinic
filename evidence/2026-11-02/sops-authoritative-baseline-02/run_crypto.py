from pathlib import Path
import io,tarfile,json,subprocess,sys,os
OUT=Path(__file__).resolve().parent;root=Path(json.loads((OUT/'root-reference.json').read_text())['root']);mode=sys.argv[1]
assert mode in ('versions','keys','encrypt')
buf=io.BytesIO()
with tarfile.open(fileobj=buf,mode='w') as t:
 for name in ['tools','keys','plaintext','encrypted','metadata','evidence','cleanup','home']:
  p=root/name
  # Never transfer kubeconfig/token/profile into crypto container.
  if name=='metadata':
   entry=tarfile.TarInfo('metadata');entry.type=tarfile.DIRTYPE;entry.mode=0o700;t.addfile(entry)
  else:t.add(p,arcname=name)
 t.add(OUT/'crypto_native.py',arcname='crypto_native.py')
args=['/opt/homebrew/bin/docker','--host','unix:///Users/zhangsir/.colima/security-test/docker.sock','run','--rm','--pull=never','--interactive','--network','none','--read-only','--cap-drop','ALL','--security-opt','no-new-privileges','--user','65532:65532','--pids-limit','64','--memory','512m','--cpus','1','--tmpfs','/fixture:rw,exec,nosuid,nodev,size=256m,mode=1777','--entrypoint','/bin/sh','sha256:452d707d4862f52530247495d180205e029056831160e22870e37e3f6c1ac31f','-c','umask 077; tar xf - -C /fixture; /usr/bin/python3 /fixture/crypto_native.py '+mode]
env={'HOME':str(root/'home'),'PATH':'/usr/bin:/bin','LANG':'C.UTF-8'}
r=subprocess.run(args,input=buf.getvalue(),capture_output=True,timeout=150,env=env)
if r.returncode:
 (OUT/'crypto-execution-error.json').write_text(json.dumps({'exitCode':r.returncode,'stderrBytes':len(r.stderr),'stdoutBytes':len(r.stdout),'mode':mode}));raise SystemExit('CRYPTO_CONTAINER_FAILED; output suppressed')
if mode=='versions':
 data=json.loads(r.stdout);(OUT/'tool-versions.json').write_text(json.dumps(data,indent=2));print(json.dumps(data));sys.exit(0)
with tarfile.open(fileobj=io.BytesIO(r.stdout)) as t:
 for member in t.getmembers():
  p=root/member.name
  if Path(member.name).is_absolute() or '..' in Path(member.name).parts or not member.name.startswith(('keys','encrypted','metadata/crypto-evidence.json','metadata/key-evidence.json')):raise SystemExit('UNSAFE_CRYPTO_OUTPUT')
  if member.isdir():p.mkdir(exist_ok=True,parents=True,mode=0o700)
  elif member.isfile():
   p.parent.mkdir(exist_ok=True,parents=True,mode=0o700)
   fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
   with os.fdopen(fd,'wb') as f:f.write(t.extractfile(member).read())
  else:raise SystemExit('UNSAFE_CRYPTO_OUTPUT_TYPE')
import shutil
meta='key-evidence.json' if mode=='keys' else 'crypto-evidence.json'
shutil.copyfile(root/'metadata'/meta,OUT/meta)
print('DISPOSABLE_KEYPAIRS_GENERATED' if mode=='keys' else 'FIXTURE_ENCRYPT_DECRYPT_VERIFIED')
