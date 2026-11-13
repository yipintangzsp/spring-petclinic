"""Narrow, reversible amd64 user-mode emulator trial; caller must hold HeavyRun."""
import argparse,base64,hashlib,json,os,pathlib,platform,shutil,subprocess
EXPECTED='f04e3597ebf2ba6fe98bfb8f453dcbb1b767695e0283ceb7fa265af94d66fc19'
SOURCE=pathlib.Path('/tmp/qemu-x86_64-verified-20261023')
BINARY=pathlib.Path('/usr/local/libexec/petclinic-qemu/10.2.3/qemu-x86_64')
ENTRY=pathlib.Path('/proc/sys/fs/binfmt_misc/qemu-x86_64')
REGISTER=ENTRY.parent/'register'
OVERRIDE=pathlib.Path('/etc/binfmt.d/qemu-x86_64.conf')
BACKUP=pathlib.Path('/root/petclinic-qemu-recovery-20261023')
def registration(text,interpreter=None,flags=None):
 d={line.split(' ',1)[0].rstrip(':'):line.split(' ',1)[1] for line in text.splitlines() if ' ' in line}
 assert set(d)=={'interpreter','flags','offset','magic','mask'} and d['offset']=='0'
 assert all(c in '0123456789abcdef' for c in d['magic']+d['mask'])
 esc=lambda s: ''.join('\\x'+s[i:i+2] for i in range(0,len(s),2))
 return ':qemu-x86_64:M:0:'+esc(d['magic'])+':'+esc(d['mask'])+':'+(interpreter or d['interpreter'])+':'+(flags or d['flags'])
def apply(line):
 if ENTRY.exists():ENTRY.write_text('-1')
 REGISTER.write_text(line)
def main(action):
 assert os.geteuid()==0 and platform.machine()=='aarch64'
 lease=json.loads(subprocess.check_output(['kubectl','-n','data-infra','get','lease','platform-heavy','-o','json']))
 assert lease['spec']['holderIdentity'].startswith('amd64-emulator-smoke-')
 BACKUP.mkdir(mode=0o700,exist_ok=True);state=BACKUP/'before.json'
 if action=='trial':
  old=ENTRY.read_text();assert 'interpreter /usr/libexec/qemu-binfmt/x86_64-binfmt-P\n' in old and 'flags: POF\n' in old
  assert hashlib.sha256(SOURCE.read_bytes()).hexdigest()==EXPECTED
  if not state.exists():
   shutil.copy2('/usr/bin/qemu-x86_64-static',BACKUP/'qemu-x86_64-static.original');(BACKUP/'qemu-x86_64-static.original').chmod(0o600)
   data={'registration':old,'original_binary_sha256':hashlib.sha256((BACKUP/'qemu-x86_64-static.original').read_bytes()).hexdigest(),'override':base64.b64encode(OVERRIDE.read_bytes()).decode() if OVERRIDE.exists() else None};state.write_text(json.dumps(data,indent=2));state.chmod(0o600)
  else:assert json.loads(state.read_text())['registration']==old
  BINARY.parent.mkdir(mode=0o755,parents=True,exist_ok=True)
  if BINARY.exists():assert hashlib.sha256(BINARY.read_bytes()).hexdigest()==EXPECTED
  else:shutil.copy2(SOURCE,BINARY)
  BINARY.chmod(0o755)
  assert hashlib.sha256(BINARY.read_bytes()).hexdigest()==EXPECTED
  try:apply(registration(old,str(BINARY),'POF'))
  except Exception:apply(registration(old));raise
 elif action=='commit':
  data=json.loads(state.read_text());assert 'interpreter '+str(BINARY)+'\n' in ENTRY.read_text()
  assert not OVERRIDE.exists() or OVERRIDE.read_text().strip()==registration(data['registration'],str(BINARY),'POF')
  tmp=OVERRIDE.with_suffix('.tmp');tmp.write_text(registration(data['registration'],str(BINARY),'POF')+'\n');tmp.chmod(0o644);tmp.replace(OVERRIDE)
 else:
  data=json.loads(state.read_text());assert hashlib.sha256(pathlib.Path('/usr/bin/qemu-x86_64-static').read_bytes()).hexdigest()==data['original_binary_sha256']
  if ENTRY.read_text()==data['registration']:
   print(json.dumps({'action':'rollback','already_original':True}));return
  assert 'interpreter '+str(BINARY)+'\n' in ENTRY.read_text();apply(registration(data['registration']))
  if data['override'] is not None:OVERRIDE.write_bytes(base64.b64decode(data['override']))
  elif OVERRIDE.exists():assert str(BINARY) in OVERRIDE.read_text();OVERRIDE.unlink()
 assert ENTRY.read_text().startswith('enabled\n');(BACKUP/('after-'+action+'.txt')).write_text(ENTRY.read_text())
 print(json.dumps({'action':action,'interpreter':ENTRY.read_text().splitlines()[1],'original_binary_unchanged':True}))
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('action',choices=['trial','commit','rollback']);main(p.parse_args().action)
