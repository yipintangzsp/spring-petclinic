from pathlib import Path
import json,subprocess,hashlib,tarfile,struct
out=Path(__file__).resolve().parent;lock=json.loads((out/'node-lock.json').read_text());root=Path(json.loads((out/'runtime-root.json').read_text())['path']);archive=root/lock['artifact']
r=subprocess.run(['/usr/bin/curl','--fail','--location','--proto','=https','--proto-redir','=https','--connect-timeout','20','--max-time','600','--continue-at','-','--silent','--show-error','--output',str(archive),lock['source']])
if r.returncode:raise SystemExit('NODE_OFFICIAL_DOWNLOAD_FAILED '+str(r.returncode))
actual=hashlib.sha256(archive.read_bytes()).hexdigest();assert actual==lock['sha256'],'NODE_CHECKSUM_MISMATCH_STOP'
with tarfile.open(archive) as t:
 for m in t.getmembers():
  if Path(m.name).is_absolute() or '..' in Path(m.name).parts:raise SystemExit('UNSAFE_ARCHIVE')
 # Extract only executable, licenses and versioned npm files; no arbitrary links.
 prefix='node-v22.23.3-linux-arm64/'
 for m in t.getmembers():
  if not m.isfile():continue
  rel=m.name.removeprefix(prefix)
  if not (rel=='bin/node' or rel in ['LICENSE','README.md'] or rel.startswith('lib/node_modules/npm/')):continue
  target=root/'runtime'/rel;target.parent.mkdir(parents=True,exist_ok=True,mode=0o700);target.write_bytes(t.extractfile(m).read());target.chmod(0o500 if rel=='bin/node' else 0o400)
node=root/'runtime/bin/node';data=node.read_bytes();assert data[:4]==b'\x7fELF' and struct.unpack('<H',data[18:20])[0]==183
(out/'verified-node.json').write_text(json.dumps({'artifact':lock['artifact'],'actualSha256':actual,'expectedSha256':lock['sha256'],'matched':True,'binarySha256':hashlib.sha256(data).hexdigest(),'ELF':'64-bit AArch64','installedGlobally':False,'runtime':str(root/'runtime')},indent=2));print('OFFICIAL_NODE_SHA_ELF_VERIFIED')
