from pathlib import Path
import json,subprocess,hashlib,tarfile,struct
out=Path('evidence/2026-11-02/sops-authoritative-baseline-02');root=Path(json.loads((out/'root-reference.json').read_text())['root']);tools=root/'tools'
plan=json.loads(Path('evidence/2026-11-02/sops-fixture-final-design/toolchain-plan.json').read_text());e=[]
for name in ['sops','age']:
 a=plan[name]['artifact'];p=tools/a['name']
 r=subprocess.run(['/usr/bin/curl','--fail','--location','--proto','=https','--proto-redir','=https','--connect-timeout','20','--max-time','480','--silent','--show-error','--continue-at','-','--output',str(p),a['browser_download_url']],capture_output=True)
 if r.returncode:raise SystemExit('OFFICIAL_DOWNLOAD_FAILED '+name+' exit='+str(r.returncode))
 sha=hashlib.sha256(p.read_bytes()).hexdigest();ok=sha==a['digest'].split(':')[1]
 e.append({'tool':name,'artifact':a['name'],'source':a['browser_download_url'],'actualSha256':sha,'expectedSha256':a['digest'].split(':')[1],'matched':ok})
 (out/'toolchain-download.json').write_text(json.dumps(e,indent=2))
 if not ok:raise SystemExit('CHECKSUM_MISMATCH_STOP '+name)
 if name=='sops':p.rename(tools/'sops')
 else:
  with tarfile.open(p) as t:
   members=t.getmembers()
   if any(Path(m.name).is_absolute() or '..' in Path(m.name).parts for m in members):raise SystemExit('UNSAFE_ARCHIVE_STOP')
   for binary in ['age','age-keygen']:
    matches=[m for m in members if m.name==('age/'+binary) and m.isfile()]
    if len(matches)!=1:raise SystemExit('ARCHIVE_MEMBER_MISMATCH')
    (tools/binary).write_bytes(t.extractfile(matches[0]).read())
for binary,expected in plan['frozenIndividualSha256'].items():
 p=tools/binary;data=p.read_bytes();sha=hashlib.sha256(data).hexdigest()
 if sha!=expected:raise SystemExit('EXTRACTED_BINARY_CHECKSUM_MISMATCH_STOP '+binary)
 if data[:4]!=b'\x7fELF' or data[4]!=2 or struct.unpack('<H',data[18:20])[0]!=183:raise SystemExit('NOT_LINUX_AARCH64_STOP '+binary)
 p.chmod(0o500)
 e.append({'binary':binary,'actualSha256':sha,'matchesProductionLock':True,'architecture':'ELF64 AArch64'})
(out/'toolchain-download.json').write_text(json.dumps(e,indent=2));print(json.dumps({'officialAssets':'SHA256_MATCH','individualBinaries':'SHA256_MATCH','arch':'Linux AArch64','executions':0}))
