"""Export safe disposable execution evidence; never source files, binary or keys."""
from pathlib import Path
import runpy,json,base64,io,tarfile,hashlib
OUT=Path(__file__).resolve().parent;api=runpy.run_path(str(OUT/'inspect-production.py'));root=json.loads((OUT/'tool-preparation.json').read_text())['workspace']
s=r'''
import pathlib,json,hashlib,io,tarfile,base64,os
r=pathlib.Path(ROOT);assert r.is_dir() and r.stat().st_uid==0
fake='ghp_'+(r/'source-secret/Main.java').read_text().split('ghp_')[1].split(chr(34))[0]
files=list((r/'outputs').rglob('*.json'))+[p for p in r.iterdir() if p.is_file() and (p.name.endswith(('controller-result.json','suite.stdout','suite.stderr')) or p.name in ['tool-provenance.json','signature-preparation.json'])]+[p for p in (r/'cosign-fixtures').iterdir() if p.is_file()]
# Hash-only source/approval evidence, no plaintext source or credential values.
a=json.loads((r/'semgrep-approval.json').read_text());meta={'classification':'REAL_CONTROLLED_FIXTURE_APPROVAL_METADATA','scope':a['scope'],'executionUid':a['executionUid'],'authorization':a['authorization'],'sources':a['sources'],'rulesSha256':hashlib.sha256((r/'rules.json').read_bytes()).hexdigest(),'approvalSha256':hashlib.sha256((r/'semgrep-approval.json').read_bytes()).hexdigest()}
stream=io.BytesIO();manifest={};total=0
with tarfile.open(fileobj=stream,mode='w:gz') as tar:
 for p in files:
  assert not p.is_symlink() and p.is_file() and p.stat().st_nlink==1 and p.stat().st_size<2*1024**2
  data=p.read_bytes();assert fake.encode()not in data,'Fake canary plaintext export rejected';assert not any(mark in data for mark in [b'-----BEGIN PRIVATE KEY',b'-----BEGIN ENCRYPTED PRIVATE KEY',b'-----BEGIN EC PRIVATE KEY',b'-----BEGIN OPENSSH PRIVATE KEY',b'-----BEGIN ENCRYPTED COSIGN PRIVATE KEY'])
  total+=len(data);assert total<16*1024**2
  name=str(p.relative_to(r));info=tarfile.TarInfo(name);info.size=len(data);info.mode=0o444;tar.addfile(info,io.BytesIO(data));manifest[name]={'sha256':hashlib.sha256(data).hexdigest(),'bytes':len(data)}
blob=stream.getvalue();print(json.dumps({'base64':base64.b64encode(blob).decode(),'manifest':manifest,'archiveSha256':hashlib.sha256(blob).hexdigest(),'metadata':meta,'fakePlaintextAbsent':True,'sourceExported':False,'publicSyntheticSignatureFixturesExported':True,'privateKeyExported':False,'binaryExported':False,'totalBytes':total}))
'''
x=json.loads(api['remote']('sudo -n python3 -','ROOT='+repr(root)+'\n'+s));blob=base64.b64decode(x.pop('base64'));assert hashlib.sha256(blob).hexdigest()==x['archiveSha256'];dest=OUT/'real-linux';dest.mkdir()
with tarfile.open(fileobj=io.BytesIO(blob)) as tar:
 for m in tar.getmembers():
  p=Path(m.name);assert m.isfile() and not p.is_absolute() and '..'not in p.parts
  b=tar.extractfile(m).read();assert hashlib.sha256(b).hexdigest()==x['manifest'][m.name]['sha256'];q=dest/p;q.parent.mkdir(parents=True,exist_ok=True)
  with q.open('xb') as f:f.write(b)
  q.chmod(0o444)
api['save']('export-proof.json',x);print(json.dumps({'exportedFiles':len(x['manifest']),'bytes':x['totalBytes'],'fakePlaintextAbsent':x['fakePlaintextAbsent'],'sourceExported':False,'testOnlyPublicSignatureMaterials':True}))
