"""Trusted operator preparation: cached OCI image read only; disposable directory only."""
import subprocess,shlex,json
from pathlib import Path
O=Path(__file__).resolve().parent
S=['ssh','-o','BatchMode=yes','-o','ConnectTimeout=6','-o','StrictHostKeyChecking=yes','-o','HostName=192.168.64.11','-o','HostKeyAlias=192.168.1.58','zhang@192.168.1.58']
script=r'''
import pathlib,tempfile,subprocess,tarfile,json,hashlib,io,os,shutil,struct
image='127.0.0.1:30050/platform-security/gitleaks@sha256:6b2d52241f9d176fc59e6e3b026ea52c98f390070587d9475d6ee2bc64941815';digest=image.split('@')[1]
assert shutil.disk_usage('/var/tmp').free>1024**3
mem=dict(line.split(':',1) for line in pathlib.Path('/proc/meminfo').read_text().splitlines());assert int(mem['MemAvailable'].split()[0])*1024>1024**3
root=pathlib.Path(tempfile.mkdtemp(prefix='security-manager-gitleaks-',dir='/var/tmp'));root.chmod(0o755);archive=root/'cached.oci'
try:
 subprocess.run(['k3s','ctr','-n','k8s.io','images','export','--platform','linux/arm64',str(archive),image],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.PIPE,timeout=60)
 assert archive.stat().st_size<128*1024**2
 with tarfile.open(archive) as tar:
  def blob(d):
   b=tar.extractfile('blobs/'+d.replace(':','/')).read();assert 'sha256:'+hashlib.sha256(b).hexdigest()==d;return b
  descriptor=json.loads(blob(digest));manifestDigest=digest
  if 'manifests'in descriptor:
   ref=next(r for r in descriptor['manifests'] if r.get('platform',{}).get('os')=='linux' and r.get('platform',{}).get('architecture')=='arm64');manifestDigest=ref['digest'];descriptor=json.loads(blob(manifestDigest))
  config=json.loads(blob(descriptor['config']['digest']));assert config['architecture']=='arm64' and config['os']=='linux'
  binary=None;layerDigest=None;entryName=None
  for layer in descriptor['layers']:
   data=blob(layer['digest'])
   with tarfile.open(fileobj=io.BytesIO(data),mode='r:*') as layerTar:
    for member in layerTar:
     if member.name.lstrip('./') in ['usr/bin/gitleaks','usr/local/bin/gitleaks','gitleaks']:
      assert member.isfile() and member.size<100*1024**2;binary=layerTar.extractfile(member).read();layerDigest=layer['digest'];entryName=member.name
  assert binary and binary[:4]==b'\x7fELF' and struct.unpack('<H',binary[18:20])[0]==183
  target=root/'gitleaks';target.write_bytes(binary);target.chmod(0o555)
 provenance={'workspace':str(root),'tool':{'path':str(target),'version':'8.30.1','image':image,'sha256':hashlib.sha256(binary).hexdigest(),'bytes':len(binary)},'verifiedOCILineage':{'imageDigest':digest,'manifestDigest':manifestDigest,'layerDigest':layerDigest,'entry':entryName,'allBlobDigestsVerified':True},'dockerAPIUsed':False,'containerCreated':False,'imagePulled':False,'productionMutation':False}
 (root/'tool-provenance.json').write_text(json.dumps(provenance));(root/'tool-provenance.json').chmod(0o444);print(json.dumps(provenance))
finally:
 if archive.exists():archive.unlink()
'''
p=subprocess.run(S+['sudo -n python3 -'],input=script,text=True,capture_output=True,timeout=100)
if p.returncode:raise SystemExit('Controlled cached-tool preparation failed: '+p.stderr[-1500:])
x=json.loads(p.stdout)
with (O/'linux-tool-provenance.json').open('x') as f:json.dump(x,f,indent=2);f.write('\n')
print(json.dumps(x))
