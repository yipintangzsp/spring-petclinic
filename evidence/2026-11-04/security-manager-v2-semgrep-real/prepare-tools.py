"""Bounded preparation from already pinned offline tools; no downloads or containers."""
import runpy,json,hashlib
from pathlib import Path
O=Path(__file__).resolve().parent;ROOT=O.parents[2]
if (O/'tool-preparation.json').exists():raise SystemExit('One-shot preparation already recorded; use a new round, no remote mutation')
api=runpy.run_path(str(O/'inspect-production.py'))
raw=(ROOT/'infra/security/scanner-tools.json').read_bytes();lock=json.loads(raw)
assert hashlib.sha256(raw).hexdigest()=='4fdb335010b9bf57d61d5e28d1397285c813bfa9bbf2ac008efddb8f27e3b703'
script=r'''
import pathlib,tempfile,subprocess,tarfile,json,hashlib,io,os,shutil,struct
image='127.0.0.1:30050/platform-security/gitleaks@sha256:6b2d52241f9d176fc59e6e3b026ea52c98f390070587d9475d6ee2bc64941815';digest=image.split('@')[1]
assert shutil.disk_usage('/var/tmp').free>2*1024**3
mem=dict(line.split(':',1) for line in pathlib.Path('/proc/meminfo').read_text().splitlines());assert int(mem['MemAvailable'].split()[0])*1024>2*1024**3
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

 lock=LOCK
 assert hashlib.sha256(json.dumps(lock).encode()).hexdigest()==LOCK_OBJECT_HASH
 rows=[e for e in lock['files'] if e['path']=='semgrep/semgrep-core' or e['path'].startswith('semgrep/libs/')]
 assert len(rows)==27 and sum(e['bytes'] for e in rows)<320*1024**2
 # Only read the existing tool PVC; never alter its source contents or mode.
 pods=json.loads(subprocess.check_output(['kubectl','-n','ns-devops','get','pods','-l','app=jenkins','-o','json'],text=True))['items']
 v=next(v for v in pods[0]['spec']['volumes'] if 'persistentVolumeClaim' in v)
 pvc=json.loads(subprocess.check_output(['kubectl','-n','ns-devops','get','pvc',v['persistentVolumeClaim']['claimName'],'-o','json'],text=True));pv=json.loads(subprocess.check_output(['kubectl','get','pv',pvc['spec']['volumeName'],'-o','json'],text=True))
 host=pv['spec'].get('hostPath',pv['spec'].get('local',{}))['path'];src=pathlib.Path(host)/'platform-security/20261027'
 for entry in rows:
  source=src/entry['path'];assert source.is_file() and not source.is_symlink() and source.stat().st_size==entry['bytes']
  dest=root/entry['path'];dest.parent.mkdir(parents=True,exist_ok=True)
  shutil.copyfile(source,dest);assert hashlib.sha256(dest.read_bytes()).hexdigest()==entry['sha256'];dest.chmod(0o555 if entry['path'].endswith('semgrep-core') else 0o444)
 for d,ds,fs in os.walk(root/'semgrep'):pathlib.Path(d).chmod(0o555)
 provenance['semgrep']={'version':lock['versions']['semgrep'],'path':str(root/'semgrep/semgrep-core'),'libraryDirectory':str(root/'semgrep/libs'),'files':rows,'manifestSha256':LOCK_BYTES_HASH,'source':'existing pinned production offline tool bundle copied read-only','platform':'linux/arm64'}
 cmd=['setpriv','--reuid=65534','--regid=65534','--clear-groups','--no-new-privs','--bounding-set=-all','env','-i','PATH=/usr/bin:/bin','HOME='+str(root),'LD_LIBRARY_PATH='+str(root/'semgrep/libs'),str(root/'semgrep/semgrep-core'),'-version']
 ver=subprocess.run(cmd,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,timeout=10)
 provenance['semgrepVersionProbe']={'exit':ver.returncode,'stdout':ver.stdout.strip(),'stderr':ver.stderr[:800],'identity':'uid/gid65534, groups cleared,NoNewPrivs,zero capabilities','scannerInvoked':False}
 assert ver.returncode==0 and lock['versions']['semgrep'] in ver.stdout+ver.stderr,provenance['semgrepVersionProbe']
 provenance['temporaryBudget']={'declaredCeilingBytes':700*1024**2,'requiredFreeBeforeBytes':2*1024**3,'noProductionQuotaOrThresholdChange':True}
 (root/'tool-provenance.json').write_text(json.dumps(provenance));(root/'tool-provenance.json').chmod(0o444);print(json.dumps(provenance))
except Exception:
 shutil.rmtree(root)
 raise
finally:
 if archive.exists():archive.unlink()
'''

prefix='LOCK='+repr(lock)+'\nLOCK_OBJECT_HASH='+repr(hashlib.sha256(json.dumps(lock).encode()).hexdigest())+'\nLOCK_BYTES_HASH='+repr(hashlib.sha256(raw).hexdigest())+'\n'
x=json.loads(api['remote']('sudo -n python3 -',prefix+script,120));api['save']('tool-preparation.json',x);print(json.dumps({'workspace':x['workspace'],'semgrepVersionProbe':x['semgrepVersionProbe'],'files':len(x['semgrep']['files']),'productionMutation':False}))
