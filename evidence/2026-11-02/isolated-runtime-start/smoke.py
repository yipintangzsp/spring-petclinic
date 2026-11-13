"""One owned disposable container on the proven local socket; network none, no mounts."""
from pathlib import Path
import subprocess,json,os,datetime,re,hashlib,tempfile,tarfile
B=Path(__file__).resolve().parent
ENV={k:os.environ[k] for k in ['PATH','USER','LOGNAME','SHELL','TMPDIR','LANG','LC_ALL','__CF_USER_TEXT_ENCODING'] if k in os.environ}
ENV['HOME']=str(B/'docker-client-config');ENV['DOCKER_CONFIG']=str(B/'docker-client-config')
CLI=['/opt/homebrew/bin/docker','--host','unix:///Users/zhangsir/.colima/security-test/docker.sock']
trace=[]
def call(args,timeout=20,required=True):
 p=subprocess.run(CLI+args,env=ENV,capture_output=True,text=True,timeout=timeout)
 trace.append({'args':args,'exit':p.returncode,'stdout':p.stdout,'stderr':p.stderr})
 if required and p.returncode:raise RuntimeError('Docker command failed: '+args[0]+': '+p.stderr)
 return p
assert json.loads((B/'mount-credential-assessment.json').read_text())['status']=='PASS'
assert json.loads((B/'start-result.json').read_text())['exit']==0
pre=json.loads((B/'pre-start-protection.json').read_text())
for x in pre['files']:
 p=Path(x['path']);assert (hashlib.sha256(p.read_bytes()).hexdigest() if p.is_file() else None)==x['sha256']
image=json.loads(call(['image','inspect','security-test-smoke:busybox-1.37.0']).stdout)[0]
assert image['Os']=='linux' and image['Architecture']=='arm64'
assert not image['Config'].get('Volumes')
config_hash=re.findall(r'Copying config (sha256:[a-f0-9]{64})',(B/'host-public-image-copy.log').read_text())
assert len(config_hash)==1
# Docker's current containerd store can expose a manifest identity as Id.
# Verify exported public config bytes instead of equating two different digest types.
with tempfile.TemporaryDirectory(prefix='security-test-image-verify-') as temp:
 archive=Path(temp)/'loaded.tar';call(['image','save','--output',str(archive),image['Id']],timeout=30)
 with tarfile.open(archive) as tf:
  manifests=json.load(tf.extractfile('manifest.json'));assert len(manifests)==1
  config_bytes=tf.extractfile(manifests[0]['Config']).read();exported_config='sha256:'+hashlib.sha256(config_bytes).hexdigest()
  assert exported_config==config_hash[0]
  configuration=json.loads(config_bytes);assert configuration['architecture']=='arm64' and configuration['os']=='linux'
(B/'image-payload-binding.json').write_text(json.dumps({'source':'Anonymous public BusyBox copy','copiedConfigDigest':config_hash[0],'loadedImageId':image['Id'],'exportedConfigDigest':exported_config,'match':True,'imageOS':'linux','imageArch':'arm64','temporaryImageExportCleaned':True,'digestTypeNote':'Image Id is not assumed to equal config digest'},indent=2)+'\n')
names=[x.split('=',1)[0] for x in image['Config'].get('Env',[])]
assert all(x in ['PATH'] for x in names),names
name='security-test-runtime-smoke-'+datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%d%H%M%S')
result={'sourceImage':'docker.io/library/busybox:1.37.0','localImageId':image['Id'],'imageArchitecture':'linux/arm64','imageDigestFile':(B/'public-image-copy.digest').read_text().strip(),'name':name,'network':'none','binds':[],'volumes':[],'credentials':[],'expectedOutput':'SECURITY_TEST_SMOKE_OK','passed':False}
cid=None
try:
 args=['create','--name',name,'--pull','never','--network','none','--read-only','--cap-drop','ALL','--security-opt','no-new-privileges:true','--user','65534:65534','--pids-limit','16','--memory','32m','--cpus','0.25','--label','security-manager.runtime-smoke='+name,'--entrypoint','/bin/sh',image['Id'],'-c','printf "%s\\n" SECURITY_TEST_SMOKE_OK']
 result['createArguments']=args;cid=call(args).stdout.strip();result['containerId']=cid
 raw=json.loads(call(['inspect',cid]).stdout)[0];host=raw['HostConfig']
 assert raw['Mounts']==[] and not host.get('Binds') and not host.get('VolumesFrom') and not host.get('Mounts')
 assert host['NetworkMode']=='none' and not host['Privileged'] and host['ReadonlyRootfs']
 assert host['CapDrop']==['ALL'] and not host.get('PortBindings') and not host.get('Devices')
 assert host['SecurityOpt']==['no-new-privileges:true'] and raw['Config']['User']=='65534:65534'
 assert raw['Config']['Labels']['security-manager.runtime-smoke']==name
 assert [x.split('=',1)[0] for x in raw['Config'].get('Env',[])]==names
 result['preRunSecurityInspection']={'mounts':raw['Mounts'],'network':host['NetworkMode'],'privileged':host['Privileged'],'readOnly':host['ReadonlyRootfs'],'capDrop':host['CapDrop'],'securityOpt':host['SecurityOpt'],'user':raw['Config']['User'],'envNames':names,'ports':host.get('PortBindings')}
 run=call(['start','--attach',cid],timeout=30);result['actualOutput']=run.stdout.strip();assert result['actualOutput']==result['expectedOutput']
 state=json.loads(call(['inspect',cid]).stdout)[0]['State'];result['exitState']=state
 assert state['Running'] is False and state['ExitCode']==0 and not state['OOMKilled']
 result['passed']=True
except Exception as error:
 result['error']=str(error)
finally:
 if cid:
  p=call(['rm',cid],required=False)
  if p.returncode:result['cleanupError']=p.stderr
  result['removed']=p.returncode==0
  p=call(['inspect',cid],required=False);result['confirmedAbsent']=p.returncode!=0 and 'no such' in p.stderr.lower()
 result['trace']=trace
 (B/'smoke-result.json').write_text(json.dumps(result,indent=2)+'\n')
print(json.dumps({k:result.get(k) for k in ['localImageId','containerId','passed','actualOutput','removed','confirmedAbsent','error','cleanupError']}))
if not(result['passed'] and result.get('removed') and result.get('confirmedAbsent')):raise SystemExit(1)
