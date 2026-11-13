import pathlib,runpy,json,shlex,os,signal,subprocess,time
h=pathlib.Path(__file__).resolve().parent;p=runpy.run_path('evidence/2026-11-05/gitlab-push-demo/preflight.py');prep=json.loads((h/'prepared.json').read_text());run=json.loads((h/'real-run.json').read_text());assert json.loads((h/'build8-observed.json').read_text())['result']=='SUCCESS'
code=p['PREFIX']+r'''
import java.security.MessageDigest
import javax.xml.transform.stream.StreamSource
def d=Jenkins.instance.getItemByFullName('security-gitlab-push-demo');assert !d.isBuilding()&&d.lastBuild.number==8&&d.lastBuild.result.toString()=='SUCCESS'
def hash={byte[] b->MessageDigest.getInstance('SHA-256').digest(b).encodeHex().toString()};assert hash(d.definition.script.bytes)=='cae6c33d937eeef1788b74affb47a2b9dcb7f0eed38d25844ee17fd8bb993533'
def backup=new File(d.rootDir,'config.before-manager-ci-20261107.xml');assert backup.exists();d.updateByXml(new StreamSource(new ByteArrayInputStream(backup.bytes)));d.save();assert hash(d.definition.script.bytes)=='3480fb1418a7d790a05d334f43b58df382ac52d81557ae5f203690093f73e6ff';assert d.getBuildByNumber(8).result.toString()=='SUCCESS'
def c=new URL('http://gitlab-service.ns-devops.svc.cluster.local/api/v4/personal_access_tokens/4').openConnection();c.setRequestProperty('PRIVATE-TOKEN',cred.password.plainText);c.requestMethod='DELETE';c.connectTimeout=4000;c.readTimeout=6000;assert c.responseCode==204
println(JsonOutput.toJson([demoOriginalDefinitionRestored:true,build7FailurePreserved:true,build8SuccessPreserved:true,writerTokenId:4,writerTokenRevoked:true,productionJobChanged:false]))
'''
x=p['script'](code)
channel=json.loads((h/'channel.json').read_text());pid=channel['pid'];cmd=subprocess.run(['/bin/ps','-p',str(pid),'-o','command='],capture_output=True,text=True)
if cmd.returncode==0:
 assert '/usr/bin/ssh'in cmd.stdout or cmd.stdout.lstrip().startswith('ssh ')
 assert '/var/lib/security-gitleaks/ci-channel/manager.sock:'+channel['localSocket']in cmd.stdout
 os.kill(pid,signal.SIGTERM)
 for _ in range(15):
  q=subprocess.run(['/bin/ps','-p',str(pid),'-o','stat='],capture_output=True,text=True)
  if q.returncode or q.stdout.lstrip().startswith('Z'):break
  time.sleep(.1)
 else:raise RuntimeError('CHANNEL_TERMINATION_NOT_CONFIRMED')
remote=r'''
import pathlib,os,json,hashlib
root=pathlib.Path('/var/lib/security-gitleaks');keys=root/'.ssh/authorized_keys';before=keys.read_text();backup=keys.with_name('authorized_keys.before-manager-ci-20261107');old=backup.read_bytes();assert 'security-manager-ci-dispatch.py'in before;st=keys.stat();keys.write_bytes(old);os.chown(keys,st.st_uid,st.st_gid);keys.chmod(st.st_mode&511)
assert hashlib.sha256(old).hexdigest()=='506c7e3c0cbe0e05b5b95a8e1d482214256650f055bb370f9b1867d2235c8c07'
f=root/'manager-ci-capability.json';assert f.stat().st_uid==0 and f.stat().st_gid==24021;f.unlink()
s=root/'ci-channel/manager.sock'
if s.exists():assert s.is_socket()and s.stat().st_uid==1000;s.unlink()
(root/'ci-channel').rmdir()
for name in ['/usr/local/libexec/security-manager-ci-dispatch.py','/usr/local/libexec/security-ci-standard-askpass','/var/lib/security-gitops-demo/ci-standard-git-token','/var/lib/security-gitops-demo/state/ci-standard-trigger.bundle']:
 f=pathlib.Path(name);assert f.is_file()and not f.is_symlink();f.unlink()
print(json.dumps({'scannerOriginalKeysRestored':True,'serverCapabilityRemoved':True,'remoteSocketRemoved':True,'newChannelDirectoryRemoved':True,'writerTokenFileRemoved':True,'temporaryWrapperRemoved':True,'legacyScannerProofEntryPreserved':pathlib.Path('/usr/local/libexec/security-gitleaks-ci-proof.py').is_file()}))
'''
x.update(json.loads(p['m']['remote']('sudo -n python3 -c '+shlex.quote(remote),timeout=20)))
f=pathlib.Path('.devsecops/security-view-ci-capability-v1.json');cap=json.loads(f.read_text());assert cap['buildId']==8
claim=pathlib.Path(cap['stateDirectory'])/'ci-claim.json';body=json.loads(claim.read_text());assert body['runId']==run['runId'];(h/'consumed-claim.json').write_text(json.dumps(body));claim.unlink();f.unlink()
r=subprocess.run(['node','infra/security/manager-v2/view/control.mjs','restart'],capture_output=True,text=True,timeout=20);assert r.returncode==0,r.stderr
assert not pathlib.Path(channel['localSocket']).exists();x.update({'localCapabilityRemoved':True,'localSocketRemoved':True,'channelTerminated':True,'managerRestartedWithoutCiListener':True,'cleanupComplete':True})
with(h/'cleanup.json').open('x')as out:json.dump(x,out,indent=2)
print(json.dumps(x))
