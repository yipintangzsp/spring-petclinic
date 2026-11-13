import pathlib,json,runpy,shlex,os,signal,subprocess,time,sys
sys.dont_write_bytecode=True
h=pathlib.Path(__file__).resolve().parent;p=runpy.run_path('evidence/2026-11-05/gitlab-push-demo/preflight.py');prep=json.loads((h/'prepared.json').read_text());ids=[prep['readTokenId']]
code=p['PREFIX']+r'''
import java.security.MessageDigest
import javax.xml.transform.stream.StreamSource
def d=Jenkins.instance.getItemByFullName('security-gitlab-push-demo');assert !d.isBuilding()
def hash={byte[] b->MessageDigest.getInstance('SHA-256').digest(b).encodeHex().toString()};assert hash(d.definition.script.bytes)=='@JOBHASH@'
def backup=new File(d.rootDir,'config.before-runner-recovery-20261107.xml');assert backup.exists();d.updateByXml(new StreamSource(new ByteArrayInputStream(backup.bytes)));d.save();assert hash(d.definition.script.bytes)=='3480fb1418a7d790a05d334f43b58df382ac52d81557ae5f203690093f73e6ff'
@IDS@.each{id->def t=api('/personal_access_tokens/'+id);assert t.user_id==4;def c=new URL('http://gitlab-service.ns-devops.svc.cluster.local/api/v4/personal_access_tokens/'+id).openConnection();c.setRequestProperty('PRIVATE-TOKEN',cred.password.plainText);c.requestMethod='DELETE';c.connectTimeout=4000;c.readTimeout=6000;assert c.responseCode==204;assert api('/personal_access_tokens/'+id).revoked}
println(JsonOutput.toJson([demoOriginalDefinitionRestored:true,lastBuild:d.lastBuild.number,lastResult:d.lastBuild.result.toString(),tokensRevoked:@IDS@,activeTokens:api('/personal_access_tokens?user_id=4&state=active').findAll{it.active&&!it.revoked}.collect{it.id},productionJobModified:false]))
'''
x=p['script'](code.replace('@IDS@',json.dumps(ids)).replace('@JOBHASH@',json.loads((h/'job-installed.json').read_text())['definitionAfterSha256']))
channel=json.loads((h/'channel.json').read_text());pid=channel['pid'];q=subprocess.run(['/bin/ps','-p',str(pid),'-o','command='],capture_output=True,text=True)
if q.returncode==0:
 assert '/var/lib/security-gitleaks/ci-channel/manager.sock:'+channel['localSocket']in q.stdout
 os.kill(pid,signal.SIGTERM)
 for _ in range(15):
  q=subprocess.run(['/bin/ps','-p',str(pid),'-o','stat='],capture_output=True,text=True)
  if q.returncode or q.stdout.lstrip().startswith('Z'):break
  time.sleep(.1)
 else:raise RuntimeError('TUNNEL_TERMINATION_UNCONFIRMED')
remote=r'''
import pathlib,json,sys,os,hashlib,shutil
meta=json.load(sys.stdin);r=pathlib.Path('/var/tmp/security-manager-gitleaks-recovery-20261107');old=pathlib.Path('/var/tmp/security-manager-gitleaks-v2-linux-20261105');f=old/'ssh-entry.py';backup=pathlib.Path(meta['sourceEntryBackup']);b=backup.read_bytes();assert hashlib.sha256(b).hexdigest()==meta['sourceEntryBeforeSha256'];f.write_bytes(b);f.chmod(0o444)
keys=pathlib.Path('/var/lib/security-gitleaks/.ssh/authorized_keys');st=keys.stat();b=pathlib.Path(meta['scannerKeysBackup']).read_bytes();assert hashlib.sha256(b).hexdigest()==meta['scannerKeysBeforeSha256'];keys.write_bytes(b);os.chown(keys,st.st_uid,st.st_gid);keys.chmod(st.st_mode&511)
for name in ['/usr/local/libexec/security-manager-ci-dispatch.py','/var/lib/security-gitleaks/manager-ci-capability.json',str(r/'read-token'),str(r/'askpass.py')]:
 f=pathlib.Path(name);assert f.is_file()and not f.is_symlink();f.unlink()
s=pathlib.Path('/var/lib/security-gitleaks/ci-channel/manager.sock')
if s.exists():assert s.is_socket();s.unlink()
s.parent.rmdir();assert not any(p.name.startswith(('source-web-','read-preflight-','input-check-','blob-inspect-','scan-'))for p in(r/'outputs').iterdir())
# Own current invocation processes must have completed, no UID24021 scanner remnants.
processes=[]
for p in pathlib.Path('/proc').iterdir():
 if not p.name.isdigit():continue
 try:
  if p.stat().st_uid==24021:processes.append(int(p.name))
 except FileNotFoundError:pass
assert not processes,'SCANNER_ACCOUNT_PROCESS_REMAINS'
print(json.dumps({'scannerEntryRestored':True,'authorizedKeysRestored':True,'credentialsFilesRemoved':True,'remoteSocketRemoved':True,'temporarySourceRemoved':True,'scannerAccountProcessesRemaining':len(processes),'sealedNonsecretArtifactsRetained':True,'retainedDirectory':str(r)}))
'''
x.update(json.loads(p['m']['remote']('sudo -n python3 -c '+shlex.quote(remote),json.dumps(prep),timeout=20)))
f=pathlib.Path('.devsecops/security-view-ci-capability-v1.json');cap=json.loads(f.read_text());claim=pathlib.Path(cap['stateDirectory'])/'ci-claim.json';body=json.loads(claim.read_text());(h/'consumed-claim.json').write_text(json.dumps(body));claim.unlink();f.unlink()
# Restore original inactive source configuration; sealed new run keeps exact source evidence.
f=pathlib.Path('infra/security/manager-v2/ci/projects.json');f.write_bytes(subprocess.check_output(['git','show','7ea8a765:infra/security/manager-v2/ci/projects.json']))
q=subprocess.run(['node','infra/security/manager-v2/view/control.mjs','restart'],capture_output=True,text=True,timeout=20);assert q.returncode==0,q.stderr;assert not pathlib.Path(channel['localSocket']).exists();x.update({'localCapabilityRemoved':True,'channelTerminated':True,'localSocketRemoved':True,'originalFixtureConfigurationRestored':True})
with(h/'cleanup.json').open('x')as f:json.dump(x,f,indent=2)
print(json.dumps(x))
