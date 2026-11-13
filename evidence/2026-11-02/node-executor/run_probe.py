from pathlib import Path
import json,tarfile,subprocess,hashlib,os
out=Path(__file__).resolve().parent;root=Path(json.loads((out/'runtime-root.json').read_text())['path']);bundle=out/'bundle'
for p in [bundle,bundle/'harness',bundle/'results',bundle/'work']:
 p.chmod(0o700)
# Pin the existing base by its full immutable local ID; no pull/tag resolution.
base='sha256:452d707d4862f52530247495d180205e029056831160e22870e37e3f6c1ac31f'
args=['/opt/homebrew/bin/docker','--host','unix:///Users/zhangsir/.colima/security-test/docker.sock','run','--rm','--pull=never','--interactive','--network','none','--read-only','--cap-drop','ALL','--security-opt','no-new-privileges','--user','65532:65532','--pids-limit','64','--memory','512m','--cpus','1','--tmpfs','/fixture:rw,exec,nosuid,nodev,size=256m,mode=1777','--tmpfs','/tmp:rw,exec,nosuid,nodev,size=32m,mode=1777','--env','PYTHONDONTWRITEBYTECODE=1','--entrypoint','/bin/sh',base,'-c','umask 077; tar xf - -C /fixture; /usr/bin/python3 /fixture/linux_guard_probe.py']
# No credentials/HOME mounts. Only public runtime, no-secret harness and frozen source copies.
with (out/'probe-linux.stdout.json').open('wb') as stdout,(out/'probe-linux.stderr.log').open('wb') as stderr:
 proc=subprocess.Popen(args,stdin=subprocess.PIPE,stdout=stdout,stderr=stderr)
 try:
  with tarfile.open(fileobj=proc.stdin,mode='w|') as t:
   for item in sorted(bundle.iterdir()):t.add(item,arcname=item.name)
   t.add(root/'runtime',arcname='runtime')
 finally:proc.stdin.close()
 ret=proc.wait(timeout=90)
(out/'container-execution.json').write_text(json.dumps({'baseImageId':base,'linuxNodeArchiveSha256':json.loads((out/'node-lock.json').read_text())['sha256'],'exitCode':ret,'network':'none','user':'65532:65532','readOnlyRoot':True,'capabilitiesDropped':['ALL'],'hostMounts':[],'tmpfsOnly':True,'productionCredentials':False,'realMinAuthentication':'NOT_TESTED; synthetic transport explicitly accepted','gateBodyEvaluated':False},indent=2))
if ret:raise SystemExit('NODE_PROBE_FAILED exit='+str(ret)+'; inspect test-only stderr')
data=json.loads((out/'probe-linux.stdout.json').read_text());(out/'startup-result.json').write_text(json.dumps(data,indent=2));print(json.dumps({'containerExit':ret,'node':data['integration']['versions'],'arch':data['integration']['machine'],'gateLink':data['startup']['gateLinkStatus'],'gateBodyEvaluated':data['startup']['gateBodyEvaluated'],'guardSanity':data['integration']['guardSanity']}))
