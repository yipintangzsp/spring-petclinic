import pathlib,subprocess,hashlib,os,json,datetime,urllib.request,socket,stat,tempfile
report={'modified':False,'socketChanged':False,'rollback':False}
root=pathlib.Path('/var/backups/docker-socket-change-20261104-1234');target=pathlib.Path('/etc/systemd/system/docker.service.d/override.conf');old=(root/'override.conf').read_bytes();expected=b'[Service]\nExecStartPost=/bin/chmod 666 /var/run/docker.sock\n';new=old.replace(b'chmod 666 ',b'chmod 0660 ')
def run(c):
 r=subprocess.run(c,capture_output=True,text=True,timeout=30);assert r.returncode==0,{'cmd':c,'exit':r.returncode,'stderr':r.stderr[-1200:]};return r.stdout
def install(b):
 fd,name=tempfile.mkstemp(prefix='.socket-permission-',dir=str(target.parent))
 try:
  os.fchmod(fd,0o644);os.write(fd,b);os.fsync(fd);os.close(fd);os.replace(name,target)
 finally:
  if os.path.exists(name):os.unlink(name)
def daemon():return run(['systemctl','show','docker.service','-p','MainPID','-p','ExecMainStartTimestampMonotonic','-p','NRestarts','-p','ActiveState'])
try:
 assert datetime.datetime.now(datetime.timezone.utc)<datetime.datetime(2026,11,4,5,4,tzinfo=datetime.timezone.utc),'WINDOW_CLOSED'
 assert old==expected and target.read_bytes()==old
 assert hashlib.sha256((root/'limits.conf').read_bytes()).hexdigest()=='48f794a8f78486485c4d8d20cdd1e0fbaf4b88a210741046e4b8b54b3e785782'
 ids=run(['kubectl','exec','-n','ns-devops','deploy/jenkins','--','id']);assert '988'in ids
 api=run(['kubectl','exec','-n','ns-devops','deploy/jenkins','--','docker','info','--format','{{.ID}}']);assert api.strip()=='4616ba22-4e70-4b96-8e66-6a3a4d756cb2'
 s=os.stat('/run/docker.sock');assert (s.st_uid,s.st_gid,s.st_ino,s.st_mode&0o777)==(0,988,1405,0o666)
 before=daemon();assert 'MainPID=983\n'in before and 'NRestarts=0\n'in before and 'ActiveState=active'in before
 report['daemonBefore']=before;report['startedAt']=datetime.datetime.now(datetime.timezone.utc).isoformat()
 install(new);report['modified']=True
 report['systemdVerify']=run(['systemd-analyze','verify','docker.service','docker.socket'])
 run(['systemctl','daemon-reload']);effective=run(['systemctl','show','docker.service','-p','ExecStartPost']);assert 'chmod 0660 /var/run/docker.sock'in effective and 'chmod 666 'not in effective
 os.chmod('/run/docker.sock',0o660);report['socketChanged']=True
 s=os.stat('/run/docker.sock');assert (s.st_uid,s.st_gid,s.st_ino,s.st_mode&0o777)==(0,988,1405,0o660)
 deny="import socket,errno,json; s=socket.socket(socket.AF_UNIX);\ntry:s.connect('/run/docker.sock');print('ALLOWED');raise SystemExit(7)\nexcept OSError as e:\n assert e.errno==errno.EACCES,e;print('DENIED_EACCES')"
 report['unauthorized']=run(['sudo','-n','-u','nobody','/usr/bin/python3','-B','-c',deny]);assert 'DENIED_EACCES'in report['unauthorized']
 report['jenkinsIdentity']=run(['kubectl','exec','-n','ns-devops','deploy/jenkins','--','id']);report['jenkinsDocker']=run(['kubectl','exec','-n','ns-devops','deploy/jenkins','--','docker','info','--format','{{.ID}}'])
 report['runnerDocker']=run(['sudo','-n','-u','gitlab-runner','docker','info','--format','{{.ID}}']);report['zhangDocker']=run(['sudo','-n','-u','zhang','docker','info','--format','{{.ID}}'])
 with urllib.request.urlopen('http://127.0.0.1:9000/api/status',timeout=5) as r:assert r.status==200;report['portainerStatus']=r.status
 assert daemon()==before,'DAEMON_CHANGED'
 assert pathlib.Path('/etc/systemd/system/docker.service.d/limits.conf').read_bytes()==(root/'limits.conf').read_bytes()
 assert pathlib.Path('/usr/lib/systemd/system/docker.socket').read_bytes()==(root/'docker.socket').read_bytes()
 report.update(status='VERIFIED',effectiveExecStartPost=effective,daemonAfter=daemon(),socketMode='0660',socketInode=s.st_ino,daemonRestartCount=0,overrideSha256=hashlib.sha256(target.read_bytes()).hexdigest(),finishedAt=datetime.datetime.now(datetime.timezone.utc).isoformat())
except Exception as e:
 report['error']=str(e)
 if report['modified']:
  if report['socketChanged']:os.chmod('/run/docker.sock',0o666)
  install(old);subprocess.run(['systemctl','daemon-reload'],capture_output=True);report['rollback']=True;report['status']='ROLLED_BACK';report['risk']='Original world-writable permission restored by authorized emergency rollback'
 else:report['status']='NOT_EXECUTED'
finally:
 (root/'execution-receipt.json').write_text(json.dumps(report,indent=2));os.chmod(root/'execution-receipt.json',0o600)
 print(json.dumps(report,indent=2))
