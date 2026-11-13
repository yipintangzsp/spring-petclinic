import pathlib,json,subprocess,runpy,time,os,shlex
h=pathlib.Path(__file__).resolve().parent;p=runpy.run_path('evidence/2026-11-05/gitlab-push-demo/preflight.py');cfg=json.loads((h/'prepared.json').read_text());assert pathlib.Path(cfg['localSocket']).is_socket()
log=h/'channel.log';f=log.open('xb');args=p['m']['SSH']+['-N','-T','-o','ControlMaster=no','-o','ControlPath=none','-o','ExitOnForwardFailure=yes','-o','StreamLocalBindUnlink=no','-o','ServerAliveInterval=5','-o','ServerAliveCountMax=2','-R','/var/lib/security-gitleaks/ci-channel/manager.sock:'+cfg['localSocket']]
child=subprocess.Popen(args,stdin=subprocess.DEVNULL,stdout=f,stderr=f,start_new_session=True);f.close();time.sleep(1);assert child.poll()is None,'CHANNEL_FAILED'
code=r'''
import os,pathlib,stat,json,socket,http.client,subprocess
p=pathlib.Path('/var/lib/security-gitleaks/ci-channel/manager.sock');s=p.stat();assert stat.S_ISSOCK(s.st_mode)and s.st_uid==1000
os.chown(p,1000,24021);p.chmod(0o660)
check="import socket; s=socket.socket(socket.AF_UNIX); s.connect('/var/lib/security-gitleaks/ci-channel/manager.sock')"
r=subprocess.run(['setpriv','--reuid=65534','--regid=65534','--clear-groups','python3','-c',check],capture_output=True,text=True,timeout=5);assert r.returncode!=0 and 'PermissionError'in r.stderr
print(json.dumps({'socketUid':p.stat().st_uid,'socketGid':p.stat().st_gid,'mode':oct(p.stat().st_mode&511),'unrelatedUidDenied':True,'linuxTcpListenerCreated':False,'sshdChanged':False}))
'''
x=json.loads(p['m']['remote']('sudo -n python3 -c '+shlex.quote(code),timeout=15));x['pid']=child.pid;x['localSocket']=cfg['localSocket']
with(h/'channel.json').open('x')as f:json.dump(x,f,indent=2)
print(json.dumps(x))
