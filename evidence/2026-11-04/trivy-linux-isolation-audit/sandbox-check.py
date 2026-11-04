import tempfile,pathlib,subprocess,json,os,time,shutil
p=pathlib.Path(tempfile.mkdtemp(prefix='trivy-native-boundary-'));os.chmod(p,0o700)
f=p/'sentinel';f.write_text('unchanged');unit='trivy-boundary-'+str(int(time.time()))
code="import os,json,pathlib; p=pathlib.Path("+repr(str(f))+"); d={'mnt':os.readlink('/proc/self/ns/mnt'),'user':os.readlink('/proc/self/ns/user'),'cgroup':pathlib.Path('/proc/self/cgroup').read_text()};\ntry:p.write_text('WRITE_ESCAPED');d['outsideWrite']='ALLOWED'\nexcept OSError as e:d['outsideWrite']='DENIED';d['errno']=e.errno\nprint(json.dumps(d))"
c=['systemd-run','--user','--wait','--pipe','--collect','--unit='+unit,'-p','Type=exec','-p','KillMode=control-group','-p','RuntimeMaxSec=5','-p','MemoryMax=32M','-p','TasksMax=8','-p','NoNewPrivileges=yes','-p','ProtectSystem=strict','-p','ProtectHome=yes','-p','PrivateTmp=yes','-p','PrivateUsers=yes','/usr/bin/python3','-B','-c',code]
r=subprocess.run(c,capture_output=True,text=True,timeout=15)
d={'command':c,'exit':r.returncode,'stdout':r.stdout,'stderr':r.stderr,'hostNamespaces':{n:os.readlink('/proc/self/ns/'+n) for n in ['mnt','user']},'sentinelUnchanged':f.read_text()=='unchanged'}
d['unitAfter']=subprocess.run(['systemctl','--user','show',unit,'-p','LoadState','-p','ActiveState'],capture_output=True,text=True).stdout
shutil.rmtree(p);d['fixtureRemoved']=not p.exists();print(json.dumps(d,indent=2))
