import subprocess,json,uuid
name='trivy-isolation-'+uuid.uuid4().hex[:12]
def run(a,t=15):
 r=subprocess.run(a,capture_output=True,text=True,timeout=t);return {'command':a,'exit':r.returncode,'stdout':r.stdout[:6000],'stderr':r.stderr[:2000]}
image=run(['docker','image','inspect','python:3.14.8-slim-trixie','--format','{{.Id}}']);rows=[image];img=image['stdout'].strip();assert image['exit']==0 and img.startswith('sha256:')
code="""import os,pathlib,json,signal,time
r={'uid':os.getuid(),'cgroup':pathlib.Path('/proc/self/cgroup').read_text(),'mounts':pathlib.Path('/proc/self/mountinfo').read_text()}
for name,p in [('root','/outside'),('symlink','/tmp/link/outside')]:
 try:
  if name=='symlink':os.symlink('/','/tmp/link')
  pathlib.Path(p).write_text('disposable');r[name]='WRITE_ALLOWED'
 except OSError as e:r[name]='DENIED:'+str(e.errno)
pid=os.fork()
if pid==0:
 os.setsid();signal.signal(signal.SIGTERM,signal.SIG_IGN);time.sleep(7);os._exit(0)
r['child']=pid;print(json.dumps(r),flush=True)
signal.signal(signal.SIGTERM,signal.SIG_IGN);time.sleep(7)
"""
try:
 rows.append(run(['docker','run','--detach','--pull=never','--name',name,'--label','purpose=trivy-isolation-controlled-fixture','--network=none','--read-only','--cap-drop=ALL','--security-opt=no-new-privileges','--pids-limit=12','--memory=48m','--memory-swap=48m','--cpus=0.1','--user=65534:65534','--tmpfs','/tmp:rw,nosuid,nodev,noexec,size=4m','--log-driver=none',img,'python3','-B','-c',code]))
 rows.append(run(['docker','inspect',name,'--format','{{json .State}} {{json .HostConfig}}']))
 rows.append(run(['docker','top',name,'-eo','pid,ppid,comm']))
 rows.append(run(['docker','stop','--time=1',name]))
 rows.append(run(['docker','inspect',name,'--format','{{json .State}}']))
finally:
 rows.append(run(['docker','rm','-f',name]));rows.append(run(['docker','inspect',name]))
print(json.dumps({'classification':'REAL_CONTROLLED_CONTAINER_NO_TRIVY','rows':rows,'note':'log-driver none deliberately; filesystem facts must be captured by attached transport in future complete test; not VERIFIED'},indent=2))
