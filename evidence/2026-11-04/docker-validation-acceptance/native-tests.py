import os,json,pathlib,subprocess,tempfile,time,uuid,shutil
records=[];owned=[];base=pathlib.Path(tempfile.mkdtemp(prefix='docker-validation-acceptance-'));sentinel=base/'sentinel';sentinel.write_text('unchanged');hostpid=os.getpid()
def run(a,t=20):
 try:
  r=subprocess.run(a,capture_output=True,text=True,timeout=t);return {'command':a,'exit':r.returncode,'stdout':r.stdout[:24000],'stderr':r.stderr[:3000]}
 except subprocess.TimeoutExpired:return {'command':a,'timeout':True}
def check(a):
 r=run(a);records.append(r);assert r.get('exit')==0,str(r);return r['stdout']
info=json.loads(check(['docker','info','--format','{{json .}}']));version=json.loads(check(['docker','version','--format','{{json .}}']));image=check(['docker','image','inspect','python:3.14.8-slim-trixie','--format','{{.Id}}']).strip();assert image.startswith('sha256:')
# Only bounded tmpfs writes; no host bind mounts and no image pulls.
flags=['--pull=never','--network=none','--read-only','--cap-drop=ALL','--security-opt=no-new-privileges','--pids-limit=24','--memory=48m','--memory-swap=48m','--cpus=0.5','--user=65534:65534','--ipc=private','--shm-size=1m','--tmpfs','/validation:rw,nosuid,nodev,noexec,size=4m,uid=65534,gid=65534,mode=0700','--tmpfs','/tmp:rw,nosuid,nodev,noexec,size=1m','--log-driver=none']
pre="import os,json,time,signal,pathlib\n"
def one(name,code,action='wait'):
 ident=uuid.uuid4().hex[:12];n='trivy-acceptance-'+ident
 cid=check(['docker','run','-d','--name',n,'--label','purpose=trivy-docker-acceptance',*flags,image,'python3','-B','-c',pre+code]).strip();owned.append(cid)
 row={'case':name,'containerId':cid,'action':action,'classification':'REAL_CONTROLLED_EXECUTION'};records.append(row);cg=None
 try:
  if action!='wait':
   for _ in range(60):
    r=run(['docker','exec',cid,'cat','/validation/ready.json'])
    if r.get('exit')==0:row['facts']=json.loads(r['stdout']);break
    time.sleep(.1)
   assert 'facts'in row,'READINESS_NOT_OBSERVED'
   state=json.loads(check(['docker','inspect',cid,'--format','{{json .State}}']));pid=state['Pid'];line=pathlib.Path('/proc/'+str(pid)+'/cgroup').read_text();cg=pathlib.Path('/sys/fs/cgroup')/line.split('0::',1)[1].strip().lstrip('/')
   row['hostCgroup']=str(cg);row['cgroupBefore']=(cg/'cgroup.procs').read_text();row['topBefore']=check(['docker','top',cid,'-eo','pid,ppid,sid,comm'])
   if action=='cleanup-failure':
    denial=run(['docker','rm',cid]);row['cleanupDenial']=denial;assert denial.get('exit')!=0;row['wouldPermitNextStep']=False
   if action=='kill':check(['docker','kill',cid])
   elif action=='parent-exit':check(['docker','exec',cid,'python3','-c',"import pathlib;pathlib.Path('/validation/exit').touch()"])
   elif action=='timeout':
    row['watchdog']=run(['docker','wait',cid],1);assert row['watchdog'].get('timeout');check(['docker','stop','--timeout=1',cid])
   else:check(['docker','stop','--timeout=1',cid])
  check(['docker','wait',cid]);state=json.loads(check(['docker','inspect',cid,'--format','{{json .State}}']));row['stateAfter']=state;assert not state['Running'] and state['Pid']==0
  if cg is not None:
   row['cgroupExistsAfter']=cg.exists();row['eventsAfter']=(cg/'cgroup.events').read_text() if cg.exists() else None;assert not cg.exists() or 'populated 0'in row['eventsAfter']
  check(['docker','rm',cid]);row['removed']=run(['docker','inspect',cid])['exit']!=0;assert row['removed'];owned.remove(cid)
  row['hostSentinelUnchanged']=sentinel.read_text()=='unchanged';row['unrelatedHostProcessStillPresent']=pathlib.Path('/proc/'+str(hostpid)).exists();assert row['hostSentinelUnchanged'] and row['unrelatedHostProcessStillPresent'];row['status']='PASS'
 except Exception as e:row['status']='FAIL';row['error']=str(e);raise
normal="p=os.fork()\nif p==0:os._exit(0)\nos.waitpid(p,0)\n"
ready="pathlib.Path('/validation/ready.json').write_text(json.dumps({'pid':os.getpid(),'cgroup':pathlib.Path('/proc/self/cgroup').read_text()}))\n"
try:
 one('single-normal','pass')
 one('nonzero-exit','raise SystemExit(7)')
 one('parent-child-normal',normal)
 tree="for depth in range(3):\n p=os.fork()\n if p:break\nos.setsid() if os.getpid()!=1 else None\nsignal.signal(signal.SIGTERM,signal.SIG_IGN)\n"+ready+"time.sleep(30)"
 one('multilevel-setsid-sigterm-kill-escalation',tree,'stop')
 orphan="p=os.fork()\nif p==0:\n os.setsid();pathlib.Path('/validation/child.json').write_text(json.dumps({'child':os.getpid()}));time.sleep(30);os._exit(0)\nwhile not pathlib.Path('/validation/child.json').exists():time.sleep(.01)\n"+ready+"while not pathlib.Path('/validation/exit').exists():time.sleep(.01)\nos._exit(0)"
 one('parent-exit-orphan-descendant',orphan,'parent-exit')
 one('docker-kill',ready+'time.sleep(30)','kill')
 one('watchdog-timeout',ready+'time.sleep(30)','timeout')
 one('cleanup-running-container-denied',ready+'time.sleep(30)','cleanup-failure')
 fs="""results={}
for name,path in [('root','/outside'),('traversal','/validation/../outside'),('host-path',HOSTPATH)]:
 try:pathlib.Path(path).write_text('disposable');results[name]='ALLOWED'
 except OSError as e:results[name]='DENIED:'+str(e.errno)
os.symlink('/','/validation/link')
try:pathlib.Path('/validation/link/outside').write_text('disposable');results['symlink']='ALLOWED'
except OSError as e:results['symlink']='DENIED:'+str(e.errno)
pathlib.Path('/validation/replaced').mkdir();pathlib.Path('/validation/replaced').rmdir();os.symlink('/','/validation/replaced')
try:pathlib.Path('/validation/replaced/outside').write_text('disposable');results['directory-replacement']='ALLOWED'
except OSError as e:results['directory-replacement']='DENIED:'+str(e.errno)
for d in ['cache','temp','report','metadata']:
 p=pathlib.Path('/validation')/d;p.mkdir();(p/'small').write_bytes(b'x'*4096)
results['boundedBytesWritten']=16384
v=os.statvfs('/validation');results['statvfs']={'capacity':v.f_blocks*v.f_frsize,'free':v.f_bavail*v.f_frsize,'inodesFree':v.f_favail};results['device']=os.stat('/validation').st_dev
results['mountinfo']=pathlib.Path('/proc/self/mountinfo').read_text();results['status']=pathlib.Path('/proc/self/status').read_text()
assert all(results[k].startswith('DENIED:') for k in ['root','traversal','host-path','symlink','directory-replacement'])
pathlib.Path('/validation/ready.json').write_text(json.dumps(results));time.sleep(30)
""".replace('HOSTPATH',repr(str(sentinel)))
 one('filesystem-and-bounded-storage',fs,'stop')
 records.append({'case':'daemon-unreachable-client','classification':'SIMULATED_TRANSPORT_UNAVAILABLE_NOT_NATIVE_DAEMON_FAILURE','result':run(['docker','--host','unix://'+str(base/'absent.sock'),'info']),'nativeDaemonDisruption':'NOT_TESTED_PROHIBITED','status':'INCOMPLETE'})
except Exception as e:records.append({'suiteError':str(e)})
finally:
 cleanup=[]
 for cid in owned:cleanup.append(run(['docker','rm','-f',cid]))
 sentinelOk=sentinel.read_text()=='unchanged';shutil.rmtree(base)
 print(json.dumps({'host':os.uname().nodename,'uid':os.getuid(),'engine':{k:info.get(k) for k in ['ID','Name','DockerRootDir','Driver','DriverStatus','CgroupDriver','CgroupVersion','SecurityOptions','OperatingSystem','KernelVersion']},'version':version,'image':image,'baselineFlags':flags,'records':records,'cleanup':cleanup,'hostSentinelUnchanged':sentinelOk,'fixtureDirectoryRemoved':not base.exists(),'leftovers':run(['docker','ps','-a','--filter','label=purpose=trivy-docker-acceptance','--format','{{.ID}} {{.Names}}'])},indent=2))
