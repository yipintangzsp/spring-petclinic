"""Finite local pair supervisor for offline tests, not a production SSH launcher.
Audited collectors never fork. Kill/reap only the exact child PIDs created here;
no global kill, no process-group claim, no arbitrary descendant guarantee.
"""
import json,os,selectors,signal,subprocess,sys,time
from sampler import stamp
from contract import BUDGET

def run_local_pair(commands,timeout=None,output_cap=None):
 if set(commands)!={'host','guest'}:raise ValueError('TWO_INDEPENDENT_WORKERS_REQUIRED')
 timeout=BUDGET['transportWallSeconds']if timeout is None else timeout;cap=BUDGET['perStreamBytes']if output_cap is None else output_cap
 if not 0<timeout<=BUDGET['transportWallSeconds']or not 128<=cap<=BUDGET['perStreamBytes']:raise ValueError('SUPERVISOR_LIMIT')
 # Explicitly forbid network transports in this OFFLINE PREPARATION implementation.
 if any(not c or c[0]!=sys.executable for c in commands.values()):raise ValueError('OFFLINE_PYTHON_ONLY_NO_SSH')
 begin=time.monotonic();cpu=time.process_time();sel=selectors.DefaultSelector();workers={};failure=None
 def stop(w,reason):
  if w.get('reaped')or w.get('stopAt')is not None:return
  w['reason']=reason;w['stopAt']=time.monotonic()
  try:w['p'].terminate()
  except ProcessLookupError:pass
 try:
  for label,cmd in commands.items():
   t=time.monotonic();sent=stamp()
   try:p=subprocess.Popen(cmd,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,close_fds=True)
   except OSError:failure='SPAWN_FAILED';break
   w={'p':p,'sent':sent,'spawnWallSeconds':time.monotonic()-t,'start':t,'buffers':{'out':bytearray(),'err':bytearray()},'stopAt':None,'reaped':False};workers[label]=w
   for kind,stream in [('out',p.stdout),('err',p.stderr)]:
    os.set_blocking(stream.fileno(),False);sel.register(stream,selectors.EVENT_READ,(label,kind))
  while not all(w['reaped']for w in workers.values())or sel.get_map():
   now=time.monotonic()
   for w in workers.values():
    if not w['reaped']:
     pid,status,usage=os.wait4(w['p'].pid,os.WNOHANG)
     if pid:
      w.update({'reaped':True,'received':stamp(),'exit':os.waitstatus_to_exitcode(status),'usage':usage});w['p'].returncode=w['exit']
      if w['exit']!=0:failure=failure or 'WORKER_NONZERO'
     elif now-w['start']>=timeout:failure=failure or 'WORKER_TIMEOUT';stop(w,'WORKER_TIMEOUT')
     if w.get('stopAt')is not None and not w['reaped']and now-w['stopAt']>=BUDGET['terminateGraceSeconds']:
      try:w['p'].kill()
      except ProcessLookupError:pass
   if failure:
    for w in workers.values():stop(w,'PEER_FAILED')
   for key,_ in sel.select(.01):
    label,kind=key.data;w=workers[label];chunk=os.read(key.fileobj.fileno(),4096)
    if not chunk:sel.unregister(key.fileobj);key.fileobj.close();continue
    allowed=cap if kind=='out'else 2048;buf=w['buffers'][kind]
    if len(buf)+len(chunk)>allowed:failure=failure or 'OUTPUT_LIMIT';stop(w,'OUTPUT_LIMIT');chunk=chunk[:max(0,allowed-len(buf))]
    buf.extend(chunk)
   if time.monotonic()-begin>timeout+BUDGET['terminateGraceSeconds']+BUDGET['reapDeadlineSeconds']:
    failure=failure or 'CLEANUP_DEADLINE';break
 finally:
  # No retry. Even a spawn/parse error cannot leave an owned local worker running.
  for w in workers.values():
   if not w['reaped']:
    try:w['p'].kill()
    except ProcessLookupError:pass
    deadline=time.monotonic()+BUDGET['reapDeadlineSeconds']
    while time.monotonic()<deadline:
     pid,status,usage=os.wait4(w['p'].pid,os.WNOHANG)
     if pid:w.update({'reaped':True,'received':stamp(),'exit':os.waitstatus_to_exitcode(status),'usage':usage});w['p'].returncode=w['exit'];break
     time.sleep(.01)
    if not w['reaped']:failure='UNREAPED_CHILD'
   for stream in [w['p'].stdout,w['p'].stderr]:stream.close()
  sel.close()
 results={}
 for label,w in workers.items():
  u=w.get('usage');cpu_seconds=u.ru_utime+u.ru_stime if u else None;rss=u.ru_maxrss*(1 if sys.platform=='darwin'else 1024)if u else None
  r={'pid':w['p'].pid,'reaped':w['reaped'],'exit':w.get('exit'),'hostSent':w['sent'],'hostReceived':w.get('received'),'spawnWallSeconds':w['spawnWallSeconds'],'wallSeconds':time.monotonic()-w['start'],'cpuSeconds':cpu_seconds,'maxRssBytes':rss,'stdoutBytes':len(w['buffers']['out']),'stderrBytes':len(w['buffers']['err']),'stopReason':w.get('reason'),'externalCommands':1,'descendantsExpected':0}
  if cpu_seconds is None or cpu_seconds>BUDGET['workerCpuSeconds']or rss is None or rss>BUDGET['workerRssBytes']:failure=failure or 'WORKER_RESOURCE_BUDGET'
  try:
   r['record']=json.loads(w['buffers']['out'])
   if not isinstance(r['record'],dict)or r['record'].get('status')!='OK':failure=failure or 'WORKER_STATUS_INVALID'
  except (ValueError,UnicodeError):failure=failure or 'INVALID_WORKER_OUTPUT'
  # Never save stderr/argv or print an uncontrolled exception payload.
  results[label]=r
 return {'status':'PASS'if failure is None else 'FAIL','failure':failure,'workers':results,'supervisorWallSeconds':time.monotonic()-begin,'supervisorCpuSeconds':time.process_time()-cpu,'cleanupVerified':all(w['reaped']for w in workers.values()),'networkExecutionEnabled':False,'retryCount':0}
