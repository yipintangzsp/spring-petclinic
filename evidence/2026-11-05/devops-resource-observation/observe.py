"""Six-minute? No: seven planned snapshots over ~10 minutes, hard cap 30m.
Only this evidence directory is writable. No remote files or resident agents.
"""
from pathlib import Path
import subprocess,concurrent.futures,time,json,datetime,os,re,resource
O=Path(__file__).resolve().parent
SSH=['ssh','-o','BatchMode=yes','-o','ConnectTimeout=5','-o','ServerAliveInterval=10','-o','ServerAliveCountMax=1','-o','StrictHostKeyChecking=yes','-o','HostName=192.168.64.11','-o','HostKeyAlias=192.168.1.58','zhang@192.168.1.58']
now=lambda:datetime.datetime.now(datetime.timezone.utc).isoformat()
def save(n,v):
 with(O/n).open('x')as f:json.dump(v,f,indent=2);f.write('\n')
def command(args,timeout=5):
 try:
  p=subprocess.run(args,text=True,capture_output=True,timeout=timeout);return {'exit':p.returncode,'stdout':p.stdout,'stderr':p.stderr[:500]}
 except subprocess.TimeoutExpired:return {'error':'TIMEOUT'}
def cpuSeconds(s):
 days=0
 if '-'in s:day,s=s.split('-',1);days=int(day)
 a=s.split(':');return days*86400+sum(float(v)*60**i for i,v in enumerate(reversed(a)))
def ps():
 q=command(['ps','-axo','pid=,ppid=,time=,pcpu=,rss=,comm=']);rows={}
 for line in q.get('stdout','').splitlines():
  a=line.strip().split(None,5)
  if len(a)!=6:continue
  try:rows[int(a[0])]={'pid':int(a[0]),'ppid':int(a[1]),'cpuTimeSeconds':cpuSeconds(a[2]),'psReportedCpuPercent':float(a[3]),'rssKiB':int(a[4]),'comm':a[5]}
  except ValueError:continue
 return rows
oneHostLink=False
def host():
 global oneHostLink
 start=time.monotonic();selfCpu=time.process_time();ru=resource.getrusage(resource.RUSAGE_CHILDREN);oldChild=ru.ru_utime+ru.ru_stime
 r={'classification':'CURRENT_MAC_HOST_SAMPLE_NOT_HISTORICAL','startedAt':now(),'cpuMemory':command(['sysctl','hw.ncpu','hw.memsize','vm.swapusage','kern.memorystatus_vm_pressure_level']),'vmstatBefore':command(['vm_stat'])}
 a=ps();at=time.monotonic();time.sleep(2);b=ps();elapsed=time.monotonic()-at
 records=[]
 for pid,v in b.items():
  old=a.get(pid)
  if old and old['comm']==v['comm']and old['ppid']==v['ppid']:
   v['cpuWindowSeconds']=elapsed;v['cpuCoresDuringWindow']=max(0,v['cpuTimeSeconds']-old['cpuTimeSeconds'])/elapsed;records.append(v)
 top=sorted(records,key=lambda v:v['cpuCoresDuringWindow'],reverse=True)[:20];qemu=[v for v in records if 'QEMULauncher'in v['comm']];r['processes']=top;r['qemu']=qemu
 if not oneHostLink:
  r['qemuLinkage']=[]
  for q in qemu:
   raw=command(['ps','-p',str(q['pid']),'-o','args=']).get('stdout','');uuid=re.search(r'-uuid\s+(\S+)',raw);smp=re.search(r'-smp\s+(\S+)',raw);mem=re.search(r'(?:^|\s)-m\s+(\S+)',raw)
   r['qemuLinkage'].append({'pid':q['pid'],'guestUuid':uuid.group(1)if uuid else None,'smp':smp.group(1)if smp else None,'memoryMiBArgument':mem.group(1)if mem else None,'devopsUuidMatches':bool(uuid and uuid.group(1).lower()=='4c8dedbc-d2fb-43f6-99ec-c2c6f9c1ff46')})
  oneHostLink=True
 r['vmstatAfter']=command(['vm_stat']);r['globalCpu']=command(['top','-l','2','-s','1','-n','0'],6)
 r['completedAt']=now();r['collectionWallSeconds']=time.monotonic()-start;ru=resource.getrusage(resource.RUSAGE_CHILDREN);r['collectorCpuSeconds']=time.process_time()-selfCpu+ru.ru_utime+ru.ru_stime-oldChild;r['stop']=r['collectorCpuSeconds']>1 or r['collectionWallSeconds']>15;r['stopReasons']=['HOST_SAMPLER_OVERHEAD_BUDGET']if r['stop']else[];return r
def guest():
 start=now()
 try:
  p=subprocess.run(SSH+['sudo -n python3 -'],input=(O/'guest-sample.py').read_text(),capture_output=True,text=True,timeout=25)
  if p.returncode:return {'startedAt':start,'exit':p.returncode,'error':'GUEST_COLLECTION_FAILED','stderr':p.stderr[-1000:],'stop':True,'stopReasons':['GUEST_COLLECTION_FAILED']}
  r=json.loads(p.stdout)
  if r.get('collectorCpuSeconds',0)>1 or r.get('collectionWallSeconds',0)>20:r['stop']=True;r.setdefault('stopReasons',[]).append('GUEST_SAMPLER_OVERHEAD_BUDGET')
  return r
 except Exception as e:return {'startedAt':start,'errorClass':type(e).__name__,'stop':True,'stopReasons':['GUEST_COLLECTION_UNKNOWN']}
start=time.monotonic();wall=now();offsets=[0,120,240,360,480,600];results=[];stop=[]
save('observation-plan.json',{'classification':'BOUNDED_READ_ONLY_PLAN','startedAt':wall,'plannedOffsetsSeconds':offsets,'hardMaximumSeconds':1800,'guestCommands':'proc reads, one ps leader/thread traversal, vmstat 1 3, <=4 Kubernetes GETs, one business GET per sample','hostCommands':'ps CPU deltas, vm_stat, sysctl, top -l2; never memory_pressure allocation','noHistoricalSnapshotSubstitution':True,'severeStopThresholds':{'guestLoad1PerVcpu':8,'guestCpuPsiSomeAvg10Percent':70,'memorySomeAvg10Percent':20,'ioFullAvg10Percent':30,'zeroReadyOrHttp502503':'stop','samplerCpuSecondsPerSampleMax':1},'productionMutationsAllowed':False})
for index,offset in enumerate(offsets):
 remaining=offset-(time.monotonic()-start)
 if remaining>0:time.sleep(remaining)
 if time.monotonic()-start>1770:stop=['HARD_OBSERVATION_LIMIT'];break
 with concurrent.futures.ThreadPoolExecutor(max_workers=2)as pool:
  g=pool.submit(guest);h=pool.submit(host);value={'index':index,'requestedAt':now(),'offsetSeconds':time.monotonic()-start,'guest':g.result(),'host':h.result()}
 save('sample-%02d.json'%index,value);results.append('sample-%02d.json'%index);stop=value['guest'].get('stopReasons',[])+value['host'].get('stopReasons',[])
 print(json.dumps({'index':index,'at':value['requestedAt'],'guestLoadavg':value['guest'].get('loadavgBefore'),'guestThreadStates':value['guest'].get('threads',{}).get('stateCounts'),'guestCollectorCpuSeconds':value['guest'].get('collectorCpuSeconds'),'ready':value['guest'].get('readyPetclinicCount'),'http':value['guest'].get('http',{}).get('status'),'stop':stop}),flush=True)
 if stop:break
save('observation-receipt.json',{'classification':'REAL_BOUNDED_CURRENT_OBSERVATION_NOT_INCIDENT_PROCESS_HISTORY','startedAt':wall,'completedAt':now(),'actualDurationSeconds':time.monotonic()-start,'samples':results,'sampleCount':len(results),'stoppedEarly':bool(stop),'stopReasons':stop,'productionMutations':0,'remoteFilesCreated':0,'newDaemonOrAgent':False,'securityScans':0,'release':0,'rollout':0});print('OBSERVATION_CLOSED',flush=True)
