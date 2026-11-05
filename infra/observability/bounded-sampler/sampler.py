#!/usr/bin/env python3
"""Finite read-only collector. No subprocess, socket, PID discovery or Kubernetes API.
Darwin native APIs are read-only; Linux fixture results are explicitly synthetic.
"""
import argparse,ctypes,datetime,errno,json,math,os,platform,re,resource,signal,stat,sys,time
MAX_PIDS=8;FILE_CAP=16384;OUTPUT_CAP=32768;WALL_LIMIT=2.5;CPU_LIMIT=.25;RSS_LIMIT=64*1024*1024
class SampleError(Exception):
 def __init__(self,code):self.code=code

def stamp():
 n=time.time_ns();return {'utcNs':n,'utc':datetime.datetime.fromtimestamp(n/1e9,datetime.timezone.utc).isoformat(timespec='milliseconds'),'timezoneOffsetSeconds':0,'localTimezoneOffsetSeconds':int(datetime.datetime.now().astimezone().utcoffset().total_seconds()),'monotonicNs':time.monotonic_ns()}
def finite(v):
 x=float(v)
 if not math.isfinite(x)or x<0:raise SampleError('METRIC_PARSE_ERROR')
 return x

def pid_list(raw):
 if raw=='self':return [os.getpid()]
 if not raw:return []
 parts=raw.split(',')
 if len(parts)>MAX_PIDS or any(not re.fullmatch(r'[1-9][0-9]{0,9}',p)or int(p)>2147483647 for p in parts):raise SampleError('PID_LIMIT_OR_FORMAT')
 out=list(map(int,parts))
 if len(out)!=len(set(out)):raise SampleError('PID_DUPLICATE')
 return out

def os_error(e):
 return 'PERMISSION_DENIED'if e.errno in (errno.EACCES,errno.EPERM)else 'METRIC_MISSING'if e.errno in(errno.ENOENT,errno.ESRCH)else 'READ_ERROR'

class LinuxProc:
 def __init__(self,root='/proc'):
  self.root=os.path.abspath(root)
  if os.path.realpath(self.root)!=self.root:raise SampleError('PROC_ROOT_SYMLINK')
  self.hz=os.sysconf('SC_CLK_TCK');self.page=os.sysconf('SC_PAGE_SIZE')
 def read(self,name):
  # O_NOFOLLOW on every directory and file; never enumerate /proc or follow links.
  parts=name.split('/');fds=[]
  if any(not re.fullmatch(r'[A-Za-z0-9_-]+',s)for s in parts):raise SampleError('PROC_PATH_INVALID')
  try:
   d=os.open(self.root,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW);fds.append(d)
   for part in parts[:-1]:d=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=d);fds.append(d)
   f=os.open(parts[-1],os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=d);fds.append(f)
   if not stat.S_ISREG(os.fstat(f).st_mode):raise SampleError('NON_REGULAR_METRIC')
   # One capped read; fail on excess instead of truncating facts to success.
   b=os.read(f,FILE_CAP+1)
   if len(b)>FILE_CAP:raise SampleError('METRIC_SIZE_LIMIT')
   return b.decode('ascii')
  except OSError as e:raise SampleError(os_error(e))from None
  except UnicodeError:raise SampleError('METRIC_PARSE_ERROR')from None
  finally:
   for f in reversed(fds):os.close(f)
 def system(self):
  try:
   load=self.read('loadavg').split()
   if len(load)<4:raise ValueError()
   loads=[finite(v)for v in load[:3]];queue=[int(v)for v in load[3].split('/')]
   if len(queue)!=2 or min(queue)<0:raise ValueError()
   lines={v.split()[0]:v.split()[1:]for v in self.read('stat').splitlines()if v.split()}
   cpu=[int(v)for v in lines['cpu']];running=int(lines['procs_running'][0]);blocked=int(lines['procs_blocked'][0])
   if len(cpu)<4 or min(cpu+[running,blocked])<0:raise ValueError()
   pressure={}
   for kind in ['cpu','memory','io']:
    rows={}
    for line in self.read('pressure/'+kind).splitlines():
     a=line.split();values=dict(p.split('=')for p in a[1:]);row={k:finite(values[k])for k in ['avg10','avg60','avg300']};row['totalUs']=int(values['total'])
     if any(row[k]>100 for k in ['avg10','avg60','avg300'])or row['totalUs']<0:raise ValueError()
     rows[a[0]]=row
    if 'some'not in rows or kind!='cpu'and 'full'not in rows:raise ValueError()
    pressure[kind]=rows
   m={a:int(b.split()[0])*1024 for a,b in(line.split(':',1)for line in self.read('meminfo').splitlines())if a in ['MemTotal','MemAvailable','SwapTotal','SwapFree']}
   if set(m)!={'MemTotal','MemAvailable','SwapTotal','SwapFree'}or min(m.values())<0:raise ValueError()
   if m['MemAvailable']>m['MemTotal']or m['SwapFree']>m['SwapTotal']:raise ValueError()
   count=sum(bool(re.fullmatch(r'cpu[0-9]+',v))for v in lines)
   if count<1:raise ValueError()
   return {'loadavg':loads,'loadavgQueue':queue,'cpuTicks':cpu,'cpuCount':count,'runnable':running,'ioBlocked':blocked,'pressure':pressure,'memoryBytes':m}
  except (ValueError,KeyError,IndexError):raise SampleError('METRIC_PARSE_ERROR')from None
 def process(self,pid):
  try:
   raw=self.read(str(pid)+'/stat');a=raw[raw.rfind(')')+2:].split()
   if int(raw.split(' ',1)[0])!=pid:raise ValueError()
   cg=self.read(str(pid)+'/cgroup');uid=re.search(r'pod([a-f0-9_-]{36})(?:[./]|$)',cg)
   return {'pid':pid,'identity':int(a[19]),'cpuSeconds':(int(a[11])+int(a[12]))/self.hz,'rssBytes':int(a[21])*self.page,'state':a[0],'podUid':uid.group(1).replace('_','-')if uid else None}
  except SampleError as e:
   if e.code=='METRIC_MISSING':raise SampleError('PID_DISAPPEARED')from None
   raise
  except (ValueError,IndexError):raise SampleError('PROCESS_PARSE_ERROR')from None

class RUsageV2(ctypes.Structure):
 _fields_=[('uuid',ctypes.c_uint8*16)]+[(n,ctypes.c_uint64)for n in ['user','system','pkg','interrupt','pageins','wired','resident','footprint','start','exit','childUser','childSystem','childPkg','childInterrupt','childPageins','childElapsed','diskRead','diskWrite']]
class DarwinNative:
 def __init__(self):
  if sys.platform!='darwin':raise SampleError('HOST_OS_UNSUPPORTED')
  self.lib=ctypes.CDLL('/usr/lib/libSystem.B.dylib',use_errno=True);self.proc=ctypes.CDLL('/usr/lib/libproc.dylib',use_errno=True)
  self.lib.mach_host_self.restype=ctypes.c_uint;self.lib.host_statistics.argtypes=[ctypes.c_uint,ctypes.c_int,ctypes.POINTER(ctypes.c_int),ctypes.POINTER(ctypes.c_uint)]
  self.lib.mach_port_deallocate.argtypes=[ctypes.c_uint,ctypes.c_uint]
  self.lib.host_processor_info.argtypes=[ctypes.c_uint,ctypes.c_int,ctypes.POINTER(ctypes.c_uint),ctypes.POINTER(ctypes.POINTER(ctypes.c_int)),ctypes.POINTER(ctypes.c_uint)]
  self.lib.vm_deallocate.argtypes=[ctypes.c_uint,ctypes.c_uint64,ctypes.c_uint64]
  self.lib.sysctlbyname.argtypes=[ctypes.c_char_p,ctypes.c_void_p,ctypes.POINTER(ctypes.c_size_t),ctypes.c_void_p,ctypes.c_size_t]
  self.proc.proc_pid_rusage.argtypes=[ctypes.c_int,ctypes.c_int,ctypes.c_void_p]
  self.proc.proc_pidpath.argtypes=[ctypes.c_int,ctypes.c_void_p,ctypes.c_uint]
 def sysctl(self,name,typ):
  value=typ();size=ctypes.c_size_t(ctypes.sizeof(value))
  if self.lib.sysctlbyname(name.encode(),ctypes.byref(value),ctypes.byref(size),None,0)!=0:raise SampleError(os_error(OSError(ctypes.get_errno(),'')))
  if size.value!=ctypes.sizeof(value):raise SampleError('NATIVE_ABI_SIZE')
  return value.value
 def system(self):
  port=self.lib.mach_host_self();cpu_count=ctypes.c_uint();values=ctypes.POINTER(ctypes.c_int)();count=ctypes.c_uint();per_cpu=[]
  vm=(ctypes.c_int*15)();vmcount=ctypes.c_uint(15)
  try:
   if self.lib.host_processor_info(port,2,ctypes.byref(cpu_count),ctypes.byref(values),ctypes.byref(count))!=0:raise SampleError('HOST_CPU_READ_FAILED')
   if not 1<=cpu_count.value<=128 or count.value!=cpu_count.value*4:raise SampleError('HOST_CPU_TOPOLOGY_LIMIT')
   per_cpu=[values[i]&0xffffffff for i in range(count.value)]
   if self.lib.host_statistics(port,2,vm,ctypes.byref(vmcount))!=0 or vmcount.value!=15:raise SampleError('HOST_MEMORY_READ_FAILED')
  finally:
   task=ctypes.c_uint.in_dll(self.lib,'mach_task_self_').value
   if values:self.lib.vm_deallocate(task,ctypes.cast(values,ctypes.c_void_p).value,count.value*ctypes.sizeof(ctypes.c_int))
   self.lib.mach_port_deallocate(task,port)
  return {'cpuTicks':[sum(per_cpu[k::4])for k in range(4)],'perCpuTicks':per_cpu,'cpuTickSource':'host_processor_info/PROCESSOR_CPU_LOAD_INFO','cpuCount':cpu_count.value,'memoryBytes':self.sysctl('hw.memsize',ctypes.c_uint64),'memoryPressureLevelRaw':self.sysctl('kern.memorystatus_vm_pressure_level',ctypes.c_uint32),'memoryPressureInterpretation':'RAW_OS_ENUM_NOT_GUEST_PSI','hostLoadavg':list(os.getloadavg()),'freeBytes':(vm[0]&0xffffffff)*os.sysconf('SC_PAGE_SIZE'),'inactiveBytes':(vm[2]&0xffffffff)*os.sysconf('SC_PAGE_SIZE')}
 def process(self,pid):
  v=RUsageV2()
  if self.proc.proc_pid_rusage(pid,2,ctypes.byref(v))!=0:raise SampleError('PID_DISAPPEARED'if ctypes.get_errno()in(errno.ESRCH,errno.ENOENT)else 'PERMISSION_DENIED'if ctypes.get_errno()in(errno.EPERM,errno.EACCES)else 'PROCESS_READ_ERROR')
  path=ctypes.create_string_buffer(4096)
  if self.proc.proc_pidpath(pid,path,4096)<=0:raise SampleError('PROCESS_IDENTITY_UNAVAILABLE')
  # Never export paths, argv, environ, command names or user names.
  category='QEMU'if os.path.basename(os.fsdecode(path.value))in ['QEMULauncher','qemu-system-aarch64','qemu-system-x86_64']else 'SELECTED_PROCESS'
  return {'pid':pid,'identity':v.start,'cpuSeconds':(v.user+v.system)/1e9,'rssBytes':v.resident,'category':category}

def pressure_stops(s):
 if 'hostLoadavg'in s:
  return (["HOST_LOAD_GE_2_PER_CPU"]if s['hostLoadavg'][0]>=2*s['cpuCount']else[])+(["HOST_MEMORY_HEADROOM"]if s['freeBytes']+s['inactiveBytes']<512*1024*1024 else[])
 if 'loadavg'not in s:return []
 out=[]
 for yes,reason in [(s['loadavg'][0]>=8*s['cpuCount'],'LOAD1_GE_8_PER_VCPU'),(s['pressure']['cpu']['some']['avg10']>=70,'CPU_SOME_AVG10_GE_70'),(s['pressure']['memory']['some']['avg10']>=20,'MEMORY_SOME_AVG10_GE_20'),(s['pressure']['io']['full']['avg10']>=30,'IO_FULL_AVG10_GE_30')]:
  if yes:out.append(reason)
 return out

def collect(backend,pids,window=.2):
 if len(pids)>MAX_PIDS or not 0<window<=.25:raise SampleError('CONFIG_LIMIT')
 a=backend.system();stop=pressure_stops(a)
 if stop:return {'status':'STOP_PRESSURE','systemBefore':a,'stopReasons':stop,'processReads':0},30
 def measured_process(p):
  begin=time.monotonic_ns();value=backend.process(p);end=time.monotonic_ns();value['cpuReadWindowMonoNs']=[begin,end];return value
 first={p:measured_process(p)for p in pids};time.sleep(window);b=backend.system();out=[]
 for p in pids:
  last=measured_process(p);initial=first[p]
  if last['identity']!=initial['identity']:raise SampleError('PID_REUSED')
  delta=last['cpuSeconds']-initial['cpuSeconds']
  if delta<0:raise SampleError('PROCESS_COUNTER_RESET')
  seconds=(sum(last['cpuReadWindowMonoNs'])-sum(initial['cpuReadWindowMonoNs']))/2e9
  if seconds<=0:raise SampleError('PROCESS_CLOCK_ORDER')
  out.append({**last,'cpuCores':delta/seconds,'cpuWindowSeconds':seconds,'initialCpuReadWindowMonoNs':initial['cpuReadWindowMonoNs']})
 stop=pressure_stops(b);result={'status':'STOP_PRESSURE'if stop else 'OK','systemBefore':a,'systemAfter':b,'processes':out,'stopReasons':stop,'processReads':len(pids)*2,'selectedPidScopeOnly':True}
 if isinstance(backend,DarwinNative):
  if a['cpuCount']!=b['cpuCount']:raise SampleError('HOST_CPU_TOPOLOGY_CHANGED')
  flat=[(y-x)&0xffffffff for x,y in zip(a['perCpuTicks'],b['perCpuTicks'])];d=[sum(flat[k::4])for k in range(4)];total=sum(d)
  if total<=0:raise SampleError('CPU_WINDOW_EMPTY')
  result['hostCpuFractions']={name:v/total for name,v in zip(['user','system','idle','nice'],d)}
 return result,30 if stop else 0

def encode(obj,cap=OUTPUT_CAP):
 data=(json.dumps(obj,separators=(',',':'),allow_nan=False)+'\n').encode()
 if len(data)>cap:raise SampleError('OUTPUT_LIMIT')
 return data

def cli():
 parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--role',choices=['guest','host'],required=True);parser.add_argument('--pids',default='');parser.add_argument('--source-id',default='unspecified');parser.add_argument('--offline-fixture');parser.add_argument('--window',type=float,default=.2);parser.add_argument('--clock-only',action='store_true');args=parser.parse_args()
 begin=stamp();cpu=time.process_time();out={'schemaVersion':1,'sourceId':'REJECTED','started':begin,'clockSyncStatus':'UNKNOWN','externalCommands':0,'subprocesses':0,'rootRequired':False,'clockStepToleranceNs':20000000,'role':args.role,'executionEnvironment':{'os':platform.system(),'release':platform.release(),'arch':platform.machine()},'classification':'SYNTHETIC_PROC_FIXTURE_REAL_EXECUTION'if args.offline_fixture else 'NATIVE_READ_ONLY_'+platform.system().upper()}
 def alarm(sig,frame):raise SampleError('TASK_TIMEOUT')
 signal.signal(signal.SIGALRM,alarm);signal.setitimer(signal.ITIMER_REAL,WALL_LIMIT)
 code=20
 try:
  if not re.fullmatch(r'[A-Za-z0-9_-]{1,40}',args.source_id):raise SampleError('SOURCE_ID_INVALID')
  out['sourceId']=args.source_id;pids=pid_list(args.pids)
  if args.role=='host'and args.offline_fixture:raise SampleError('FIXTURE_ROLE_INVALID')
  if args.role=='guest'and not args.offline_fixture and sys.platform!='linux':raise SampleError('GUEST_OS_UNSUPPORTED')
  if args.clock_only:
   facts,code={'status':'OK','clockOnly':True,'metricReads':0,'clockResolutionSeconds':{'realtime':time.get_clock_info('time').resolution,'monotonic':time.get_clock_info('monotonic').resolution}},0
  else:
   backend=DarwinNative()if args.role=='host'else LinuxProc(args.offline_fixture or'/proc')
   facts,code=collect(backend,pids,args.window)
  out.update(facts)
 except SampleError as e:out.update({'status':'ERROR','error':e.code});code=21 if e.code=='TASK_TIMEOUT'else 20
 except Exception:out.update({'status':'ERROR','error':'UNEXPECTED_COLLECTOR_ERROR'});code=20
 finally:signal.setitimer(signal.ITIMER_REAL,0)
 out['completed']=stamp();elapsed=(out['completed']['monotonicNs']-begin['monotonicNs'])/1e9;usage=resource.getrusage(resource.RUSAGE_SELF);rss=usage.ru_maxrss*(1 if sys.platform=='darwin'else 1024)
 out['measurement']={'wallSeconds':elapsed,'collectorCpuDeltaSeconds':time.process_time()-cpu,'processLifetimeCpuSeconds':usage.ru_utime+usage.ru_stime,'maxRssBytes':rss,'pidCap':MAX_PIDS,'fileReadCapBytes':FILE_CAP,'outputCapBytes':OUTPUT_CAP}
 if abs((out['completed']['utcNs']-begin['utcNs'])-(out['completed']['monotonicNs']-begin['monotonicNs']))>20000000:out.update({'status':'ERROR','error':'LOCAL_CLOCK_STEP'});code=20
 if usage.ru_utime+usage.ru_stime>CPU_LIMIT or rss>RSS_LIMIT:out.update({'status':'ERROR','error':'SELF_BUDGET_EXCEEDED'});code=22
 try:payload=encode(out)
 except SampleError:payload=b'{"status":"ERROR","error":"OUTPUT_LIMIT"}\n';code=23
 try:sys.stdout.buffer.write(payload);sys.stdout.buffer.flush()
 except BrokenPipeError:return 24
 return code
if __name__=='__main__':raise SystemExit(cli())
