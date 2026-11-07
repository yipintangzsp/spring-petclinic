"""Shared bounded admission probe. No scanner, credentials, process control or writes."""
import pathlib,os,time,json,shutil,datetime
THRESHOLDS={'memBytesMin':1073741824,'diskBytesMin':1073741824,'cpuBusyPctMax':75}
def decide(mem,disk,busy):
 if not isinstance(mem,int)or not isinstance(disk,int)or mem<0 or disk<0 or not isinstance(busy,(int,float))or not 0<=busy<=100:raise ValueError('RESOURCE_STATE_UNKNOWN_BLOCKED')
 return {'memAvailable':mem<THRESHOLDS['memBytesMin'],'diskAvailable':disk<THRESHOLDS['diskBytesMin'],'cpuBusy':busy>THRESHOLDS['cpuBusyPctMax']}
def probe(directory):
 start=datetime.datetime.now(datetime.timezone.utc).isoformat();mem=int(next(l.split()[1]for l in pathlib.Path('/proc/meminfo').read_text().splitlines()if l.startswith('MemAvailable:')))*1024
 def ticks():return list(map(int,pathlib.Path('/proc/stat').read_text().splitlines()[0].split()[1:9]))
 a=ticks();t=time.monotonic();time.sleep(.25);b=ticks();elapsed=time.monotonic()-t;d=[y-x for x,y in zip(a,b)];total=sum(d)
 if any(v<0 for v in d)or total<=0:raise ValueError('RESOURCE_STATE_UNKNOWN_BLOCKED')
 busy=100*(1-(d[3]+d[4])/total);disk=shutil.disk_usage(directory).free;blocked=decide(mem,disk,busy);stat=os.statvfs(directory)
 return {'schemaVersion':1,'kind':'ResourceBudgetObservation','host':os.uname().nodename,'uid':os.getuid(),'gid':os.getgid(),'groups':os.getgroups(),'cgroup':pathlib.Path('/proc/self/cgroup').read_text().strip(),'startedAt':start,'completedAt':datetime.datetime.now(datetime.timezone.utc).isoformat(),'thresholds':THRESHOLDS,'observed':{'memAvailableBytes':mem,'diskAvailableBytes':disk,'availableInodes':stat.f_favail,'cpuBusyPct':busy,'cpuTicksBefore':a,'cpuTicksAfter':b,'sampleSeconds':elapsed},'blockedConditions':blocked,'preflight':'BLOCKED'if any(blocked.values())else'PASS','sources':{'memory':'/proc/meminfo MemAvailable kB * 1024','disk':'statvfs f_bavail * f_frsize via shutil.disk_usage','cpu':'/proc/stat first8 counters; idle+iowait;250ms'},'scannerStarted':False,'newRun':False}
