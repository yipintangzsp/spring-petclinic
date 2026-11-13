import os,pathlib,json,time,shutil,resource,datetime,fcntl
r=pathlib.Path('/var/tmp/security-manager-gitleaks-recovery-20261107');start=datetime.datetime.now(datetime.timezone.utc).isoformat();mem=int(next(l.split()[1]for l in pathlib.Path('/proc/meminfo').read_text().splitlines()if l.startswith('MemAvailable:')))*1024
def ticks():return list(map(int,pathlib.Path('/proc/stat').read_text().splitlines()[0].split()[1:9]))
a=ticks();t=time.monotonic();time.sleep(.25);b=ticks();elapsed=time.monotonic()-t;d=[y-x for x,y in zip(a,b)];busy=100*(1-(d[3]+d[4])/sum(d))if sum(d)>0 else 100
v=os.statvfs(r);free=shutil.disk_usage(r).free;conditions={'memAvailable':mem<1073741824,'diskAvailable':free<1073741824,'cpuBusy':busy>75}
cgroup=pathlib.Path('/proc/self/cgroup').read_text();cg={}
for row in cgroup.splitlines():
 if row.startswith('0::'):
  domain=pathlib.Path('/sys/fs/cgroup')/row.split('::',1)[1].lstrip('/')
  for parent in [domain,*domain.parents]:
   if not parent.is_relative_to('/sys/fs/cgroup'):continue
   vals={}
   for name in ['memory.max','memory.current','cpu.max','cpuset.cpus.effective','pids.max','pids.current']:
    p=parent/name
    if p.is_file():vals[name]=p.read_text().strip()
   if vals:cg[str(parent)]=vals
lock={'exists':(r/'outputs/execution.lock').exists(),'held':None}
if lock['exists']:
 f=open(r/'outputs/execution.lock','r')
 try:fcntl.flock(f,fcntl.LOCK_EX|fcntl.LOCK_NB);lock['held']=False;fcntl.flock(f,fcntl.LOCK_UN)
 except BlockingIOError:lock['held']=True
 f.close()
out={'startedAt':start,'completedAt':datetime.datetime.now(datetime.timezone.utc).isoformat(),'host':os.uname().nodename,'uid':os.getuid(),'gid':os.getgid(),'groups':os.getgroups(),'thresholds':{'memBytesMin':1073741824,'diskBytesMin':1073741824,'cpuBusyPctMax':75},'observed':{'memAvailableBytes':mem,'diskAvailableBytes':free,'statvfsAvailableBytes':v.f_bavail*v.f_frsize,'availableInodes':v.f_favail,'cpuBusyPct':busy,'cpuTicksBefore':a,'cpuTicksAfter':b,'sampleSeconds':elapsed,'loadAverage':os.getloadavg()},'blockedConditions':conditions,'preflight':'BLOCKED'if any(conditions.values())else'PASS','actualSources':['/proc/meminfo:MemAvailable_kB*1024','statvfs(directory).f_bavail*f_frsize','/proc/stat aggregate first8; idle+iowait; 250ms'],'notUsedByExistingGuard':['loadAverage','inodes','cgroup limits','filesystem quota','process count'],'cgroup':cgroup,'cgroupHierarchy':cg,'lock':lock,'rlimits':{n:list(resource.getrlimit(getattr(resource,n)))for n in ['RLIMIT_AS','RLIMIT_CPU','RLIMIT_NPROC','RLIMIT_NOFILE','RLIMIT_FSIZE']},'scannerStarted':False,'newRun':False}
print(json.dumps(out))
