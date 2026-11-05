"""One finite Linux snapshot. Read-only, no installation, no remote files."""
import os,time,json,datetime,subprocess,re,resource,urllib.request,urllib.error
now=lambda:datetime.datetime.now(datetime.timezone.utc).isoformat();started=time.monotonic();r={'classification':'CURRENT_LINUX_GUEST_SAMPLE_NOT_HISTORICAL','startedAt':now(),'collectorPid':os.getpid(),'productionMutations':0,'errors':[]}
def read(p):
 try:return open(p).read()
 except (OSError,PermissionError):return None
def pressure():return {k:read('/proc/pressure/'+k)for k in ['cpu','memory','io']}
def stat():
 s=read('/proc/stat')or'';return {'cpu':[int(x)for x in s.splitlines()[0].split()[1:]],'procs_running':int(re.search(r'^procs_running (\d+)',s,re.M).group(1)),'procs_blocked':int(re.search(r'^procs_blocked (\d+)',s,re.M).group(1))}
def pavg(raw,kind='some'):
 m=re.search(r'^'+kind+r' avg10=([0-9.]+)',raw or'',re.M);return float(m.group(1))if m else None
r['loadavgBefore']=read('/proc/loadavg');r['pressureBefore']=pressure();r['kernelBefore']=stat();r['cpuCount']=os.cpu_count();r['meminfo']=read('/proc/meminfo');r['bootId']=read('/proc/sys/kernel/random/boot_id');r['uptime']=read('/proc/uptime')
load=float(r['loadavgBefore'].split()[0]);cpu=pavg(r['pressureBefore']['cpu']);mem=pavg(r['pressureBefore']['memory']);io=pavg(r['pressureBefore']['io'],'full');severity=[]
if load>=8*r['cpuCount']:severity.append('LOAD1_GE_8_PER_VCPU')
if cpu is not None and cpu>=70:severity.append('CPU_SOME_AVG10_GE_70')
if mem is not None and mem>=20:severity.append('MEMORY_SOME_AVG10_GE_20')
if io is not None and io>=30:severity.append('IO_FULL_AVG10_GE_30')
# Severe pressure: stop before ps/vmstat/Kubernetes/HTTP, retain only cheap proc reads.
if severity:r.update({'stop':True,'stopReasons':severity,'abbreviatedBeforeExpensiveCollection':True,'completedAt':now(),'collectionWallSeconds':time.monotonic()-started});print(json.dumps(r));raise SystemExit(0)
def command(args,timeout=5):
 try:
  p=subprocess.run(args,capture_output=True,text=True,timeout=timeout);return {'exit':p.returncode,'stdout':p.stdout,'stderr':p.stderr[:500]}
 except subprocess.TimeoutExpired:return {'error':'TIMEOUT'}
ps=command(['ps','-eo','pid=,ppid=,stat=,pcpu=,pmem=,comm=']);leaders=[]
for line in ps.get('stdout','').splitlines():
 a=line.strip().split(None,5)
 if len(a)==6:leaders.append({'pid':int(a[0]),'ppid':int(a[1]),'state':a[2],'psLifetimeCpuPercent':float(a[3]),'psMemoryPercent':float(a[4]),'comm':a[5]})
selected=sorted(leaders,key=lambda p:p['psLifetimeCpuPercent'],reverse=True)[:25]
for p in leaders:
 if p['comm']in['k3s','containerd','dockerd','java']and p['pid']not in{x['pid']for x in selected}and len(selected)<40:selected.append(p)
thread=command(['ps','-eLo','pid=,tid=,ppid=,stat=,wchan:32=,comm=']);states={};rd=[]
for line in thread.get('stdout','').splitlines():
 a=line.strip().split(None,5)
 if len(a)!=6:continue
 state=a[3][:1];states[state]=states.get(state,0)+1
 if state in['R','D']and len(rd)<30:rd.append({'pid':int(a[0]),'tid':int(a[1]),'ppid':int(a[2]),'state':a[3],'wchan':a[4],'comm':a[5]})
r['threads']={'commandExit':thread.get('exit'),'stateCounts':states,'runnableOrDExamples':rd,'examplesLimit':30,'countsScope':'all visible threads, one finite ps traversal'}
def pidstat(pid):
 raw=read('/proc/'+str(pid)+'/stat')
 if not raw:return None
 a=raw[raw.rfind(')')+2:].split();return {'ticks':int(a[11])+int(a[12]),'startTicks':int(a[19])}
first={p['pid']:pidstat(p['pid'])for p in selected};t=time.monotonic();r['vmstat']=command(['vmstat','1','3'],5);elapsed=time.monotonic()-t
for p in selected:
 pid=p['pid'];a=first[pid];b=pidstat(pid);p['cpuWindowSeconds']=elapsed;p['cpuCoresDuringWindow']=(b['ticks']-a['ticks'])/os.sysconf('SC_CLK_TCK')/elapsed if a and b and a['startTicks']==b['startTicks']else None
 cg=read('/proc/'+str(pid)+'/cgroup');p['cgroup']=cg[:1500]if cg else None
 uid=re.search(r'pod([0-9a-f_-]{36})',cg or'');p['podUidFromCgroup']=uid.group(1).replace('_','-')if uid else None
r['processes']=sorted(selected,key=lambda p:p['cpuCoresDuringWindow'] or 0,reverse=True);r['pressureAfter']=pressure();r['kernelAfter']=stat();r['loadavgAfter']=read('/proc/loadavg');r['procWindowMeaning']='interval CPU from PID/starttime-validated tick delta; psLifetimeCpuPercent is NOT interval CPU; vmstat first row since boot'
def get(p):
 try:
  b=subprocess.check_output(['kubectl','--request-timeout=3s','get','--raw',p],stderr=subprocess.PIPE,text=True,timeout=5);return json.loads(b)
 except Exception as e:r['errors'].append({'path':p,'errorClass':type(e).__name__});return None
nodes=get('/api/v1/nodes');r['nodes']=[{'name':n['metadata']['name'],'conditions':n['status']['conditions'],'capacity':n['status']['capacity']}for n in(nodes or{}).get('items',[])]
if any(n['name']=='devops'and any(c['type']=='Ready'and c['status']!='True'for c in n['conditions'])for n in r['nodes']):severity.append('DEVOPS_NODE_NOT_READY')
pods=get('/api/v1/namespaces/petclinic/pods');r['petclinicPods']=[{'name':p['metadata']['name'],'uid':p['metadata']['uid'],'node':p['spec'].get('nodeName'),'phase':p['status'].get('phase'),'conditions':p['status'].get('conditions'),'containers':[{'name':c['name'],'image':c['image'],'resources':c.get('resources')}for c in p['spec']['containers']],'containerStatuses':[{'name':s['name'],'ready':s['ready'],'restartCount':s['restartCount'],'state':{k:{a:v.get(a)for a in['reason','exitCode','startedAt','finishedAt']}for k,v in s['state'].items()}}for s in p['status'].get('containerStatuses',[])]}for p in(pods or{}).get('items',[])if p['metadata'].get('labels',{}).get('app')=='petclinic']
ready=sum(any(c['type']=='Ready'and c['status']=='True'for c in p['conditions']or[])for p in r['petclinicPods']);r['readyPetclinicCount']=ready if pods else None
if pods and ready==0:severity.append('PETCLINIC_ZERO_READY')
if not severity:
 argo=get('/apis/argoproj.io/v1alpha1/namespaces/argocd/applications/petclinic');r['argo']=None if not argo else {'sync':argo['status'].get('sync',{}).get('status'),'health':argo['status'].get('health',{}).get('status'),'conditions':argo['status'].get('conditions')}
 try:
  q=urllib.request.Request('http://192.168.64.11/',headers={'Host':'petclinic.devops.local'});res=urllib.request.build_opener(urllib.request.ProxyHandler({})).open(q,timeout=3);r['http']={'status':res.status,'at':now()};res.close()
 except Exception as e:r['http']={'status':getattr(e,'code','UNREACHABLE'),'errorClass':type(e).__name__,'at':now()}
 if r['http']['status']in[502,503,'UNREACHABLE']:severity.append('BUSINESS_HTTP_UNAVAILABLE')
if severity:
 # No further calls after detecting severe/unavailable production.
 r['stop']=True;r['stopReasons']=severity
else:r['stop']=False;r['stopReasons']=[]
r['collectorCpuSeconds']=time.process_time()+resource.getrusage(resource.RUSAGE_CHILDREN).ru_utime+resource.getrusage(resource.RUSAGE_CHILDREN).ru_stime;r['collectionWallSeconds']=time.monotonic()-started;r['completedAt']=now();print(json.dumps(r))
