"""Bounded current local process linkage and existing unified-log metadata only."""
from pathlib import Path
import subprocess,json,os,re,datetime,tempfile
O=Path(__file__).resolve().parent;now=lambda:datetime.datetime.now(datetime.timezone.utc).isoformat();r={'classification':'LOCAL_MAC_READ_ONLY_HOST_CORRELATION','at':now(),'productionMutations':0,'historicalResourcePeaks':'UNKNOWN_NOT_MEASURED_BY_TEST_RUNNER'}
ps=subprocess.check_output(['ps','-axo','pid=,ppid=,args='],text=True);residue=[];qemu=[]
for line in ps.splitlines():
 parts=line.strip().split(None,2)
 if len(parts)<3:continue
 pid,ppid,args=parts
 if any(s in args for s in ['loki.test.mjs','manager-v2/observability/queries.test.mjs','security-manager-v2-loki/run-tests.py','security-cosign-boundary-'])and pid!=str(os.getpid()):residue.append({'pid':int(pid),'ppid':int(ppid),'matchedSignature':next(s for s in ['loki.test.mjs','manager-v2/observability/queries.test.mjs','security-manager-v2-loki/run-tests.py','security-cosign-boundary-']if s in args)})
 if 'QEMULauncher'in args:
  uuid=re.search(r'(?:-uuid|uuid=)\s*([^\s,]+)',args);memory=re.search(r'(?:^|\s)-m\s+(\S+)',args);smp=re.search(r'(?:^|\s)-smp\s+(\S+)',args)
  qemu.append({'pid':int(pid),'ppid':int(ppid),'guestUuid':uuid.group(1)if uuid else None,'memoryArgument':memory.group(1)if memory else None,'smpArgument':smp.group(1)if smp else None,'devopsUuidMatches':bool(uuid and uuid.group(1).lower()=='4c8dedbc-d2fb-43f6-99ec-c2c6f9c1ff46')})
r['matchingTestProcesses']=residue;r['qemuLinkage']=qemu;r['remainingTemporaryTrees']=[{'name':p.name,'createdAt':datetime.datetime.fromtimestamp(p.stat().st_ctime,datetime.timezone.utc).isoformat()}for p in Path(tempfile.gettempdir()).glob('security-cosign-boundary-*')if p.is_dir()]
predicate='(process == "kernel" AND (eventMessage CONTAINS[c] "memory pressure" OR eventMessage CONTAINS[c] "memorystatus" OR eventMessage CONTAINS[c] "out of memory")) OR ((process == "QEMULauncher" OR process == "UTM" OR process == "QEMUHelper") AND (eventMessage CONTAINS[c] "suspend" OR eventMessage CONTAINS[c] "resume" OR eventMessage CONTAINS[c] "error" OR eventMessage CONTAINS[c] "exception"))'
cmd=['/usr/bin/log','show','--start','2026-11-05 10:05:00','--end','2026-11-05 10:45:00','--style','json','--info','--predicate',predicate]
try:
 p=subprocess.run(cmd,text=True,capture_output=True,timeout=20);body=p.stdout;r['unifiedLog']={'command':cmd,'requestedWindowTimezone':'Asia/Shanghai (local host)','exit':p.returncode,'stderr':p.stderr[:1000],'bytes':len(body.encode())}
 if p.returncode==0 and len(body.encode())<=2*1024*1024:
  try:data=json.loads(body);r['unifiedLog']['entries']=[{k:v.get(k)for k in ['timestamp','processID','processImagePath','subsystem','category','messageType','eventMessage']}for v in data]
  except ValueError:r['unifiedLog']['parseStatus']='UNKNOWN_FORMAT'
 else:r['unifiedLog']['status']='UNAVAILABLE_OR_RESPONSE_CAP'
except subprocess.TimeoutExpired:r['unifiedLog']={'command':cmd,'status':'TIMEOUT','timeoutSeconds':20}
with(O/'local-host.json').open('x')as f:json.dump(r,f,indent=2);f.write('\n')
print(json.dumps({'matchingTestProcesses':residue,'qemuLinkage':qemu,'temporaryTrees':len(r['remainingTemporaryTrees']),'unifiedLog':{k:v for k,v in r['unifiedLog'].items()if k!='entries'},'unifiedLogEntries':len(r['unifiedLog'].get('entries',[]))}))
