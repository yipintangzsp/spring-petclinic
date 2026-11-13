from pathlib import Path
import subprocess,json,shutil,datetime,os,importlib.util
O=Path('/Users/zhangsir/code/petclinic-platform-20261011/evidence/2026-11-03/trivy-guard-dependency-boundary-review')
rows=[]
for tool,args in [('colima',['list','--json']),('limactl',['list','--json'])]:
 exe=shutil.which(tool)
 if not exe:rows.append({'tool':tool,'available':False});continue
 p=subprocess.run([exe,*args],capture_output=True,text=True,timeout=20)
 data=[]
 if p.returncode==0:
  for line in p.stdout.splitlines():
   try:
    d=json.loads(line)
    for x in d if isinstance(d,list) else [d]:
     if isinstance(x,dict):data.append({k:v for k,v in x.items() if k.lower() in ['name','status','arch','cpus','memory','disk','vmtype','runtime','dir']})
   except json.JSONDecodeError:pass
 rows.append({'tool':tool,'available':True,'exitStatus':p.returncode,'entries':data,'stderrPresent':bool(p.stderr),'stderrNotArchived':True})
mounts=[]
for path in [Path('/Users/zhangsir/code'),*list(Path('/Volumes').iterdir())]:
 if not path.is_dir():continue
 try:
  s=os.statvfs(path);mounts.append({'path':str(path),'capacityBytes':s.f_blocks*s.f_frsize,'availableBytes':s.f_bavail*s.f_frsize,'device':os.stat(path).st_dev})
 except OSError:pass
result={'sampledAt':datetime.datetime.now(datetime.timezone.utc).isoformat(),'classification':'LOCAL_READ_ONLY_RESOURCE_INVENTORY_NOT_EXPERIMENT','runtimes':rows,'visibleMountedStorage':mounts,'jsonschemaInstalled':importlib.util.find_spec('jsonschema') is not None,'noVMStartedOrProvisioned':True,'noDiskCreated':True,'scopeLimit':'Only this local host and visible existing Lima/Colima inventory; no claim all remote capacity globally absent. No isolated target was supplied/attested.'}
(O/'isolated-resource-inventory.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result))
