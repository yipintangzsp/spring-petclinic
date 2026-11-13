"""One read-only inventory. No VM start, container create, filesystem write, DB or credential read."""
from pathlib import Path
import json,subprocess,shlex,datetime,platform,os,plistlib,shutil,ipaddress
O=Path(__file__).resolve().parent
S=['ssh','-o','BatchMode=yes','-o','ConnectTimeout=6','-o','StrictHostKeyChecking=yes','-o','HostName=192.168.64.11','-o','HostKeyAlias=192.168.1.58','zhang@192.168.1.58']
def remote(cmd,timeout=30):
 p=subprocess.run(S+[cmd],capture_output=True,text=True,timeout=timeout)
 if p.returncode:raise RuntimeError('Trusted read-only command failed exit='+str(p.returncode))
 return p.stdout
def k(args):return json.loads(remote('sudo -n kubectl '+shlex.join(args)))
nodes=k(['get','nodes','-o','json'])['items'];pods=k(['get','pods','-A','-o','json'])['items'];records=[]
for n in nodes:
 name=n['metadata']['name'];st=n['status'];stats=k(['get','--raw','/api/v1/nodes/'+name+'/proxy/stats/summary'])['node'];work=[]
 for p in pods:
  if p.get('spec',{}).get('nodeName')!=name:continue
  work.append({'namespace':p['metadata']['namespace'],'name':p['metadata']['name'],'phase':p.get('status',{}).get('phase'),'ownerKinds':[x['kind'] for x in p['metadata'].get('ownerReferences',[])],'resourceRequests':[c.get('resources',{}).get('requests',{}) for c in p['spec'].get('containers',[])],'deletionTimestamp':p['metadata'].get('deletionTimestamp')})
 records.append({'candidateId':'node-'+name,'host':name,'role':'control-plane and shared platform' if name=='devops' else 'production k3s worker','nodeUid':n['metadata']['uid'],'providerIdPresent':bool(n.get('spec',{}).get('providerID')),'providerProvisionedDiskSize':'UNKNOWN_NO_PROVIDER_MANAGEMENT_ACCESS_USED','system':st['nodeInfo'],'conditions':[{k:c.get(k) for k in ['type','status','reason']} for c in st['conditions']],'capacity':st['capacity'],'allocatable':st['allocatable'],'fs':stats['fs'],'imageFs':stats.get('runtime',{}).get('imageFs'),'productionWorkloads':work,'nodeAddresses':st.get('addresses',[]),'additionalAttachedDisks':'UNKNOWN_UNLESS_HOST_READ_SUCCEEDS'})
# Only already-trusted SSH access is attempted. No known_hosts additions, password/key exports or bypass.
hostCode="""import json,platform,os,subprocess
x={'architecture':platform.machine(),'OS':platform.platform()}
for tool,args in [('df',['-B1','-P']),('lsblk',['-b','-J','-o','NAME,TYPE,SIZE,FSTYPE,MOUNTPOINTS']),('findmnt',['-J','-o','TARGET,SOURCE,FSTYPE,OPTIONS'])]:
 p=subprocess.run([tool,*args],capture_output=True,text=True,timeout=8);x[tool]={'exit':p.returncode,'stdout':p.stdout if p.returncode==0 else None}
s=os.statvfs('/');x['rootStatvfs']={'capacityBytes':s.f_blocks*s.f_frsize,'availableBytes':s.f_bavail*s.f_frsize,'freeBytes':s.f_bfree*s.f_frsize,'blockSize':s.f_frsize}
print(json.dumps(x))"""
for r in records:
 if r['host']=='devops':continue
 ip=next((a['address'] for a in r['nodeAddresses'] if a['type']=='InternalIP'),None)
 if not ip:r['hostRead']={'status':'UNAVAILABLE','reason':'NO_INTERNAL_IP'};continue
 ipaddress.ip_address(ip)
 inner=['ssh','-o','BatchMode=yes','-o','StrictHostKeyChecking=yes','-o','ConnectTimeout=4','-o','ConnectionAttempts=1','root@'+ip,'python3 -c '+shlex.quote(hostCode)]
 try:
  p=subprocess.run(S+[shlex.join(inner)],capture_output=True,text=True,timeout=15)
  if p.returncode==0:r['hostRead']={'status':'READ_ONLY_SUCCESS','metadata':json.loads(p.stdout)}
  else:r['hostRead']={'status':'UNAVAILABLE','exit':p.returncode,'reason':'HOST_KEY_NOT_TRUSTED' if 'Host key verification failed' in p.stderr else 'AUTH_OR_ROUTE_UNAVAILABLE','noBypass':True}
 except (subprocess.TimeoutExpired,json.JSONDecodeError):r['hostRead']={'status':'UNAVAILABLE','reason':'BOUNDED_TIMEOUT_OR_INVALID_OUTPUT','noBypass':True}
(O/'node-candidate-inventory.json').write_text(json.dumps({'sampledAt':datetime.datetime.now(datetime.timezone.utc).isoformat(),'classification':'READ_ONLY_CURRENT_NODES_AND_WORKLOADS','nodes':records,'noPodCreated':True,'noNodeModification':True,'noSecretsRead':True},indent=2)+'\n')
# Local inventory bounded to actual profiles/known UTM document root and mounted storage.
def runlocal(args):
 try:
  p=subprocess.run(args,capture_output=True,text=True,timeout=15);return {'exit':p.returncode,'stdout':p.stdout if p.returncode==0 else None,'errorRecordedWithoutSensitiveText':p.returncode!=0}
 except (FileNotFoundError,subprocess.TimeoutExpired):return {'exit':None,'stdout':None,'errorRecordedWithoutSensitiveText':True}
local={'sampledAt':datetime.datetime.now(datetime.timezone.utc).isoformat(),'host':platform.node(),'architecture':platform.machine(),'OS':platform.platform(),'colima':runlocal(['colima','list','--json']),'dockerContexts':runlocal(['docker','context','ls','--format','{{json .}}']),'mounted':[],'utm':[]}
for p in [Path('/Users/zhangsir/code'),*list(Path('/Volumes').iterdir())]:
 if p.is_dir():
  s=os.statvfs(p);local['mounted'].append({'path':str(p),'device':os.stat(p).st_dev,'capacityBytes':s.f_blocks*s.f_frsize,'availableBytes':s.f_bavail*s.f_frsize,'freeBytes':s.f_bfree*s.f_frsize,'usedBytes':(s.f_blocks-s.f_bfree)*s.f_frsize})
local['diskutil']=runlocal(['/usr/sbin/diskutil','list','-plist'])
if local['diskutil'].get('stdout'):
 try:
  b=plistlib.loads(local['diskutil'].pop('stdout').encode());local['diskutil']['disks']=b.get('AllDisksAndPartitions',[])
 except Exception:local['diskutil']['stdout']=None
for d in Path('/Users/zhangsir/Library/Containers/com.utmapp.UTM/Data/Documents').glob('*.utm'):
 cfg=d/'config.plist'
 if not cfg.exists():continue
 x=plistlib.loads(cfg.read_bytes());local['utm'].append({'path':str(d),'system':x.get('System'),'drives':[{k:v for k,v in drive.items() if k in ['ImageName','ImageType','Interface','ReadOnly']} for drive in x.get('Drive',[])],'configSha256':__import__('hashlib').sha256(cfg.read_bytes()).hexdigest()})
# Existing running profile only; never start stopped profile. Read guest metadata and existing container inventory.
entries=[]
for l in (local['colima'].get('stdout') or '').splitlines():
 try:entries.append(json.loads(l))
 except json.JSONDecodeError:pass
if any(x.get('name')=='security-test' and x.get('status')=='Running' for x in entries):
 local['securityTestGuest']=runlocal(['colima','ssh','--profile','security-test','--','python3','-c',hostCode])
 local['securityTestContainers']=runlocal(['docker','--context','colima-security-test','ps','-a','--format','{{json .}}'])
(O/'local-candidate-inventory.json').write_text(json.dumps(local,indent=2)+'\n')
print(json.dumps({'nodeCandidates':[{ 'host':r['host'],'arch':r['system']['architecture'],'availableGiB':r['fs']['availableBytes']/1024**3,'workloadCount':len(r['productionWorkloads']),'hostRead':r.get('hostRead',{}).get('status')} for r in records],'localMounts':local['mounted'],'utmNames':[Path(x['path']).name for x in local['utm']],'colimaExit':local['colima']['exit'],'localGuestReadExit':local.get('securityTestGuest',{}).get('exit')}))
