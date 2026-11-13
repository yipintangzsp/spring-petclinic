from pathlib import Path
import subprocess,plistlib,json,datetime,concurrent.futures,hashlib,re,os
O=Path(__file__).resolve().parent;H=Path.home()
def save(n,x):(O/n).write_text(json.dumps(x,ensure_ascii=False,indent=2,default=str)+'\n')
commands={
 'apfs':['diskutil','apfs','list','-plist'],'data-volume':['diskutil','info','-plist','/System/Volumes/Data'],
 'external-disks':['diskutil','list','-plist','external'],'all-disks':['diskutil','list','-plist'],'mounts':['mount'],'volumes':['df','-kP'],
 'smb-shares':['smbutil','statshares','-a'],'nfs-mounts':['nfsstat','-m'],'colima':['colima','list','--json'],
 'docker-contexts':['docker','context','ls','--format','{{json .}}'],
 'docker-cache-security-test':['docker','--context','colima-security-test','system','df','--format','{{json .}}'],
 'docker-build-cache-security-test':['docker','--context','colima-security-test','builder','du'],
 'usb-thunderbolt':['system_profiler','SPUSBDataType','SPThunderboltDataType','-json'],
 'cloud-mounts':['ls','-ld',str(H/'Library/CloudStorage'),str(H/'Library/Mobile Documents/com~apple~CloudDocs')],
 'utm-bundles':['du','-x','-k','-d','2',str(H/'Library/Containers/com.utmapp.UTM/Data/Documents')],
}
paths={
 'downloads':H/'Downloads','trash':H/'.Trash','homebrew-cache':H/'Library/Caches/Homebrew',
 'browser-cache':H/'Library/Caches/Google','browser-cache-other':H/'Library/Caches/com.apple.Safari',
 'colima-data':H/'.colima','xcode-deriveddata':H/'Library/Developer/Xcode/DerivedData',
 'xcode-support':H/'Library/Developer/Xcode/iOS DeviceSupport','simulators':H/'Library/Developer/CoreSimulator',
 'npm-cache':H/'.npm','pip-cache':H/'Library/Caches/pip','maven-cache':H/'.m2',
 'gradle-cache':H/'.gradle','cargo-cache':H/'.cargo','go-cache':H/'Library/Caches/go-build',
 'logs':H/'Library/Logs','cache-other':H/'Library/Caches','generic-cache':H/'.cache',
 'security-temp':Path('/private/tmp'),
}
for n,p in paths.items():
 if n!='security-temp':commands[n]=['du','-x','-k','-d','1',str(p)]
def run(item):
 n,a=item;beg=datetime.datetime.now(datetime.timezone.utc).isoformat();b=b''
 try:
  z=subprocess.run(a,capture_output=True,timeout=40);b=z.stdout;meta={'command':a,'exit':z.returncode,'stderr':z.stderr.decode(errors='replace')[-1600:]}
  if '-plist' in a:
   try:b=(json.dumps(plistlib.loads(b),indent=2,default=str)+'\n').encode()
   except Exception:meta['parse']='FAILED'
  if n=='usb-thunderbolt' and z.returncode==0:
   data=json.loads(b);rows=[]
   def visit(x,anc=''):
    if isinstance(x,dict):
     if '_name' in x:rows.append({'name':x['_name'],'parent':anc,'storageType':x.get('device_media_type'),'speed':x.get('device_speed')});anc=x.get('_name',anc)
     for k,v in x.items():
      if isinstance(v,(dict,list)):visit(v,anc)
    elif isinstance(x,list):
     for v in x:visit(v,anc)
   visit(data);b=(json.dumps({'devices':rows,'serialNumbersExcluded':True},indent=2)+'\n').encode()
 except subprocess.TimeoutExpired as e:b=e.stdout or b'';meta={'command':a,'exit':'TIMEOUT','stderr':'Bounded inventory incomplete; cannot infer absence'}
 except FileNotFoundError:meta={'command':a,'exit':'TOOL_NOT_FOUND','stderr':''}
 meta.update({'start':beg,'end':datetime.datetime.now(datetime.timezone.utc).isoformat()})
 (O/(n+'.stdout')).write_bytes(b);save(n+'-execution.json',meta);return {'name':n,'exit':meta['exit'],'bytes':len(b)}
# VM metadata, no content reads of active disk or production credentials.
vm=H/'Library/Containers/com.utmapp.UTM/Data/Documents/devops.utm';c=plistlib.loads((vm/'config.plist').read_bytes());files=[]
for p in vm.rglob('*'):
 if p.is_file():
  s=p.stat();files.append({'path':str(p.relative_to(vm)),'logicalBytes':s.st_size,'allocatedBytes':s.st_blocks*512})
save('vm-identity.json',{'identity':c['Information'],'bundle':str(vm),'configSha256':hashlib.sha256((vm/'config.plist').read_bytes()).hexdigest(),'files':files,'system':c['System']})
disk=vm/'Data/450FFAC4-2D45-4A41-B8C7-76EDE35C4877.qcow2'
commands['image-info']=['qemu-img','info','-U','--output=json','--backing-chain',str(disk)]
commands['image-use']=['lsof','-Fpcfan','--',str(disk)]
with concurrent.futures.ThreadPoolExecutor(max_workers=4) as ex:
 for r in ex.map(run,commands.items()):print(json.dumps(r),flush=True)
rows=[]
for n,p in paths.items():
 if not p.exists():rows.append({'name':n,'path':str(p),'exists':False});continue
 s=p.stat();rows.append({'name':n,'path':str(p),'exists':True,'uid':s.st_uid,'mode':oct(s.st_mode&0o777),'lastModified':s.st_mtime,'accessTime':s.st_atime,'accessTimeIsUsageProof':False})
save('candidate-path-metadata.json',rows)
# Do not read SSH keys, proxy commands, cloud credentials or /etc auto mounts containing credentials.
ssh=H/'.ssh/config';aliases=[]
if ssh.exists():
 for line in ssh.read_text().splitlines():
  m=re.match(r'^\s*Host\s+(.+)$',line,re.I)
  if m:aliases.extend(m.group(1).split())
save('existing-management-entrypoints.json',{'configuredSshAliases':aliases,'secretsRead':False,'remoteTargetsUsedAsBackup':False,'authorization':'Profile presence is not permission to repurpose remote server storage; no newly discovered hosts probed.'})
# Temporary names only; never inspect unrelated contents or assume disposable based on a prefix.
rows=[]
for p in Path('/private/tmp').iterdir():
 if any(x in p.name.lower() for x in ('security','sops','trivy','runtime','vm-copy','backup')):
  try:s=p.lstat();rows.append({'path':str(p),'uid':s.st_uid,'modified':s.st_mtime,'symlink':p.is_symlink(),'safeDelete':False,'reason':'Ownership/current references not established'})
  except OSError:pass
save('temporary-candidate-metadata.json',rows)
