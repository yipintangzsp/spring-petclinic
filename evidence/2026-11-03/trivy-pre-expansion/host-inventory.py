from pathlib import Path
import subprocess,json,concurrent.futures,datetime,plistlib,hashlib,shutil
O=Path(__file__).resolve().parent;home=Path.home();vm=home/'Library/Containers/com.utmapp.UTM/Data/Documents/devops.utm';disk=vm/'Data/450FFAC4-2D45-4A41-B8C7-76EDE35C4877.qcow2'
commands={
'apfs':['diskutil','apfs','list','-plist'],
'data-volume':['diskutil','info','-plist','/System/Volumes/Data'],
'snapshots':['diskutil','apfs','listSnapshots','/System/Volumes/Data','-plist'],
'volumes':['df','-kP'],
'local-snapshots':['tmutil','listlocalsnapshots','/'],
'image-info':['qemu-img','info','-U','--output=json','--backing-chain',str(disk)],
'image-use':['lsof','-Fpcfan','--',str(disk)],
'downloads':['du','-x','-k','-d','1',str(home/'Downloads')],
'cache':['du','-x','-k','-d','1',str(home/'Library/Caches')],
'dev-cache':['du','-x','-k','-d','1',str(home/'.cache')],
'colima':['du','-x','-k','-d','2',str(home/'.colima')],
'trash':['du','-x','-k','-d','1',str(home/'.Trash')],
'user-top':['du','-x','-k','-d','1',str(home)],
'logs':['du','-x','-k','-d','1',str(home/'Library/Logs')],
}
def run(item):
 name,cmd=item
 try:
  p=subprocess.run(cmd,capture_output=True,timeout=50);meta={'command':cmd,'exit':p.returncode,'stderr':p.stderr.decode(errors='replace')[-1500:]};b=p.stdout
  if name in ['apfs','data-volume','snapshots']:
   try:b=(json.dumps(plistlib.loads(b),indent=2,default=str)+'\n').encode()
   except Exception:meta['parse']='NOT_PLIST'
 except subprocess.TimeoutExpired as e:b=e.stdout or b'';meta={'command':cmd,'exit':'TIMEOUT','stderr':'Bounded read-only inventory timed out; partial output is not full accounting'}
 (O/(name+'.stdout')).write_bytes(b);(O/(name+'-execution.json')).write_text(json.dumps(meta,indent=2)+'\n');return {'name':name,'exit':meta['exit'],'bytes':len(b)}
config=plistlib.loads((vm/'config.plist').read_bytes());items=[]
for p in vm.rglob('*'):
 if p.is_file():
  s=p.stat();items.append({'path':str(p.relative_to(vm)),'logicalBytes':s.st_size,'allocatedBytes':s.st_blocks*512})
r={'vmIdentity':config['Information'],'bundle':str(vm),'configSha256':hashlib.sha256((vm/'config.plist').read_bytes()).hexdigest(),'drives':config['Drive'],'system':config['System'],'files':items,'UTMVersion':plistlib.loads(Path('/Applications/UTM.app/Contents/Info.plist').read_bytes())['CFBundleShortVersionString'],'qemuImg':shutil.which('qemu-img')};(O/'vm-identity.json').write_text(json.dumps(r,indent=2,default=str)+'\n')
with concurrent.futures.ThreadPoolExecutor(max_workers=3) as ex:
 for r in ex.map(run,commands.items()):print(json.dumps(r),flush=True)
