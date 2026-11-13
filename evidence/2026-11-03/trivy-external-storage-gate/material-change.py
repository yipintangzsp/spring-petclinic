from pathlib import Path
import subprocess,json,plistlib,datetime,hashlib
O=Path(__file__).resolve().parent;prior=O.parent/'trivy-backup-capacity'
def save(n,x):(O/n).write_text(json.dumps(x,ensure_ascii=False,indent=2)+'\n')
commands={'all-disks':['diskutil','list','-plist'],'external-disks':['diskutil','list','-plist','external'],'data-volume':['diskutil','info','-plist','/System/Volumes/Data'],'mounts':['mount'],'df':['df','-kP','/System/Volumes/Data'],'smb':['smbutil','statshares','-a'],'nfs':['nfsstat','-m']}
for n,cmd in commands.items():
 z=subprocess.run(cmd,capture_output=True,timeout=20)
 assert z.returncode==0,(n,z.returncode)
 b=z.stdout
 if '-plist' in cmd:b=(json.dumps(plistlib.loads(b),indent=2,default=str)+'\n').encode()
 (O/(n+'.stdout')).write_bytes(b);save(n+'-execution.json',{'command':cmd,'exit':z.returncode,'time':datetime.datetime.now(datetime.timezone.utc).isoformat(),'stderr':z.stderr.decode(errors='replace')[-700:]})
read=lambda p:json.loads(p.read_text())
old=read(prior/'all-disks.stdout');new=read(O/'all-disks.stdout');oldext=read(prior/'external-disks.stdout');ext=read(O/'external-disks.stdout')
oldmount=(prior/'mounts.stdout').read_text().splitlines();mount=(O/'mounts.stdout').read_text().splitlines();added=sorted(set(mount)-set(oldmount));removed=sorted(set(oldmount)-set(mount))
data=read(O/'data-volume.stdout');df=int((O/'df.stdout').read_text().splitlines()[1].split()[3])*1024;free=min(data['APFSContainerFree'],df)
oldfree=read(prior/'host-after-audit.json')['HOST_FREE_AUTHORITATIVE']
vm=read(prior/'vm-identity.json');bundle=Path(vm['bundle']);cfg=bundle/'config.plist';conf=plistlib.loads(cfg.read_bytes());sameconfig=hashlib.sha256(cfg.read_bytes()).hexdigest()==vm['configSha256'];sameidentity=conf['Information']['UUID']==vm['identity']['UUID']
newdisk=sorted(set(new['AllDisks'])-set(old['AllDisks']));gone=sorted(set(old['AllDisks'])-set(new['AllDisks']));changed=bool(added or removed or newdisk or gone or ext!=oldext or not sameconfig or not sameidentity or free>=37*1024**3)
r={'baseline':'../trivy-backup-capacity/evidence-sha256.json','time':datetime.datetime.now(datetime.timezone.utc).isoformat(),'newMounts':added,'removedMounts':removed,'newDiskIdentifiers':newdisk,'removedDiskIdentifiers':gone,'externalDisks':ext,'previousHostFreeBytes':oldfree,'HOST_FREE_AUTHORITATIVE':free,'hostFreeDeltaBytes':free-oldfree,'requiredHostBytesArchitectureA':37*1024**3,'hostShortfallBytes':max(0,37*1024**3-free),'hostFreeCrossedGuard':free>=37*1024**3,'vmIdentityUnchanged':sameidentity,'vmConfigSha256':hashlib.sha256(cfg.read_bytes()).hexdigest(),'vmConfigUnchanged':sameconfig,'vmBundlePath':str(bundle),'newUtmStorageLocationIdentified':not sameconfig or not sameidentity,'newIndependentStorageIdentified':bool(added or newdisk or ext!=oldext),'MATERIAL_STORAGE_CHANGE':'YES' if changed else 'NO','note':'Normal free-byte drift below guard is not material capacity recovery. No cache, Trash, image or archive re-inventory performed. No new unmounted network endpoint is inferred.'}
save('material-change.json',r);print(json.dumps(r,ensure_ascii=False))
