from pathlib import Path
import subprocess,json,concurrent.futures,plistlib
O=Path(__file__).resolve().parent;H=Path.home();commands={
'external-disks':['diskutil','list','-plist','external'],
'mounts':['mount'],
'app-support':['du','-x','-k','-d','1',str(H/'Library/Application Support')],
'app-containers':['du','-x','-k','-d','1',str(H/'Library/Containers')],
'homebrew-cache':['brew','--cache'],
'colima-status':['colima','list','--json'],
'docker-status':['docker','context','ls','--format','{{json .}}'],
'qemu-version':['qemu-img','--version'],
'copy-tools':['rsync','--version'],
}
def one(item):
 n,a=item
 try:
  p=subprocess.run(a,capture_output=True,timeout=45);b=p.stdout;meta={'command':a,'exit':p.returncode,'stderr':p.stderr.decode(errors='replace')[-1500:]}
  if n=='external-disks':
   try:b=json.dumps(plistlib.loads(b),indent=2,default=str).encode()
   except:pass
 except (FileNotFoundError,subprocess.TimeoutExpired) as e:b=getattr(e,'stdout',b'') or b'';meta={'command':a,'exit':type(e).__name__,'stderr':'Read-only metadata not available; no absence-of-use proof inferred'}
 (O/(n+'.stdout')).write_bytes(b);(O/(n+'-execution.json')).write_text(json.dumps(meta,indent=2)+'\n');return {'name':n,'exit':meta['exit'],'bytes':len(b)}
with concurrent.futures.ThreadPoolExecutor(max_workers=3) as ex:
 for r in ex.map(one,commands.items()):print(json.dumps(r),flush=True)
# Top-level installers/archives metadata only, not their contents or Trash contents.
rows=[]
for p in (H/'Downloads').iterdir():
 if p.is_file():
  s=p.stat();rows.append({'path':str(p),'logicalBytes':s.st_size,'allocatedBytes':s.st_blocks*512,'modifiedAt':s.st_mtime,'suffix':p.suffix,'classification':'REVIEW_REQUIRED','safeDelete':False})
(O/'download-file-metadata.json').write_text(json.dumps(rows,indent=2)+'\n')
