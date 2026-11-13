from pathlib import Path
import subprocess,json,concurrent.futures,os,errno,datetime
O=Path(__file__).resolve().parent;H=Path.home()
def save(n,x):(O/n).write_text(json.dumps(x,ensure_ascii=False,indent=2)+'\n')
cmds={
'colima-profiles':['du','-x','-k','-d','2',str(H/'.colima/_lima')],
'documents':['du','-x','-k','-d','2',str(H/'Documents')],
'local-data':['du','-x','-k','-d','2',str(H/'.local')],
'virtual-machines':['du','-x','-k','-d','2',str(H/'Virtual Machines.localized')],
'security-temp-sizes':['du','-x','-k','-d','1','/private/tmp/security-manager-kind-gdasvx1h'],
'build-tools':['sh','-c','command -v rsync; command -v tar; command -v gzip; command -v zstd; command -v qemu-img'],
}
def one(item):
 n,cmd=item
 try:
  z=subprocess.run(cmd,capture_output=True,timeout=35);out=z.stdout;meta={'command':cmd,'exit':z.returncode,'stderr':z.stderr.decode(errors='replace')[-1200:]}
 except subprocess.TimeoutExpired as e:out=e.stdout or b'';meta={'command':cmd,'exit':'TIMEOUT','partial':True}
 (O/(n+'.stdout')).write_bytes(out);save(n+'-execution.json',meta);return {'name':n,'exit':meta['exit'],'bytes':len(out)}
with concurrent.futures.ThreadPoolExecutor(max_workers=3) as ex:
 for x in ex.map(one,cmds.items()):print(json.dumps(x),flush=True)
# Archive/installers file metadata, without reading contents or declaring duplicates based on size.
rows=[]
for root in (H/'Downloads',H/'Documents',H/'Virtual Machines.localized'):
 for parent,dirs,files in os.walk(root):
  dirs[:]=[d for d in dirs if d not in ('.git','node_modules','.ssh','.kube')]
  for n in files:
   p=Path(parent)/n
   if p.suffix.lower() in ('.dmg','.pkg','.zip','.tar','.gz','.xz','.zst','.qcow2','.vmdk','.iso'):
    try:s=p.lstat();rows.append({'path':str(p),'size':s.st_size,'allocatedBytes':s.st_blocks*512,'uid':s.st_uid,'modified':s.st_mtime,'symlink':p.is_symlink(),'duplicateProof':False,'safeDelete':False})
    except OSError:pass
save('archive-candidate-metadata.json',rows)
# Read-only extent census: never reads file contents or changes qcow2. Active allocation is not a cold backup bound.
disk=H/'Library/Containers/com.utmapp.UTM/Data/Documents/devops.utm/Data/450FFAC4-2D45-4A41-B8C7-76EDE35C4877.qcow2'
r={'scope':'READ_ONLY_HOST_EXTENT_METADATA_ON_ACTIVE_SOURCE_NOT_CONSISTENT_BACKUP','mutations':0,'supported':all(hasattr(os,x) for x in ('SEEK_DATA','SEEK_HOLE'))}
if r['supported']:
 fd=os.open(disk,os.O_RDONLY)
 try:
  start=os.fstat(fd);pos=0;total=0;count=0;ok=True
  while pos<start.st_size and count<200000:
   try:data=os.lseek(fd,pos,os.SEEK_DATA)
   except OSError as e:
    if e.errno==errno.ENXIO:break
    raise
   end=os.lseek(fd,data,os.SEEK_HOLE);end=min(end,start.st_size)
   if end<=data:ok=False;break
   total+=end-data;count+=1;pos=end
  after=os.fstat(fd)
  r.update({'logicalBytes':start.st_size,'allocatedBytes':start.st_blocks*512,'dataExtentBytesObserved':total,'extentCount':count,'completed':ok and count<200000,'sourceStatStableDuringCensus':start.st_size==after.st_size and start.st_mtime_ns==after.st_mtime_ns,'notSafeUpperBoundForFutureColdCopy':True,'reason':'APFS extent hints and st_blocks may differ; live writes continue. Re-measure stopped source and validate target sparse copy before reducing conservative budget.'})
 except OSError as e:r.update({'errorErrno':e.errno,'completed':False})
 finally:os.close(fd)
save('source-extents.json',r);print(json.dumps({'extentCensus':r}))
# Only retain candidate-related open file records; never output unrelated credentials or process args.
p=subprocess.run(['lsof','-nP','-Fpcn'],capture_output=True,text=True,timeout=35)
prefixes=[str(H/x) for x in ['Library/Caches','Library/Logs','Downloads','.Trash','.npm','.m2','.colima','Library/Developer']]+['/private/tmp/security-']
rows=[];pid=None;comm=None
for line in p.stdout.splitlines():
 if line.startswith('p'):pid=line[1:]
 elif line.startswith('c'):comm=line[1:]
 elif line.startswith('n') and any(line[1:].startswith(x) for x in prefixes):rows.append({'pid':pid,'process':comm,'path':line[1:]})
save('candidate-open-files.json',{'exit':p.returncode,'stderrSummary':p.stderr[-600:],'visibility':'Current user/visible processes only; no matching FD does not prove no future/asynchronous use','rows':rows})
print(json.dumps({'archives':len(json.loads((O/'archive-candidate-metadata.json').read_text())),'candidateOpenFiles':len(rows)}))
