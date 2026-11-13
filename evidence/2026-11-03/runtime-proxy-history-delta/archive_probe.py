"""Bounded read-only archive inspection. Never extracts files or emits content."""
import io,json,tarfile,gzip,time,hashlib,re,sys
from pathlib import Path
OLD='e3c322ce52c284ac77450781fce9ed71fe0711e52d62550d076059956e054452'
class ReadLimit(Exception):pass
class LimitedReader:
 def __init__(self,base,limit):self.base=base;self.remaining=limit
 def read(self,n=-1):
  if n<0 or n>self.remaining:raise ReadLimit()
  b=self.base.read(n);self.remaining-=len(b);return b
def inspect_archive(path,byte_limit=32*1024**2,entry_limit=100000,time_limit=3):
 p=Path(path);r={'path':str(p),'size':p.stat().st_size,'entriesInspected':0,'candidates':[],'rawContentsArchived':False,'extractedToDisk':False,'status':'IN_PROGRESS','compression':'gzip' if p.name.endswith(('.gz','.tgz')) else 'none'};start=time.monotonic()
 try:
  with p.open('rb') as raw:
   if r['compression']=='gzip':
    gz=gzip.GzipFile(fileobj=raw,mode='rb');z=tarfile.open(fileobj=LimitedReader(gz,byte_limit),mode='r|')
   else:z=tarfile.open(fileobj=raw,mode='r:')
   with z:
    for e in z:
     if time.monotonic()-start>time_limit:r['status']='TIME_BOUND';break
     if r['entriesInspected']>=entry_limit:r['status']='ENTRY_BOUND';break
     r['entriesInspected']+=1
     if not e.isfile() or e.size>1024**2 or not re.search(r'config\.json(?:\.|$)|(?:v2ray|xray).*\.json$',e.name,re.I):continue
     f=z.extractfile(e);b=f.read(1024**2+1);digest=hashlib.sha256(b).hexdigest()
     r['candidates'].append({'entry':e.name,'bytes':len(b),'entryMtimeEpoch':e.mtime,'timestampBasis':'Archive header mtime, not trusted capture time','sha256':digest,'source':'EXISTING_ARCHIVE_ENTRY','trustLevel':'TRUSTED_PRE_DRIFT' if digest==OLD else 'UNTRUSTED','exactOldMatch':digest==OLD,'whyPredatesDrift':'Exact old sealed digest' if digest==OLD else 'No trusted pre-drift content binding'})
    else:r['status']='ARCHIVE_END_REACHED'
 except ReadLimit:r['status']='DECOMPRESSED_READ_BOUND'
 except (OSError,tarfile.TarError,EOFError) as e:r['status']='READ_ERROR';r['errorType']=type(e).__name__
 r['elapsedSeconds']=time.monotonic()-start;return r
if __name__=='__main__':print(json.dumps(inspect_archive(sys.argv[1])))
