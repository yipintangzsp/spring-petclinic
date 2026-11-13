"""Read-only evidence helpers. No production/checkpoint implementation imports."""
import hashlib,json,datetime,re
OLD='e3c322ce52c284ac77450781fce9ed71fe0711e52d62550d076059956e054452'
NEW='b702ff16eae6f27f0cc84e11e59565b1dded8e2c197778f0b888297266593d62'
DRIFT='2026-11-03T09:20:28.424102+00:00'
def sha(b):return hashlib.sha256(b).hexdigest()
def timestamp(s):
 if not isinstance(s,str):return None
 try:
  t=datetime.datetime.fromisoformat(s.replace('Z','+00:00'))
  return t.astimezone(datetime.timezone.utc) if t.tzinfo is not None else None
 except (ValueError,TypeError):return None
def classify(digest,mtime,source_trusted=False):
 if digest==OLD:return 'TRUSTED_PRE_DRIFT' # exact content identity bound to sealed old hash
 if digest==NEW:return 'POST_DRIFT'
 t=timestamp(mtime)
 return 'LIKELY_PRE_DRIFT' if source_trusted and t and t<timestamp(DRIFT) else 'UNTRUSTED'
def parse(text):
 def pairs(items):
  d={}
  for k,v in items:
   if k in d:raise ValueError('DUPLICATE_KEY')
   d[k]=v
  return d
 return json.loads(text,object_pairs_hook=pairs,parse_constant=lambda _:(_ for _ in ()).throw(ValueError('NONFINITE')))
def differences(a,b,path='$'):
 if type(a)!=type(b):return [{'path':path,'kind':'TYPE_CHANGE','oldDigest':sha(json.dumps(a,sort_keys=True).encode()),'newDigest':sha(json.dumps(b,sort_keys=True).encode())}]
 if isinstance(a,dict):
  out=[]
  for k in sorted(set(a)|set(b)):
   p=path+'.'+k
   if k not in a or k not in b:out.append({'path':p,'kind':'ADDED' if k not in a else 'REMOVED'})
   else:out+=differences(a[k],b[k],p)
  return out
 if isinstance(a,list):
  out=[]
  for i in range(max(len(a),len(b))):
   p=path+'['+str(i)+']'
   if i>=len(a) or i>=len(b):out.append({'path':p,'kind':'ADDED' if i>=len(a) else 'REMOVED'})
   else:out+=differences(a[i],b[i],p)
  return out
 return [] if a==b else [{'path':path,'kind':'VALUE_CHANGE','oldDigest':sha(json.dumps(a).encode()),'newDigest':sha(json.dumps(b).encode())}]
def ordered(events):
 times=[timestamp(e['timestamp']) for e in events]
 return all(t is not None for t in times) and all(a<=b for a,b in zip(times,times[1:]))
