"""Offline seal only; no production probes, imports or historical replays."""
from pathlib import Path
import hashlib,json,stat,ast,sys,datetime
O=Path(__file__).resolve().parent;R=O.parents[2];SRC=R/'infra/observability/bounded-sampler'
def sha(p):
 h=hashlib.sha256()
 with p.open('rb')as f:
  for b in iter(lambda:f.read(1024*1024),b''):h.update(b)
 return h.hexdigest()
def snapshot(p):
 s=p.lstat();return {'sha256':sha(p),'size':s.st_size,'mode':stat.S_IMODE(s.st_mode),'uid':s.st_uid,'gid':s.st_gid,'mtimeNs':s.st_mtime_ns,'ctimeNs':s.st_ctime_ns,'inode':s.st_ino,'symlink':p.is_symlink()}
def read(p):return json.loads(p.read_text())
def put(n,v):
 with(O/n).open('x')as f:json.dump(v,f,indent=2);f.write('\n')
b=read(O/'protected-before.json');assert b['priorProtectedCount']==13931 and len(b['protected'])==13953
assert all((R/n).exists()and snapshot(R/n)==v for n,v in b['protected'].items()),'Historical content or metadata changed'
hist=sorted(str(p.relative_to(R))for p in(R/'evidence').rglob('*')if p.is_file()and not p.is_relative_to(O));assert hist==b['historicalEvidenceFiles']
files=list(O.iterdir())+list(SRC.iterdir());syntax=0
for p in files:
 assert p.is_file()and not p.is_symlink()and p.stat().st_nlink==1,p
 if p.suffix=='.py':compile(p.read_text(),str(p),'exec');syntax+=1
 if p.suffix=='.json':json.loads(p.read_text())
receipt=read(O/'attempt4-receipt.json');assert receipt['exit']==0 and receipt['temporaryTreeRemoved']and receipt['productionConnections']==receipt['productionChanges']==receipt['release']==receipt['rollout']==0
for n,h in receipt['sourceHashes'].items():assert sha(SRC/n)==h,'Final tested source mismatch: '+n
for i in range(1,5):assert read(O/f'attempt{i}-receipt.json')['temporaryTreeRemoved']
t=read(O/'attempt4-tests.json');assert t['tests']==43 and t['failures']==t['errors']==0 and len(t['skipped'])==1
assert 'test_native_linux_proc'in t['skipped'][0]['test']and t['environment']['uid']!=0
for item in t['metrics']:
 assert item['result']['cleanupVerified']and item['result']['retryCount']==0 and not item['result']['networkExecutionEnabled']
 for w in item['result']['workers'].values():assert w['reaped']
 if item['case']in ['cli-guest','cli-host']:
  assert item['result']['status']=='PASS'
  for w in item['result']['workers'].values():
   assert w['cpuSeconds']<=.25 and w['maxRssBytes']<=64*1024*1024 and w['stdoutBytes']<=32768
   assert w['record']['externalCommands']==w['record']['subprocesses']==0
 assert 'SYNTHETIC_SECRET'not in json.dumps(item['result'])and 'SYNTHETIC_PRIVATE_COMM'not in json.dumps(item['result'])
# Static check is a supporting source audit, not a complete Python security proof.
a=ast.parse((SRC/'sampler.py').read_text());modules={x.name for n in ast.walk(a)if isinstance(n,ast.Import)for x in n.names}
assert not modules&{'subprocess','socket','urllib','requests','multiprocessing'}
for n in ast.walk(a):
 if isinstance(n,ast.Call)and isinstance(n.func,ast.Attribute)and isinstance(n.func.value,ast.Name)and n.func.value.id=='os':assert n.func.attr not in ['system','fork','popen','execv','execve','kill','killpg','listdir','scandir','walk']
v=read(O/'verdict.json')['verdict'];assert v['PRODUCTION_SAMPLER_OVERHEAD']==v['HOST_GUEST_REAL_SYNCHRONIZED_CAPTURE']=='NOT_TESTED'
assert v['ROOT_CAUSE']=='UNDETERMINED'and v['ORIGINAL_EVIDENCE_INTEGRITY']=='FAILED'and v['FINAL_WIRED_CAPABILITY']=='14/16'
assert v['RELEASE_COUNT']==v['ROLLOUT_COUNT']==0
if not(O/'verification.json').exists():put('verification.json',{'at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'status':'PASS','protectedCount':len(b['protected']),'priorProtectedCount':13931,'allContentAndSpecifiedMetadataUnchanged':True,'historicalEvidenceFileCount':len(hist),'historicalNamesUnchanged':True,'pythonSyntaxFiles':syntax,'testedSourceHashesMatch':True,'localTests':{'pass':42,'fail':0,'skip':1},'allOwnedMeasuredWorkersReaped':True,'allTemporaryTreesRemoved':True,'actualSshTests':0,'productionConnections':0,'productionChanges':0,'noHistoricalReplayEntrypoint':True,'originalEvidenceIntegrity':'FAILED'})
if not(O/'seal.json').exists():put('seal.json',{'files':{str(p.relative_to(R)):snapshot(p)for p in sorted(list(O.iterdir())+list(SRC.iterdir()))if p.name!='seal.json'},'selfExcluded':True,'originalEvidenceIntegrity':'FAILED'})
seal=read(O/'seal.json');actual={str(p.relative_to(R))for p in list(O.iterdir())+list(SRC.iterdir())if p.name!='seal.json'}
assert set(seal['files'])==actual and all(snapshot(R/n)==v for n,v in seal['files'].items()),'Current seal drift'
print(json.dumps({'status':'PASS','protected':13953,'previousProtected':13931,'sealedFiles':len(seal['files']),'tests':'42 PASS / 1 SKIP','productionOverhead':'NOT_TESTED','productionConnections':0}))
