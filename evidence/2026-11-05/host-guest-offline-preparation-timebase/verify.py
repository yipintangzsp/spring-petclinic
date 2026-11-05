"""Final offline verification, including superseded immutable attempts."""
from pathlib import Path
import json,hashlib,stat,datetime,ast
O=Path(__file__).resolve().parent;R=O.parents[2];P=R/'evidence/2026-11-05/host-guest-offline-preparation';SRC=R/'infra/observability/bounded-sampler'
def sha(p):
 h=hashlib.sha256()
 with p.open('rb')as f:
  for b in iter(lambda:f.read(1024*1024),b''):h.update(b)
 return h.hexdigest()
def snap(p):
 s=p.lstat();return {'sha256':sha(p),'size':s.st_size,'mode':stat.S_IMODE(s.st_mode),'uid':s.st_uid,'gid':s.st_gid,'mtimeNs':s.st_mtime_ns,'ctimeNs':s.st_ctime_ns,'inode':s.st_ino,'symlink':p.is_symlink()}
def read(p):return json.loads(p.read_text())
def put(n,v):
 with(O/n).open('x')as f:json.dump(v,f,indent=2);f.write('\n')
b=read(O/'baseline-receipt.json');assert sha(R/b['baseManifest'])==b['baseManifestSha256']and sha(R/b['priorSeal'])==b['priorSealSha256']
base=read(R/b['baseManifest']);prior=read(R/b['priorSeal']);protected={**base['protected'],**prior['files'],**b['sealSelfSnapshot']};assert len(protected)==13987
assert all((R/n).exists()and snap(R/n)==v for n,v in protected.items()),'Protected content/metadata changed'
hist=sorted(str(p.relative_to(R))for p in(R/'evidence').rglob('*')if p.is_file()and not p.is_relative_to(O)and not p.is_relative_to(P));assert hist==base['historicalEvidenceFiles']
receipt=read(O/'receipt.json');assert receipt['exit']==0 and receipt['temporaryTreeRemoved']and receipt['productionConnections']==receipt['productionChanges']==receipt['release']==receipt['rollout']==0
for n,h in receipt['sourceHashes'].items():assert sha(SRC/n)==h,'Tested source drift '+n
t=read(O/'tests.json');assert t['tests']==45 and t['failures']==t['errors']==0 and len(t['skipped'])==1
assert 'test_native_linux_proc'in t['skipped'][0]['test'];assert t['environment']['uid']!=0
for item in t['metrics']:
 result=item['result'];assert result['cleanupVerified']and result['retryCount']==0 and not result['networkExecutionEnabled']
 for w in result['workers'].values():assert w['reaped']
 if item['case']in ['cli-guest','cli-host']:
  assert result['status']=='PASS'
  for w in result['workers'].values():
   assert w['cpuSeconds']<=.25 and w['maxRssBytes']<=64*1024*1024 and w['stdoutBytes']<=32768
   assert w['record']['externalCommands']==w['record']['subprocesses']==0
   if item['case']=='cli-host':assert all(p['identity']>0 and p['timebase']['denom']>0 and p['cpuTimeSource'].startswith('proc_pid_rusage Mach')for p in w['record']['processes'])
 assert 'SYNTHETIC_SECRET'not in json.dumps(result)and 'SYNTHETIC_PRIVATE_COMM'not in json.dumps(result)
u=read(O/'native-unit-sanity.json');assert u['getrusageBeforeSeconds']-.01<=u['nativeConvertedCpuSeconds']<=u['getrusageAfterSeconds']+.01
assert u['timebase']=={'numer':125,'denom':3}
assert abs(u['nativeConvertedCpuSeconds']-u['rejectedPriorUnconvertedSeconds'])>.01
v=read(O/'verdict.json')['verdict'];assert v['ROOT_CAUSE']=='UNDETERMINED'and v['PRODUCTION_SAMPLER_OVERHEAD']==v['HOST_GUEST_REAL_SYNCHRONIZED_CAPTURE']=='NOT_TESTED'
assert v['ORIGINAL_EVIDENCE_INTEGRITY']=='FAILED'and v['FINAL_WIRED_CAPABILITY']=='14/16'and v['RELEASE_COUNT']==v['ROLLOUT_COUNT']==0
files=sorted(list(O.iterdir())+list(P.iterdir())+list(SRC.iterdir()));syntax=0
for p in files:
 assert p.is_file()and not p.is_symlink()and p.stat().st_nlink==1
 if p.suffix=='.py':compile(p.read_text(),str(p),'exec');syntax+=1
 if p.suffix=='.json':json.loads(p.read_text())
for name in ['sampler.py','sampler_mach_time.py']:
 tree=ast.parse((SRC/name).read_text());imports={n.name for x in ast.walk(tree)if isinstance(x,ast.Import)for n in x.names};assert not imports&{'subprocess','socket','requests','urllib','multiprocessing'}
for i in range(1,5):assert read(P/f'attempt{i}-receipt.json')['temporaryTreeRemoved']
if not(O/'verification.json').exists():put('verification.json',{'status':'PASS','at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'protectedCount':13987,'requiredPriorProtectedCount':13931,'priorRound13953Unchanged':True,'superseded34FilesUnchanged':True,'historicalEvidenceNamesUnchanged':True,'contentAndSpecifiedMetadataUnchanged':True,'currentTests':{'pass':44,'fail':0,'skip':1},'testedSourceHashesMatch':True,'cpuUnitCrossCheck':'VERIFIED_NATIVE_SELF_ONLY','localCleanupVerified':True,'temporaryTreesRemoved':True,'pythonSyntaxFiles':syntax,'realSshTests':0,'productionConnections':0,'originalEvidenceIntegrity':'FAILED'})
if not(O/'seal.json').exists():put('seal.json',{'files':{str(p.relative_to(R)):snap(p)for p in sorted(list(O.iterdir())+list(P.iterdir())+list(SRC.iterdir()))if p!=O/'seal.json'},'selfExcluded':True,'supersedesCompletionClaimOnly':'Earlier evidence and source content not rewritten','originalEvidenceIntegrity':'FAILED'})
seal=read(O/'seal.json');current={str(p.relative_to(R))for p in list(O.iterdir())+list(P.iterdir())+list(SRC.iterdir())if p!=O/'seal.json'}
assert set(seal['files'])==current and all(snap(R/n)==v for n,v in seal['files'].items()),'Final seal changed'
print(json.dumps({'status':'PASS','protected':13987,'sealedFiles':len(seal['files']),'tests':'44 PASS / 1 SKIP','nativeLinux':'NOT_TESTED','productionConnections':0,'release':0,'rollout':0}))
