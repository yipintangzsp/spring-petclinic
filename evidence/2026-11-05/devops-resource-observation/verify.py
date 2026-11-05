"""Offline verification only. Seal once; subsequent invocations verify, never overwrite."""
from pathlib import Path
import json,hashlib,stat,datetime,sys
O=Path(__file__).resolve().parent;R=O.parents[2]
def sha(p):
 h=hashlib.sha256()
 with p.open('rb')as f:
  for b in iter(lambda:f.read(1024*1024),b''):h.update(b)
 return h.hexdigest()
def snap(p):
 s=p.lstat();return {'sha256':sha(p),'size':s.st_size,'mode':stat.S_IMODE(s.st_mode),'uid':s.st_uid,'gid':s.st_gid,'mtimeNs':s.st_mtime_ns,'ctimeNs':s.st_ctime_ns,'inode':s.st_ino,'symlink':p.is_symlink()}
def put(n,x):
 with(O/n).open('x')as f:json.dump(x,f,indent=2);f.write('\n')
read=lambda n:json.loads((O/n).read_text())
b=read('protected-before.json');assert len(b['protected'])==13931
changed=[]
for n,v in b['protected'].items():
 p=R/n
 if not p.exists()or snap(p)!=v:changed.append(n)
assert not changed,changed[:10]
historical=sorted(str(p.relative_to(R)) for p in(R/'evidence').rglob('*')if p.is_file()and not p.is_relative_to(O))
assert historical==b['historicalEvidenceFileList'],'Historical evidence names changed'
syntax=0;js=0
for p in O.iterdir():
 assert not p.is_symlink() and p.is_file() and p.stat().st_nlink==1,p.name
 if p.suffix=='.py':compile(p.read_text(),str(p),'exec');syntax+=1
 if p.suffix=='.json':json.loads(p.read_text());js+=1
r=read('observation-receipt.json');s=read('sample-00.json');a=read('analysis.json');v=read('verdict.json')['verdict'];w=read('write-boundary-preflight.json')
assert r['sampleCount']==1 and r['stoppedEarly']and r['actualDurationSeconds']<30
assert set(r['stopReasons'])=={'GUEST_SAMPLER_OVERHEAD_BUDGET','HOST_SAMPLER_OVERHEAD_BUDGET'}
assert r['productionMutations']==r['remoteFilesCreated']==r['securityScans']==r['release']==r['rollout']==0
assert not r['newDaemonOrAgent']
assert all(x=='DENIED'for x in w['checks'].values())and w['canaryContentMtimeModeUnchanged']and w['temporaryDirectoryRemoved']
assert w['historicalWriteProbes']==w['historicalDeleteProbes']==0
assert s['guest']['readyPetclinicCount']==3 and s['guest']['http']['status']==200
assert all(any(c['type']=='Ready'and c['status']=='True'for c in n['conditions'])for n in s['guest']['nodes'])
assert s['guest']['argo']['sync']=='Synced'and s['guest']['argo']['health']=='Healthy'
assert a['currentHealth']['podUidsAndRestartsUnchangedFromRCA']
assert all(c['image'].endswith('sha256:489cb821573ff1f98edd846d5949d74bf3391b24e2f1fe5bcfb71c6be0793137')for p in s['guest']['petclinicPods']for c in p['containers'])
assert v['ORIGINAL_EVIDENCE_INTEGRITY']=='FAILED'and v['ROOT_CAUSE']=='UNDETERMINED'and v['NODE_CPU_PRESSURE_OBSERVATION']=='INCOMPLETE'
assert v['FINAL_WIRED_CAPABILITY']=='14/16'and v['RELEASE_COUNT']==v['ROLLOUT_COUNT']==0
assert len(a['historicalStatistics'])==12 and len(a['currentProcessContainerJoin'])==29
assert sum(p['association']=='CGROUP_UID_MATCH'for p in a['currentProcessContainerJoin'])==20
assert [x for x in a['historicalStatistics']if x['queryName']=='runnable'][0]['series'][0]['max']==68
assert [x for x in a['historicalStatistics']if x['queryName']=='blocked'][0]['series'][0]['max']==1
if not(O/'verification.json').exists():
 put('verification.json',{'classification':'OFFLINE_REAL_EVIDENCE_VERIFICATION_NOT_NEW_RUNTIME','at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'result':'PASS','protectedFileCount':len(b['protected']),'protectedContentAndMetadataUnchanged':True,'historicalEvidenceNameCount':len(historical),'historicalEvidenceNamesUnchanged':True,'pythonSyntaxFiles':syntax,'parsedJsonFilesBeforeSeal':js,'currentProcessRecords':29,'cgroupPodUidJoins':20,'historicalQueries':12,'earlyStopVerified':True,'productionMutationCallsInCollector':0,'productionHealthAsOf':s['guest']['completedAt'],'noFreshSamplingInVerification':True,'originalEvidenceIntegrity':'FAILED','scopeCaution':'Source-backed offline assertions, not a new production availability test.'})
if not(O/'evidence-sha256.json').exists():put('evidence-sha256.json',{'classification':'NEW_ROUND_CONTENT_AND_METADATA_SEAL','files':{p.name:snap(p)for p in sorted(O.iterdir())if p.is_file()and p.name!='evidence-sha256.json'},'selfExcluded':True,'originalEvidenceIntegrity':'FAILED'})
seal=read('evidence-sha256.json');assert set(seal['files'])=={p.name for p in O.iterdir()if p.is_file()and p.name!='evidence-sha256.json'}
assert all(snap(O/n)==v for n,v in seal['files'].items()),'New round seal mismatch'
print(json.dumps({'result':'PASS','protectedFiles':len(b['protected']),'sealedCurrentFiles':len(seal['files']),'historicalNames':len(historical),'originalEvidenceIntegrity':'FAILED','productionMutations':0}))
