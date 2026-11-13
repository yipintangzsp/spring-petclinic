"""Freeze a new epoch once, then take five read-only samples over 120 seconds."""
from pathlib import Path
import json,datetime,subprocess,time
from epoch_proxy import sha,capture,validate_samples
O=Path(__file__).resolve().parent;R=O.parents[2];P=O.parent/'runtime-14-checkpoint-guard-review'
def save(n,x):(O/n).write_text(json.dumps(x,ensure_ascii=False,indent=2)+'\n')
def ref(p):return {'path':str(p.relative_to(R)),'sha256':sha(p.read_bytes())}
if (O/'epoch-start.json').exists():raise SystemExit('REFUSE_EPOCH_RESTART')
old=json.load(open(P/'checkpoint.json'));assert old['authoritativeAcceptance']=='FAILED'
sources=json.load(open(O/'implementation-before.json'))
for p,h in sources.items():assert sha((R/p).read_bytes())==h,p
for p,h in old['frozenGateHashes'].items():assert sha((R/p).read_bytes())==h,p
code=['proxy-contract.json','epoch_proxy.py','epoch_engine.py','start_epoch.py','finish_epoch.py','verify-old-checkpoint.mjs','epoch_proxy_test.py','epoch_engine_test.py','epoch_live_integrity_test.py']
for name in code:sources[str((O/name).relative_to(R))]=sha((O/name).read_bytes())
hist={k:ref(p) for k,p in {'checkpoint':P/'checkpoint.json','oldHashes':P/'local-config-before.json','oldDrift':P/'observed-protection-drift.json','oldAcceptance':P/'checkpoint-integrity.json','driftReport':O.parent/'runtime-proxy-drift-review/REPORT-43.md','historyRecoveryReport':O.parent/'runtime-proxy-history-recovery/REPORT-43.md','archiveDeltaReport':O.parent/'runtime-proxy-history-delta/REPORT-43.md','archiveSearch':O.parent/'runtime-proxy-history-delta/large-archive-results.json'}.items()}
previous=json.load(open(O.parent/'runtime-proxy-history-delta/source-hash-preservation.json'))['oldSeals'];seals=[]
for b in [R/s['path'] for s in previous]+[O.parent/'runtime-proxy-history-delta']:
 m=json.load(open(b/'evidence-sha256.json'))
 for p,h in m['files'].items():assert sha((b/p).read_bytes())==h,(b.name,p)
 seals.append(ref(b/'evidence-sha256.json'))
hist['priorSeals']=seals
run=json.load(open(O/'run.json'));start={'epochId':run['epochId'],'createdAt':datetime.datetime.now(datetime.timezone.utc).isoformat(),'gitRevision':subprocess.check_output(['git','rev-parse','HEAD'],cwd=R,text=True).strip(),'gitBranch':subprocess.check_output(['git','branch','--show-current'],cwd=R,text=True).strip(),'historicalContinuity':'NOT_PROVEN','newEpochBaseline':'CURRENT_STATE_ONLY','historicalFailedCheckpointRefs':hist,'immutableImplementationCount':len(sources),'authorization':{'attachmentSha256':sha(Path('/Users/zhangsir/.codex/attachments/8043e2e1-4cf1-4d6a-a6b5-067ad345a8fe/已粘贴的文本.txt').read_bytes()),'scope':'Explicit user authorization to establish a new CURRENT_STATE_ONLY epoch; no proxy/production mutation'}}
save('source-hash-matrix.json',{'implementationHashes':sources,'existingImplementationCount':77,'newEpochToolingFiles':len(code),'frozenGateHashes':old['frozenGateHashes'],'frozenGateReferences':455,'frozenGateUniqueFiles':229,'collector':old['collector'],'owner':old['owner'],'authoritativePolicyOwner':old['authoritativePolicyOwner'],'projection':old['projection'],'policyBaseline':old['policyBaseline'],'canonicalSourceManifest':old['sourceManifest'],'v1Producer':old['v1SummaryProducer'],'compatibilitySamplesUnchanged':2202})
save('epoch-start.json',start)
contract=json.load(open(O/'proxy-contract.json'));samples=[];begin=time.monotonic();folder=O/'samples';folder.mkdir(exist_ok=False)
for i in range(5):
 deadline=begin+i*contract['observation']['intervalSeconds']
 while time.monotonic()<deadline:time.sleep(min(1,deadline-time.monotonic()))
 s=capture('T'+str(i),contract);samples.append(s);save('samples/T'+str(i)+'.json',s)
 print(json.dumps({'sample':s['sample'],'status':s['status'],'at':s['startedAt'],'runtimeHash':s.get('files',{}).get('runtime',{}).get('rawSha256'),'semanticDigest':s.get('proxySemanticDigest'),'errorCode':s.get('errorCode')}),flush=True)
save('stability-result.json',validate_samples(samples,contract))
print(json.dumps({'epochId':run['epochId'],'stability':validate_samples(samples,contract)}),flush=True)
