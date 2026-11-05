"""Read-only seal verification; no remote calls and no history-writing runners."""
from pathlib import Path
import json,hashlib,stat,sys,subprocess
sys.dont_write_bytecode=True
O=Path(__file__).resolve().parent;R=O.parents[2];read=lambda n:json.loads((O/n).read_text());sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest();base=read('protected-before.json')
for n,expected in base['protected'].items():
 p=R/n;s=p.lstat();actual={'sha256':sha(p),'size':s.st_size,'mode':stat.S_IMODE(s.st_mode),'uid':s.st_uid,'gid':s.st_gid,'mtimeNs':s.st_mtime_ns,'ctimeNs':s.st_ctime_ns,'inode':s.st_ino,'symlink':p.is_symlink()};assert actual==expected,'Historical file drift: '+n
history=sorted(str(p.relative_to(R))for p in(R/'evidence').rglob('*')if p.is_file()and not p.is_relative_to(O));assert history==base['historicalEvidenceFileList'],'Historical list drift'
actual={str(p.relative_to(O)):sha(p)for p in O.rglob('*')if p.is_file()and p.name!='evidence-sha256.json'};assert actual==read('evidence-sha256.json'),'Current evidence seal drift'
for p in O.glob('*.py'):compile(p.read_text(),str(p),'exec')
p=read('write-boundary-preflight.json');assert all(x=='DENIED'for x in p['checks'].values())and p['temporaryDirectoryRemoved']and p['canaryContentMtimeModeUnchanged']
a=read('analysis.json');assert all(a['productionComparison'].values());assert len(a['pods'])==3 and all(p['sameUidAsBefore']and p['restartDelta']==1 and p['lastTerminated']['exitCode']==143 for p in a['pods']);assert a['rolloutProof']['actualPetclinicRolloutCount']==0 and a['rolloutProof']['containerRestarts']==3
assert any(x['conditionCounts']=={'false':3}for x in a['endpointObservedTransitions']);assert any(x['conditionCounts']=={'true':3}for x in a['endpointObservedTransitions'][1:]);assert any(x['labels'].get('instance')=='10.0.0.3:9100'and x['max']>=98 for x in a['statistics']['node-load'])
assert any('PLEG is not healthy'in x['message']for x in a['nodeLogExcerpts']);assert any(x['message']=='Updated sync status: Synced -> Unknown'for x in a['argo']);assert any(x['message']=='Updated sync status: Unknown -> Synced'for x in a['argo'])
local=read('local-host.json');assert not local['matchingTestProcesses']and not local['remainingTemporaryTrees'];assert any(x['devopsUuidMatches']for x in local['qemuLinkage'])
logs=read('runtime-logs.json');assert next(x['entryCount']for x in logs['lokiQueries']if x['name']=='petclinic')==341
for n in ['inventory.json','journal.json','prometheus.json','prometheus-followup.json','focused-metrics-attempt2.json','containerd.json','runtime-logs.json','coverage-network.json']:assert read(n)['productionMutations']==0
v=read('verdict.json')['verdict'];assert v['ROOT_CAUSE']=='UNDETERMINED'and v['LOKI_CANDIDATE_TEST_CAUSALITY']=='UNKNOWN'and v['PRODUCTION_FIX_EXECUTED']=='NO'and v['ROLLOUT_COUNT']==v['RELEASE_COUNT']==0 and v['ORIGINAL_EVIDENCE_INTEGRITY']=='FAILED'
assert read('read-only-scope.json')['productionMutationsInitiated']==0
print(json.dumps({'seal':'VERIFIED','protectedFiles':len(base['protected']),'historicalEvidenceFileListUnchanged':True,'sealedEvidenceFiles':len(actual),'offlineAssertions':'PASS','productionMutationsInitiated':0,'scannersExecuted':0,'actualPetclinicRollouts':0,'containerRestartsDuringIncident':3,'rootCause':'UNDETERMINED','currentProductionSnapshot':'HEALTHY','originalEvidenceIntegrity':'FAILED','push':0}))
