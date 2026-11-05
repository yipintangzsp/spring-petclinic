"""Read-only current-round acceptance and content/metadata seal verification."""
from pathlib import Path
import sys,json,hashlib,stat,subprocess,re
sys.dont_write_bytecode=True
O=Path(__file__).resolve().parent;R=O.parents[2];sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest();read=lambda n:json.loads((O/n).read_text());base=read('protected-before.json')
for n,old in base['protected'].items():
 p=R/n;s=p.lstat();now={'sha256':sha(p),'size':s.st_size,'mode':stat.S_IMODE(s.st_mode),'uid':s.st_uid,'gid':s.st_gid,'mtimeNs':s.st_mtime_ns,'ctimeNs':s.st_ctime_ns,'inode':s.st_ino,'symlink':p.is_symlink()};assert now==old,'Protected content/metadata drift: '+n
history=sorted(str(p.relative_to(R))for p in(R/'evidence').rglob('*')if p.is_file()and not p.is_relative_to(O));assert history==base['historicalEvidenceFileList']
for n,h in base['approvedExistingChanges'].items():assert hashlib.sha256(subprocess.check_output(['git','show',base['head']+':'+n],cwd=R)).hexdigest()==h
for n,h in read('code-sha256.json').items():assert sha(R/n)==h,'Code hash: '+n
actual={str(p.relative_to(O)):sha(p)for p in O.rglob('*')if p.is_file()and p.name!='evidence-sha256.json'};assert actual==read('evidence-sha256.json'),'Current evidence seal drift'
assert all(v=='DENIED'for v in read('write-boundary-preflight.json')['checks'].values())
p=read('http-boundary-preflight.json');assert p['checks']=={'32185':'ok','32187':'ok','otherLoopback':'DENIED','external':'DENIED','protectedWrite':'DENIED'}and p['temporaryTreeRemoved']
t=read('tests-attempt5.json');assert t['tests']==t['pass']==299 and t['fail']==t['skipped']==0 and t['historicalContentMetadataUnchanged']and t['temporaryTreeRemoved']
for k in ['scannersStarted','consumerPolicyEvaluations','productionLokiPush','realDojoWrites']:assert t[k]==0
assert read('source-compatibility.json')['legacyRouterExactBytePrefixPreserved']
samples=read('sample-index.json');assert samples['sampleCount']==27 and not samples['secretLeakageDetected']and not samples['testLogCredentialLeakageDetected']
for row in samples['samples']:assert sha(O/row['file'])==row['sha256']
for p in O.glob('tests-attempt*.tap'):assert not re.search(r'SMV2_MOCK_TOKEN_[A-Za-z0-9_]{8,}',p.read_text())
q=read('logql-contract-samples-attempt5/offline-query-contract.json');assert q['realLokiQuery']=='NOT_TESTED'and q['realGrafanaImport']=='NOT_TESTED'and all(r['duplicateMetricsInvariant']for r in q['rows'])
p=read('production-comparison.json');assert all(p['checks'].values())and p['intermediateIncident']['present']and not p['intermediateIncident']['uninterruptedHealthVerified']and p['intermediateIncident']['rootCause']=='NOT_DETERMINED'
assert all(read('observability-comparison.json')['checks'].values())
v=read('verdict.json')['verdict'];assert v['ORIGINAL_EVIDENCE_INTEGRITY']=='FAILED'and v['FINAL_WIRED_CAPABILITY']=='14/16'and v['LOKI_REMOTE_EXACTLY_ONCE']=='NOT_VERIFIED'and v['GRAFANA_REAL_QUERY']=='NOT_TESTED'and v['RELEASE_COUNT']==v['ROLLOUT_COUNT']==0
print(json.dumps({'currentRoundSeal':'VERIFIED','protectedFiles':len(base['protected']),'historicalFileListUnchanged':True,'currentEvidenceFiles':len(actual),'codeFiles':len(read('code-sha256.json')),'tests':299,'samples':27,'originalEvidenceIntegrity':'FAILED','realLokiDelivery':'NOT_TESTED','realGrafanaQuery':'NOT_TESTED','productionFinalSnapshot':'VERIFIED','uninterruptedProductionHealth':'NOT_VERIFIED_INCIDENT_OBSERVED','push':0,'release':0,'rollout':0}))
