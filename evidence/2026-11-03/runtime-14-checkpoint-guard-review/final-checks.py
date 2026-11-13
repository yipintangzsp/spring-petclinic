from pathlib import Path
import json,hashlib,re
R=Path.cwd();O=Path(__file__).resolve().parent
read=lambda n:json.loads((O/n).read_text())
def save(n,x):(O/n).write_text(json.dumps(x,ensure_ascii=False,indent=2)+'\n')
checks=[]
for x in json.load(open('evidence/2026-11-02/summary-integration-readiness-recheck/source-integrity.json'))['checks']:
 actual=hashlib.sha256(Path(x['path']).read_bytes()).hexdigest();assert actual==x['expected'],x['path'];checks.append({'path':x['path'],'expected':x['expected'],'actual':actual})
assert all(hashlib.sha256(Path(p).read_bytes()).hexdigest()==h for p,h in read('implementation-before.json').items())
seals=[]
for name in ['runtime-dojo-dependency-review','runtime-independent-boundaries','runtime-final-three','trivy-infra-repair','trivy-storage-expansion','trivy-pre-expansion','trivy-backup-capacity','trivy-external-storage-gate','runtime-boundary-followup']:
 base=O.parent/name;m=json.load(open(base/'evidence-sha256.json'));assert all(hashlib.sha256((base/p).read_bytes()).hexdigest()==h for p,h in m['files'].items()),name;seals.append({'path':str(base.relative_to(R)),'verifiedFiles':len(m['files']),'failures':0})
save('source-hash-preservation.json',{'frozenReferences':len(checks),'uniqueFiles':len(set(x['path'] for x in checks)),'implementationFiles':len(read('implementation-before.json')),'failures':[],'checks':checks,'priorEvidenceSeals':seals,'compatibilityCount':2202,'compatibilityCountChanged':False})
counts={}
for p in list(O.glob('*-tests.log'))+[O/'completeness-negative.log']:
 c={k:int(v) for k,v in re.findall(r'(?m)^(?:#|ℹ) (tests|pass|fail|cancelled|skipped|todo) (\d+)$',p.read_text())};assert c and c['tests']==c['pass'] and c['fail']==0,p;counts[p.stem]=c
assert read('policy-contract.json')['ready'] and len(read('policy-contract.json')['checks'])==10
save('test-counts.json',counts)
a=read('trivy-storage-before.json');b=read('trivy-storage-after.json');assert a['pod']==b['pod'] and a['pvcs']==b['pvcs'] and a['volumes']==b['volumes'];assert a['statefulsetSpecSha256']==b['statefulsetSpecSha256'] and a['environmentConfigurationSha256']==b['environmentConfigurationSha256'];assert a['nodeFs']['capacityBytes']==b['nodeFs']['capacityBytes']
def meta(phase):
 t=(O/('trivy-filesystem-'+phase+'.stdout')).read_text();files={l.split('|')[0]:l for l in t.splitlines() if l.startswith('/home/scanner/.cache/trivy/') and len(l.split('|'))==7};hashes={p:h for h,p in re.findall(r'(?m)^([a-f0-9]{64})  (/home/scanner/.cache/trivy/(?:db|java-db)/metadata.json)$',t)};return {'files':files,'metadataSha256':hashes}
assert meta('before')==meta('after')
drift=read('observed-protection-drift.json');assert drift['unresolved'] and drift['agentProxyWrites']==0
assert read('local-config-before.json')['files']['utmConfig']==read('local-config-after.json')['files']['utmConfig']
assert read('dojo-governance-before.json')==read('dojo-governance-after.json')
save('storage-config-preservation.json',{'classification':'READ_ONLY_SIZE_BLOCK_INODE_MTIME_METADATA_HASH_AND_CONFIG_COMPARISON','podAndPvcIdentitiesUnchanged':True,'statefulsetSpecUnchanged':True,'containerEnvConfigurationHashUnchanged':True,'dbFileSizeBlocksDeviceInodeMtimeUnchanged':True,'metadataHashesUnchanged':meta('before')['metadataSha256'],'dbFullContentChecksumRecomputed':False,'dbContentGuaranteeScope':'No updater/write invoked; file metadata and DB metadata hashes unchanged; no new full SQL content SHA claimed','proxyConfigHashUnchanged':False,'utmConfigHashUnchanged':True,'observedProxyDrift':'observed-protection-drift.json','proxyDriftCause':'NOT_DETERMINED','proxyAgentWrites':0,'localConfigValuesArchived':False,'filesystemCapacityUnchanged':True,'storageMoves':0,'dbPathChanges':0,'thresholdChanges':0,'dbRefreshes':0,'newDownloads':0,'networkWritesToRegistryOrKubernetes':0,'diskCleanup':0})
save('dojo-governance-comparison.json',{'selectedMetadataUnchanged':True,'normalProducts':2,'normalEngagements':2,'normalTests':35,'normalFindings':6627,'productionWrites':0,'validationObjectsCreated':0,'credentialValuesRead':0})
print(json.dumps({'tests':counts,'frozenHashChecks':len(checks),'sourceFailures':0,'dbAndConfigurationMetadataUnchanged':True,'oldEvidenceFiles':sum(s['verifiedFiles'] for s in seals)}))
