"""Validate the current-round seal without rewriting historical evidence."""
from pathlib import Path
import sys,json,hashlib,stat,subprocess
sys.dont_write_bytecode=True
O=Path(__file__).resolve().parent;R=O.parents[2];sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest();base=json.loads((O/'protected-before.json').read_text())
for n,old in base['protected'].items():
 p=R/n;s=p.lstat();now={'sha256':sha(p),'size':s.st_size,'mode':stat.S_IMODE(s.st_mode),'uid':s.st_uid,'gid':s.st_gid,'mtimeNs':s.st_mtime_ns,'ctimeNs':s.st_ctime_ns,'inode':s.st_ino,'symlink':p.is_symlink()};assert now==old,'Protected content/metadata drift: '+n
history=sorted(str(p.relative_to(R))for p in(R/'evidence').rglob('*')if p.is_file()and not p.is_relative_to(O));assert history==base['historicalEvidenceFileList']
for n,h in base['approvedExistingChanges'].items():assert hashlib.sha256(subprocess.check_output(['git','show',base['head']+':'+n],cwd=R)).hexdigest()==h
for n,h in json.loads((O/'code-sha256.json').read_text()).items():assert sha(R/n)==h,'Code hash: '+n
manifest=json.loads((O/'evidence-sha256.json').read_text());actual={str(p.relative_to(O)):sha(p)for p in O.rglob('*')if p.is_file()and p.name!='evidence-sha256.json'};assert actual==manifest,'New evidence seal drift'
read=lambda n:json.loads((O/n).read_text())
assert all(v=='DENIED' for v in read('write-boundary-preflight.json')['checks'].values())
p=read('http-boundary-preflight.json');assert p['checks']['approvedLoopback']==200 and p['checks']['external']=='DENIED' and p['checks']['otherLoopback']=='DENIED' and p['temporaryTreeRemoved']
for name,n in [('tests-attempt4.json',210),('tests-attempt5.json',59)]:
 t=read(name);assert t['pass']==t['tests']==n and t['fail']==0 and t['temporaryTreeRemoved'] and t['historicalContentMetadataUnchanged']
schema=read('api-schema-attempt5.json');assert schema['actualMultipartPayloadsChecked']==27 and schema['descriptionInputUnsupportedAndNotSent']
r=read('router-compatibility.json');assert r['defaultConsumersIdentical'] and r['protectedContentAndMetadataUnchanged'] and len(r['cases'])==5 and all(c['offlineDojoIdentical'] for c in r['cases'])
assert all(read('production-comparison.json')['checks'].values())
samples=read('sample-index.json');assert samples['sampleCount']==15 and not samples['secretLeakageDetected']
for record in samples['samples']:assert sha(O/record['file'])==record['sha256']
assert 'SMV2_MOCK_TOKEN_DISPOSABLE_NOT_REAL_123456789' not in ''.join((O/x['file']).read_text()for x in samples['samples'])
v=read('VERDICT.json')['verdict'];assert v['ORIGINAL_EVIDENCE_INTEGRITY']=='FAILED' and v['FINAL_WIRED_CAPABILITY']=='14/16' and v['DEFECTDOJO_REAL_REMOTE_DELIVERY']=='NOT_TESTED' and v['DEFECTDOJO_API_COMPATIBILITY']=='INCOMPLETE' and v['DEFECTDOJO_NONPROD_PRODUCT']=='UNKNOWN' and v['DEFECTDOJO_NONPROD_IDENTITY']=='NOT_READY'
assert read('real-delivery-authorization.json')['realDeliveryApproval']=='NOT_GRANTED'
print(json.dumps({'newRoundSeal':'VERIFIED_LOCAL_MOCK_HTTP_SCOPE_ONLY','protectedFiles':len(base['protected']),'historicalFileListUnchanged':True,'relatedRegressionTests':153,'finalHTTPTests':59,'distinctTests':212,'legacyRouterDirectComparisons':20,'finalProtocolSamples':15,'actualMultipartSchemaSamples':27,'realDojoWrites':0,'realRemoteDelivery':'NOT_TESTED','remoteIdempotency':'NOT_TESTED','nonprodReadiness':'NOT_READY','originalEvidenceIntegrity':'FAILED','runtime':'14/16','release':0,'rollout':0}))
