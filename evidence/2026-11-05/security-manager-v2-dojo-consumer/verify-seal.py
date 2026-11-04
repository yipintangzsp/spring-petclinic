"""New round byte/metadata seal; no historical recovery or status upgrades."""
from pathlib import Path
import hashlib,json,stat,subprocess,sys
sys.dont_write_bytecode=True
O=Path(__file__).resolve().parent;R=O.parents[2];sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest();base=json.loads((O/'protected-before.json').read_text())
for n,old in base['protected'].items():
 p=R/n;s=p.lstat();now={'sha256':sha(p),'size':s.st_size,'mode':stat.S_IMODE(s.st_mode),'uid':s.st_uid,'gid':s.st_gid,'mtimeNs':s.st_mtime_ns,'ctimeNs':s.st_ctime_ns,'inode':s.st_ino,'symlink':p.is_symlink()};assert now==old,'Protected content/metadata drift: '+n
history=sorted(str(p.relative_to(R))for p in(R/'evidence').rglob('*')if p.is_file()and not p.is_relative_to(O));assert history==base['historicalEvidenceFileList'],'Historical file list changed'
for n,old in base['approvedExistingChanges'].items():assert hashlib.sha256(subprocess.check_output(['git','show',base['head']+':'+n],cwd=R)).hexdigest()==old['sha256']
code=json.loads((O/'code-sha256.json').read_text());assert all(sha(R/n)==h for n,h in code.items()),'Code changed after seal'
pre=json.loads((O/'write-boundary-preflight.json').read_text());assert all(v=='DENIED'for v in pre['checks'].values())
tests=json.loads((O/'tests-attempt4.json').read_text());assert tests['pass']==tests['tests']==153 and tests['fail']==0 and tests['temporaryTreeRemoved']and tests['contentAndMetadataUnchanged']
samples=json.loads((O/'sample-generation.json').read_text());assert samples['sampleCases']==9 and samples['httpRequests']==0 and samples['temporaryTreeRemoved'];assert all(sha(O/'samples'/n)==h['sha256']for n,h in samples['files'].items())
parser=json.loads((O/'parser-compatibility-isolated.json').read_text());assert len(parser['checks'])==16 and len(parser['negativeChecks'])==2 and parser['temporaryTreeRemoved'] and parser['importAPI']=='NOT_TESTED'
compat=json.loads((O/'router-compatibility.json').read_text());assert len(compat['cases'])==5 and compat['defaultConsumersIdentical']and compat['temporaryTreeRemoved']
assert all(json.loads((O/'production-comparison.json').read_text())['checks'].values())
v=json.loads((O/'VERDICT.json').read_text())['verdict'];assert v['ORIGINAL_EVIDENCE_INTEGRITY']=='FAILED'and v['FINAL_WIRED_CAPABILITY']=='14/16'and v['DEFECTDOJO_REMOTE_DELIVERY']=='NOT_TESTED'
sealed=json.loads((O/'evidence-sha256.json').read_text());actual={str(p.relative_to(O)):sha(p)for p in O.rglob('*')if p.is_file()and p.name!='evidence-sha256.json'};assert sealed==actual,'Current evidence seal mismatch'
print(json.dumps({'newRoundSeal':'VERIFIED_SCOPED_OFFLINE_ONLY','protectedContentAndMetadataFiles':len(base['protected']),'historicalFileListUnchanged':True,'tests':153,'routerComparisons':15,'adapterSampleCases':9,'genericPayloads':16,'parserNegativeCases':2,'consumerPolicyEvaluations':0,'newScans':0,'remoteDelivery':'NOT_TESTED','remoteIdempotency':'NOT_TESTED','cosignFindingMapping':'UNSUPPORTED','originalEvidenceIntegrity':'FAILED','canonicalRuntime':'14/16','release':0,'rollout':0}))
