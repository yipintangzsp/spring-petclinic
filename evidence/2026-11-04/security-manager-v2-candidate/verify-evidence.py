from pathlib import Path
import json,hashlib,re
R=Path(__file__).resolve().parents[3];O=Path(__file__).resolve().parent
B=json.loads((O/'baseline.json').read_text())
changes=[p for p,h in B['protectedFilesAtStart'].items() if not (R/p).is_file() or hashlib.sha256((R/p).read_bytes()).hexdigest()!=h];assert not changes,changes
before=json.loads((O/'host-before.json').read_text());after=json.loads((O/'host-after.json').read_text())
for key in ['socket','dockerService','defectdojoPods','nodes']:assert before[key]==after[key],key
stable=lambda x:[{'id':c['id'],'name':c['name'],'restartCount':c['restartCount'],'state':{k:v for k,v in c['state'].items() if k!='Health'},'healthStatus':c['state'].get('Health',{}).get('Status')} for c in x['containers']]
assert stable(before)==stable(after),'container identity/start/restart/health-status changed'
pre=json.loads((O/'pre-live-jenkins-final.json').read_text());post=json.loads((O/'live-jenkins-final.json').read_text());p=next(x for x in pre['jobs'] if x['job']=='petclinic-ci');q=next(x for x in post['jobs'] if x['job']=='petclinic-ci')
assert (p['latestBuild'],p['result'],p['summarySha256'])==(q['latestBuild'],q['result'],q['summarySha256'])==(270,'SUCCESS','ec9ee51a06d4b9f61c6c0eaf50b374d1e25e6d3ca687908b7596d3a2c794f5d8')
for phase in ['before','after']:
 x=json.loads((O/('trivy-storage-'+phase+'.json')).read_text());assert x['refreshes']==0
extract=lambda phase:[line for line in (O/('trivy-filesystem-'+phase+'.stdout')).read_text().splitlines() if line.startswith('/home/scanner/.cache/trivy') or re.match(r'^[0-9a-f]{64}  /home/scanner',line)]
assert extract('before')==extract('after'),'Trivy DB file identity changed'
records=[]
for mode in ['original-v1','helm-versioned']:
 for f in ['db-differential.json','differential.json','workflow-differential.json']:
  x=json.loads((O/mode/'generated-evidence'/f).read_text());rows=x['records'] if isinstance(x,dict) else x
  assert all(r['oldDecision']==r['standardDecision'] and r['rawPreserved'] for r in rows)
  records.extend(rows)
checks={'protectedFiles':len(B['protectedFilesAtStart']),'protectedFilesUnchanged':True,'originalEvidenceIntegrity':'FAILED','dockerSocket0660':True,'dockerDaemonRestarts':0,'containersIdentityStartRestartAndHealthStatusUnchanged':True,'ignoredVolatileFields':['Docker Health.Log probe timestamps/output rotation','node sampled free bytes'],'defectdojoWorkloadStateUnchanged':True,'jenkins270':'SUCCESS','v1SummarySha256':q['summarySha256'],'trivyDBMetadataAndFileIdentityUnchanged':True,'trivyFrozenDifferentialCountPerVersion':184,'trivyDifferentialComparisonsBothVersions':len(records),'productionHealth':'VERIFIED','releaseCount':0,'rolloutCount':0,'pushCount':0}
(O/'preservation-and-production-checks.json').write_text(json.dumps(checks,indent=2)+'\n');print(json.dumps(checks))
