"""Continue only the interrupted level check. No automatic retries or guard changes."""
import runpy,json
from pathlib import Path
HERE=Path(__file__).resolve().parent
m=runpy.run_path(str(HERE/'verify-behavior.py'));call=m['call'];settings=m['settings'];run=m['run'];save=m['save'];restart=m['restart']
initial=json.loads((HERE/'initial-config.json').read_text());records=[];facts=[]
try:
 for level in ['low','strict']:
  value=json.loads(json.dumps(initial['settings']));value['securityLevel']=level;c=settings(value);r=run('semgrep','controlled-finding');save('finding-'+level+'.json',r)
  assert r['state']=='COMPLETED' and r['evidenceClass']=='REAL' and r['policyDecision']=='FAIL' and r['evaluationCount']==1 and r['securityLevel']==level,r
  artifact=m['REPO']/r['source'];result=json.loads(artifact.read_text());config=json.loads((artifact.parent/'effective-config.json').read_text())
  assert result['policy']['securityLevel']==result['policy']['evaluation']['securityLevel']==config['securityLevel']==config['policyConfig']['securityLevel']==level
  assert result['oldGateDecision']=='FAIL' and result['policy']['effectivePolicy']['semgrep']['High']==('WARN'if level=='low'else'FAIL')
  facts.append(json.loads((artifact.parent/'semgrep.facts.json').read_text()));records.append(r)
  print(json.dumps({'level':level,'runId':r['runId'],'policy':r['policyDecision'],'digest':r['resultDigest']}),flush=True)
 assert facts[0]==facts[1]
finally:
 c=call('/api/config');restored=call('/api/config/reset',{'revision':c['revision']});assert restored['settings']==initial['settings'];restart();assert call('/api/config')==restored;save('restored-config.json',restored)
assert all(p['state']=='READY'for p in call('/api/plugins')['plugins'])
allruns=call('/api/runs')['runs']
for plugin in ['gitleaks','semgrep','cosign']:
 for decision in ['PASS','FAIL']:assert any(r['pluginId']==plugin and r['evidenceClass']=='REAL'and r['policyDecision']==decision for r in allruns)
for r in records+[json.loads((HERE/'reenabled-clean.json').read_text())]:assert call('/api/runs/'+r['runId'])==r
receipt={'disabledAllThreeNoRemoteExecution':True,'semgrepReenabled':json.loads((HERE/'reenabled-clean.json').read_text()),'securityLevelRuns':[{'runId':r['runId'],'level':r['securityLevel'],'policy':r['policyDecision'],'digest':r['resultDigest']}for r in records],'sameFindingFactsUnchanged':True,'ruleReason':'Existing mandatory FAIL is never weakened; effective severity maps differ, but this fixed high-risk finding remains FAIL.','policyEvaluationsPerRealRun':1,'configPersistsAfterRestart':True,'safeDefaultsRestored':restored['settings'],'finalRevision':restored['revision'],'threePluginHistoryPreserved':True,'earlierResourceBlockedAttemptRetained':True,'browserClick':'NOT_TESTED','release':0,'rollout':0}
save('behavior-acceptance.json',receipt);print(json.dumps(receipt),flush=True)
