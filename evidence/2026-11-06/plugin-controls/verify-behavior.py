"""Only requested HTTP config behavior and three tiny real Semgrep scans."""
import json,pathlib,urllib.request,time,subprocess,runpy,sys,copy
HERE=pathlib.Path(__file__).resolve().parent;REPO=HERE.parents[2];BASE='http://security.devops.local:17862'
op=urllib.request.build_opener(urllib.request.ProxyHandler({}));api=runpy.run_path(str(REPO/'evidence/2026-11-05/security-manager-v2-loki/inspect-production.py'))
def save(n,x):
 with (HERE/n).open('x')as f:json.dump(x,f,indent=2);f.write('\n')
def call(path,body=None):
 headers={}
 if body is not None:
  token=json.load(op.open(BASE+'/api/plugins',timeout=8))['csrfToken'];headers={'Origin':BASE,'Content-Type':'application/json','X-CSRF-Token':token}
 with op.open(urllib.request.Request(BASE+path,data=json.dumps(body).encode() if body is not None else None,headers=headers),timeout=8)as r:return json.load(r)
def settings(value):
 c=call('/api/config');return call('/api/config',{'revision':c['revision'],'settings':value})
def run(plugin,scenario):
 r=call('/api/run',{'pluginId':plugin,'scenarioId':scenario});print(json.dumps({'submitted':r['runId'],'plugin':plugin,'scenario':scenario}),flush=True)
 for _ in range(65):
  x=call('/api/runs/'+r['runId'])
  if x['state'] not in ['RUNNING','QUEUED']:break
  time.sleep(.5)
 return x
def restart():subprocess.run(['node','infra/security/manager-v2/view/control.mjs','restart'],cwd=REPO,check=True,capture_output=True,text=True,timeout=12)
def remote_outputs():
 script="""import pathlib,json
roots=['/var/tmp/security-manager-gitleaks-v2-linux-20261105','/var/tmp/security-manager-gitleaks-semgrep-web-20261106','/var/tmp/security-manager-gitleaks-cosign-web-20261106']
print(json.dumps({r:sorted(p.name for p in (pathlib.Path(r)/'outputs').iterdir())for r in roots}))
"""
 return json.loads(api['remote']('sudo -n python3 -',script,timeout=20))
def main():
 initial=call('/api/config');assert initial['settings']['enabled'] and initial['settings']['securityLevel']=='standard' and all(p['enabled'] for p in initial['settings']['plugins'].values())
 save('initial-config.json',initial)
 before=remote_outputs();disabled=copy.deepcopy(initial['settings'])
 for v in disabled['plugins'].values():v['enabled']=False
 c=settings(disabled);save('disabled-config.json',c)
 blocked=[]
 for plugin in ['semgrep','gitleaks','cosign']:
  r=run(plugin,'clean');assert r['state']=='DISABLED' and r['scannerExecuted'] is False and r['remoteInvocationCount']==0 and r['evaluationCount']==0 and r['policyDecision'] is None,r
  blocked.append(r)
 after=remote_outputs();assert before==after
 save('disabled-results.json',{'records':blocked,'remoteOutputsUnchanged':True,'remoteBefore':before,'remoteAfter':after})
 restart();assert call('/api/config')==c
 for r in blocked:assert call('/api/runs/'+r['runId'])==r
 assert all(p['state']=='DISABLED' for p in call('/api/plugins')['plugins'])
 save('disabled-restart-persistence.json',{'revision':c['revision'],'settingsPreserved':True,'disabledRecordsPreserved':True})
 print('DISABLED verified: zero remote invocations, zero new Linux output runs; persists across restart',flush=True)
 c=settings(initial['settings']);r=run('semgrep','clean')
 assert r['state']=='COMPLETED' and r['evidenceClass']=='REAL' and r['policyDecision']=='PASS' and r['securityLevel']=='standard' and r['evaluationCount']==1,r
 assert r['configurationSnapshot']['revision']==c['revision'];save('reenabled-clean.json',r)
 print(json.dumps({'reenabledRunId':r['runId'],'policy':r['policyDecision'],'digest':r['resultDigest']}),flush=True)
 levels=[];facts=[]
 for level in ['low','strict']:
  s=copy.deepcopy(initial['settings']);s['securityLevel']=level;c=settings(s);r=run('semgrep','controlled-finding')
  assert r['state']=='COMPLETED' and r['evidenceClass']=='REAL' and r['policyDecision']=='FAIL' and r['evaluationCount']==1 and r['securityLevel']==level,r
  artifact=REPO/r['source'];result=json.loads(artifact.read_text());config=json.loads((artifact.parent/'effective-config.json').read_text())
  assert result['policy']['securityLevel']==result['policy']['evaluation']['securityLevel']==config['securityLevel']==level
  assert config['policyConfig']['securityLevel']==level
  assert result['oldGateDecision']=='FAIL'
  assert result['policy']['effectivePolicy']['semgrep']['High']==('WARN' if level=='low' else 'FAIL')
  facts.append(json.loads((artifact.parent/'semgrep.facts.json').read_text()))
  levels.append(r);save('finding-'+level+'.json',r)
  print(json.dumps({'securityLevel':level,'actualPolicy':r['policyDecision'],'runId':r['runId'],'digest':r['resultDigest']}),flush=True)
 assert facts[0]==facts[1],'Same fixed finding facts must be preserved across Policy levels'
 c=call('/api/config');restored=call('/api/config/reset',{'revision':c['revision']});assert restored['settings']==initial['settings'];restart();assert call('/api/config')==restored
 assert all(p['state']=='READY' for p in call('/api/plugins')['plugins'])
 for r in [r for r in levels]+[json.loads((HERE/'reenabled-clean.json').read_text())]:assert call('/api/runs/'+r['runId'])==r
 allruns=call('/api/runs')['runs']
 for plugin in ['gitleaks','semgrep','cosign']:
  for decision in ['PASS','FAIL']:assert any(r['pluginId']==plugin and r['evidenceClass']=='REAL' and r['policyDecision']==decision for r in allruns)
 save('restored-config.json',restored)
 receipt={'verifiedAt':time.strftime('%Y-%m-%dT%H:%M:%S%z'),'disabledAllThreeNoRemoteExecution':True,'semgrepReenabled':json.loads((HERE/'reenabled-clean.json').read_text()),'securityLevelInputs':[r['securityLevel']for r in levels],'securityLevelDecisions':[r['policyDecision']for r in levels],'sameFindingFactsUnchanged':True,'ruleReason':'Existing mandatory FAIL is never weakened; levels have different effective severity maps but this frozen high-risk fixture remains FAIL.','policyEvaluationsPerRealRun':1,'configPersistsAfterRestart':True,'safeDefaultsRestored':restored['settings'],'finalRevision':restored['revision'],'threePluginHistoryPreserved':True,'browserClick':'NOT_TESTED','release':0,'rollout':0}
 save('behavior-acceptance.json',receipt);print(json.dumps(receipt),flush=True)

if __name__=='__main__':main()
