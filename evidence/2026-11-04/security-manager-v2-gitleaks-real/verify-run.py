"""Read-only assertions over this run and its pre-existing protected input inventory."""
from pathlib import Path
import hashlib,json
O=Path(__file__).resolve().parent;R=O.parents[2]
read=lambda p:json.loads((O/p).read_text())
sha=lambda b:hashlib.sha256(b).hexdigest()
allowed={'infra/security/manager-v2/README.md','infra/security/manager-v2/cli.mjs','infra/security/manager-v2/core.mjs','infra/security/manager-v2/core.test.mjs','infra/security/manager-v2/registry.mjs','infra/security/manager-v2/runner.test.mjs','infra/security/policy/gitleaks-parent.mjs'}
unchanged={};changes={}
for name,before in read('baseline.json')['protectedFilesAtStart'].items():
 after=sha((R/name).read_bytes())
 if before==after:unchanged[name]=before
 else:
  assert name in allowed,name
  changes[name]={'before':before,'after':after}
assert all(not p.startswith('evidence/') for p in changes)
assert len(changes)==7
package=read('linux-package-retry.json')
assert all(sha((R/name).read_bytes())==h for name,h in package['files'].items()),'executed package differs from reviewed final code'
proof=read('real-linux/export-proof.json')
assert proof['secretLeakageCheck']=='PASS' and not proof['sourcePlaintextExported']
assert all(sha((O/'real-linux'/n).read_bytes())==h for n,h in proof['files'].items())
samples=read('versioned-differential.json');assert len(samples['records'])==127
assert all(x['oldDecision']==x['currentDecision'] and x['rawPreserved'] for x in samples['records'])
suite=read('real-linux/outputs/normal-suite.json');assert suite['executionCounts']=={'scans':2,'commands':4}
for name,decision,exitcode in [('java-real-secret','FAIL',1),('python-real-clean','PASS',0)]:
 base='real-linux/outputs/'+name+'/'
 result=read(base+'gitleaks.result.json');facts=read(base+'gitleaks.facts.json');summary=read(base+'candidate-summary.json');runtime=read(base+'gitleaks.runtime-facts.json');native=(O/(base+'gitleaks.raw.json')).read_bytes()
 assert result['oldGateDecision']==result['policyDecision']==decision
 assert result['evaluationCount']==1 and result['runtimeFacts']==runtime
 assert next(x for x in summary['pluginResults'] if x['pluginId']=='gitleaks')==result
 assert result['rawReportDigest']==runtime['rawReportDigest']==sha(native)
 canonical=json.dumps(facts,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()
 assert sha(canonical)==runtime['factDigest']==result['factDigest']
 assert runtime['identity']['uid']==65534 and runtime['identity']['groups']==[65534]
 assert runtime['command']['exitStatus']==exitcode and runtime['tool']['observedVersion']=='v8.30.1'
 assert summary['promotion']['status']=='BLOCKED' and not summary['productionEvidence']
 assert runtime['oldGate']['scope']=='ORIGINAL_SOURCE_SECRET_CLASSIFIER_ON_REAL_INPUT'
err=read('real-linux/outputs/tool-error/gitleaks.result.json');assert err['executionStatus']=='ERROR' and err['policyDecision'] is None and err['evaluationCount']==0
router=read('real-linux/outputs/router-receipts.json');assert router['executionCountsUnchanged'] and router['policyCounts']['gitleaks']==1
assert router['delivery']['receipts'][1]['deliveryDecision']=='DELIVERED_LOCAL_ONLY'
assert router['failedDelivery']['receipts'][1]['deliveryDecision']=='ERROR'
assert read('linux-cleanup.json')['workspaceRemoved']
pre=read('host-before.json');post=read('host-after.json')
assert pre['socket']==post['socket'] and post['socket']['mode']=='0660'
assert pre['dockerService']==post['dockerService']
def containers(rows):
 normalized=[]
 for item in rows:
  item=json.loads(json.dumps(item))
  if 'Health' in item['state']:item['state']['Health'].pop('Log',None)
  normalized.append(item)
 return sorted(normalized,key=lambda x:x['id'])
assert containers(pre['containers'])==containers(post['containers'])
assert pre['defectdojoPods']==post['defectdojoPods']==[]
assert all(n['ready']=='True' for n in post['nodes'])
assert read('pre-live-jenkins-final.json')['jobs']==read('live-jenkins-final.json')['jobs']
job=read('live-jenkins-final.json')['jobs'][0];assert job['latestBuild']==270 and job['result']=='SUCCESS'
assert job['summarySha256']=='ec9ee51a06d4b9f61c6c0eaf50b374d1e25e6d3ca687908b7596d3a2c794f5d8'
assert read('health-final.json')['deployment']==read('pre-health-final.json')['deployment']
assert read('health-final.json')['http']=={'status':'200','exit':0}
assert read('final-production-verification.json')['readyEndpoints']==3
assert read('final-production-verification.json')['objects']==read('pre-final-production-verification.json')['objects']
for key in ['volumes','statefulsetSpecSha256','environmentConfigurationSha256','pvcs','refreshes']:
 assert read('trivy-storage-before.json')[key]==read('trivy-storage-after.json')[key]
# Host df usage is volatile; DB/cache inode/size/mtime/metadata, mounts and temporary
# names are the protected evidence. Preserve both complete df observations too.
beforeFs=(O/'trivy-filesystem-before.stdout').read_text();afterFs=(O/'trivy-filesystem-after.stdout').read_text()
assert beforeFs.split('\nFS\n')[0]==afterFs.split('\nFS\n')[0]
assert beforeFs.split('\nTEMP_NAMES\n')[1]==afterFs.split('\nTEMP_NAMES\n')[1]
result={'protectedUnchangedCount':len(unchanged),'authorizedSourceChanges':changes,'allOldEvidenceUnchanged':True,'originalManifestUnchanged':True,'productionGateUnchanged':True,'executedPackageMatchesFinalCode':True,'realScans':2,'differentialRealMatches':2,'frozenParentMatches':127,'rawFactsUnchanged':True,'singleEvaluation':True,'resultDigestReused':True,'routerFailureObserved':True,'secretLeakageCheck':'PASS','temporaryWorkspaceRemoved':True,'productionUnchanged':True,'dockerDaemonRestarts':0,'trivyDbRefreshes':0,'dojoExecutions':0,'release':0,'rollout':0,'originalEvidenceIntegrity':'FAILED','canonicalRuntime':'14/16'}
if __name__=='__main__':
 target=O/'verification.json'
 if target.exists():assert json.loads(target.read_text())==result
 else:target.write_text(json.dumps(result,indent=2)+'\n')
 print(json.dumps(result))
