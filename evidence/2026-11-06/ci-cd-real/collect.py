"""Collect same-build archived receipts and verify their original digests."""
from common import *
import base64,hashlib
prep=json.loads((OUT/'prepared.json').read_text())
code=p['PREFIX']+r'''
def b=Jenkins.instance.getItemByFullName('security-gitlab-push-demo').getBuildByNumber(@BUILD@)
assert !b.building && b.result.toString()=='SUCCESS'
assert b.causes.size()==1 && b.causes.first().class.name=='com.dabsquared.gitlabjenkins.cause.GitLabWebHookCause'
assert b.causes.first().data.after=='@COMMIT@'
def names=['evidence/jenkins-gitleaks-receipt.json','evidence/jenkins-gitops-receipt.json','evidence/artifact/gitleaks.result.json']
def files=names.collectEntries{name->def f=new File(b.artifactsDir,name);assert f.exists() && f.length()<262144;[(name):f.bytes.encodeBase64().toString()]}
def log=b.getLog(1000).join('\n')
assert log.contains('GITLEAKS_REAL_GATE PASS')&&log.contains('GITOPS_UPDATED_COMMIT')&&log.contains('GITOPS_REVERT_COMMIT')&&log.contains('CI_CD_VERIFIED')
println(JsonOutput.toJson([build:b.number,result:b.result.toString(),files:files,startedAt:b.timeInMillis,duration:b.duration,cause:[type:b.causes.first().class.name,after:b.causes.first().data.after,branch:b.causes.first().data.sourceBranch]]))
'''.replace('@BUILD@',str(prep['allowedBuild'])).replace('@COMMIT@',prep['triggerCommit'])
r=script(code)
def digest(v):return hashlib.sha256(json.dumps(v,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()).hexdigest()
files={name:json.loads(base64.b64decode(data)) for name,data in r.pop('files').items()}
gate=files['evidence/jenkins-gitleaks-receipt.json'];cd=files['evidence/jenkins-gitops-receipt.json'];raw=files['evidence/artifact/gitleaks.result.json']
for receipt in [gate,cd]:assert digest({k:v for k,v in receipt.items() if k!='receiptDigest'})==receipt['receiptDigest']
assert digest({k:v for k,v in raw.items() if k!='resultDigest'})==raw['resultDigest']==gate['resultDigest']==cd['resultDigest']
assert gate['runId']==cd['runId']==raw['runId'] and gate['evaluationCount']==raw['evaluationCount']==1
assert gate['policyDecision']==cd['policyDecision']==raw['policyDecision']=='PASS' and gate['scannerExitCode']==0
assert cd['status']=='SUCCESS' and cd['updated']['verified'] and cd['restored']['verified']
assert cd['updated']['value']=='updated' and cd['restored']['value']=='baseline'
assert cd['updated']['argoRevision']==cd['update']['afterCommit'] and cd['restored']['argoRevision']==cd['restore']['afterCommit']
assert cd['updated']['configMapUid']==cd['restored']['configMapUid'] and cd['updated']['resourceVersion']!=cd['restored']['resourceVersion']
assert cd['gateReceipt']['receiptId']==gate['gateReceipt']['receiptId'] and cd['update']['receiptId']==cd['restore']['receiptId']==cd['gateReceipt']['receiptId']
save('gate-result.json',gate);save('result.json',cd);r.update({'runId':gate['runId'],'policy':'PASS','resultDigest':gate['resultDigest'],'gateReceiptServerVerified':True,'policyEvaluations':1,'updateCommit':cd['update']['afterCommit'],'restoreCommit':cd['restore']['afterCommit']})
save('verified.json',r);print(json.dumps(r))
