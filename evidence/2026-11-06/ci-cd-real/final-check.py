"""Final exact-commit, protected receipt ledger and unchanged production verification."""
from common import *
cd=json.loads((OUT/'result.json').read_text());prep=json.loads((OUT/'prepared.json').read_text())
up=cd['update']['afterCommit'];rev=cd['restore']['afterCommit']
code=p['PREFIX']+r'''
import java.security.MessageDigest
def hash={byte[] v->MessageDigest.getInstance('SHA-256').digest(v).encodeHex().toString()}
def paths=['@UPDATE@','@RESTORE@'].collect{sha->def c=api('/projects/12/repository/commits/'+sha);def d=api('/projects/12/repository/commits/'+sha+'/diff');assert d.size()==1 && d[0].new_path=='infra/devops-lab/gitops-demo/configmap.yaml';[commit:c.id,parents:c.parent_ids,message:c.message,paths:d.collect{it.new_path}]}
assert paths[1].parents==['@UPDATE@']&&paths[1].message.contains('This reverts commit @UPDATE@')
assert api('/projects/12/repository/branches/security-demo%2Fgitops-20261105').commit.id=='@RESTORE@'
assert api('/projects/12/repository/branches/main').commit.id=='340ef4b8c74e3c2a5820da8d98b0f134283bb8d9'
assert j.lastBuild.number==270&&j.lastBuild.result.toString()=='SUCCESS'
assert hash(j.configFile.file.bytes)=='abedd817048170dcf0833853d3820347341a91bd77501a77a2fcf10fb07a8f25'
assert hash(new File(j.getBuildByNumber(270).artifactsDir,'.devsecops/security-summary.json').bytes)=='ec9ee51a06d4b9f61c6c0eaf50b374d1e25e6d3ca687908b7596d3a2c794f5d8'
println(JsonOutput.toJson([gitopsCommits:paths,productionJenkins270:'SUCCESS',productionJobUnchanged:true,v1SummaryUnchanged:true,mainUnchanged:true,firstAttempt5:Jenkins.instance.getItemByFullName('security-gitlab-push-demo').getBuildByNumber(5).result.toString()]))
'''.replace('@UPDATE@',up).replace('@RESTORE@',rev)
j=script(code)
host=r'''
import json,pathlib,subprocess,hashlib,os,datetime,urllib.request,urllib.error,stat
def k(a):return json.loads(subprocess.check_output(['kubectl']+a,text=True,timeout=10))
cm=k(['-n','devsecops-test','get','configmap','petclinic-gitops-demo','-o','json']);a=k(['-n','argocd','get','application','petclinic-gitops-demo','-o','json'])
assert cm['data']=={'demo-stage':'baseline'} and a['status']['sync']['revision']=='@RESTORE@' and a['status']['sync']['status']=='Synced' and a['status']['health']['status']=='Healthy'
ledger=json.loads(pathlib.Path('/var/lib/security-gitops-demo/state/@NONCE@.json').read_text())
assert ledger['state']=='RESTORED' and ledger['runId']=='@RUN@' and ledger['resultDigest']=='@DIGEST@' and ledger['afterCommit']=='@RESTORE@'
proof=pathlib.Path('/var/lib/security-gitops-demo-proofs/@NONCE@.json');st=proof.stat()
assert st.st_uid==24021 and st.st_gid==24022 and stat.S_IMODE(st.st_mode)==0o440 and st.st_nlink==1
d=k(['-n','petclinic','get','deployment','petclinic','-o','json']);pa=k(['-n','argocd','get','application','petclinic','-o','json']);nodes=k(['get','nodes','-o','json'])
assert d['metadata']['generation']==175 and hashlib.sha256(json.dumps(d['spec'],sort_keys=True).encode()).hexdigest()=='123ad729d83f3a7afc548a8c3071be70ff7ac8ed78b7333a296945b525552f4b'
assert pa['status']['sync']['revision']=='340ef4b8c74e3c2a5820da8d98b0f134283bb8d9' and hashlib.sha256(json.dumps(pa['spec'],sort_keys=True).encode()).hexdigest()=='00e16a65e6d0ae9743afee12d8d71ceb525d93cd514abc7fa90ae88cc0d49c3a'
try:
 with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(urllib.request.Request('http://192.168.64.11/',headers={'Host':'petclinic.devops.local'}),timeout=5) as r:http=r.status
except urllib.error.HTTPError as e:http=e.code
except (OSError,urllib.error.URLError):http='UNAVAILABLE'
assert d['status'].get('readyReplicas')==3 and http==200
ready={v['metadata']['name']:next(c['status'] for c in v['status']['conditions'] if c['type']=='Ready') for v in nodes['items']};assert all(v=='True' for v in ready.values())
assert stat.S_IMODE(os.stat('/run/docker.sock').st_mode)==0o660
print(json.dumps({'observedAt':datetime.datetime.now(datetime.timezone.utc).isoformat(),'serverLedger':ledger,'proofOwnership':{'uid':st.st_uid,'gid':st.st_gid,'mode':'0440','nlink':st.st_nlink},
 'demo':{'revision':a['status']['sync']['revision'],'sync':a['status']['sync']['status'],'health':a['status']['health']['status'],'value':cm['data']['demo-stage'],'uid':cm['metadata']['uid'],'resourceVersion':cm['metadata']['resourceVersion']},
 'production':{'ready':3,'http':http,'nodes':ready,'argoSync':pa['status']['sync']['status'],'argoHealth':pa['status']['health']['status'],'unchanged':True,'dockerSocket':'0660'}}))
'''
for key,val in {'RESTORE':rev,'NONCE':cd['gateReceipt']['receiptId'],'RUN':cd['runId'],'DIGEST':cd['resultDigest']}.items():host=host.replace('@'+key+'@',val)
h=remote(host,55);save('final-check.json',{'gitlab':j,'host':h});print(json.dumps({'gitlab':j,'host':h}))
