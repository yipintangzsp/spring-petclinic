"""Read-only execution/credential metadata check; never binds a key or pushes Git."""
import json
import runpy
from pathlib import Path
OUT=Path(__file__).resolve().parent
PRIOR=OUT.parents[1]/'2026-11-05'
p=runpy.run_path(str(PRIOR/'gitlab-push-demo/preflight.py'))
code=p['PREFIX']+r'''
import com.cloudbees.plugins.credentials.common.StandardCredentials
import hudson.security.ACL
import java.security.MessageDigest
def hash={byte[] v->MessageDigest.getInstance('SHA-256').digest(v).encodeHex().toString()}
def demo=Jenkins.instance.getItemByFullName('security-gitlab-push-demo')
def creds=CredentialsProvider.lookupCredentialsInItem(StandardCredentials.class,demo,ACL.SYSTEM2,[]).collect{c->
 [id:c.id,type:c.class.name,scope:c.scope?.toString(),username:c.hasProperty('username')?c.username:null]
}
def user=api('/user')
def b=demo.lastBuild
def bindings=(demo.definition.script =~ /credentialsId:s*['"]([^'"]+)['"]/).collect{it[1]}.unique()
def hooks=api('/projects/12/hooks').collect{[id:it.id,url:it.url,push:it.push_events,branch:it.push_events_branch_filter]}
println(JsonOutput.toJson([observedAt:new Date().format("yyyy-MM-dd'T'HH:mm:ssXXX",TimeZone.getTimeZone('UTC')),
 demo:[name:demo.fullName,lastBuild:b.number,result:b.result?.toString(),building:demo.isBuilding(),definitionSha256:hash(demo.configFile.file.bytes),
 boundCredentialIds:bindings,hasGitOpsStage:demo.definition.script.contains('GitOps'),
 hasEchoOnlyDemoPublish:demo.definition.script.contains('no image, GitOps or deployment action'),sandbox:demo.definition.sandbox],
 availableCredentialMetadata:creds,readOnlyGitlabIdentity:[username:user.username,isAdmin:user.is_admin],
 triggerBranchHead:api('/projects/12/repository/branches/security-demo%2Fgitlab-push-20261105').commit.id,
 gitopsBranchHead:api('/projects/12/repository/branches/security-demo%2Fgitops-20261105').commit.id,
 main:api('/projects/12/repository/branches/main').commit.id,hooks:hooks,
 production:[lastBuild:j.lastBuild.number,result:j.lastBuild.result?.toString(),definitionSha256:hash(j.configFile.file.bytes),
 summarySha256:hash(new File(j.getBuildByNumber(270).artifactsDir,'.devsecops/security-summary.json').bytes)],
 writes:0,buildsStarted:0]))
'''
jenkins=p['script'](code)
host=r'''
import json,subprocess,pwd,pathlib,datetime,hashlib,os,urllib.request,urllib.error
def k(a):return json.loads(subprocess.check_output(['kubectl']+a,text=True,timeout=10))
a=k(['-n','argocd','get','application','petclinic-gitops-demo','-o','json'])
cm=k(['-n','devsecops-test','get','configmap','petclinic-gitops-demo','-o','json'])
d=k(['-n','petclinic','get','deployment','petclinic','-o','json'])
pa=k(['-n','argocd','get','application','petclinic','-o','json'])
nodes=k(['get','nodes','-o','json'])
keys=pathlib.Path('/var/lib/security-gitleaks/.ssh/authorized_keys').read_text().splitlines()
prefixes=[line.split(' ssh-ed25519 ',1)[0] for line in keys if line.strip()]
base=pathlib.Path('/var/tmp/security-manager-gitleaks-v2-linux-20261105')
entry=(base/'ssh-entry.py').read_text()
possible=[]
for directory in ['/usr/local/bin','/usr/local/sbin','/opt']:
 path=pathlib.Path(directory)
 if path.exists():possible += [str(q) for q in path.iterdir() if any(term in q.name.lower() for term in ['gitops','git-write','git-push'])]
try:
 with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(urllib.request.Request('http://192.168.64.11/',headers={'Host':'petclinic.devops.local'}),timeout=5) as r:http=r.status
except urllib.error.HTTPError as e:http=e.code
except (OSError,urllib.error.URLError):http='UNAVAILABLE'
sha=lambda v:hashlib.sha256(json.dumps(v,sort_keys=True).encode()).hexdigest()
print(json.dumps({'observedAt':datetime.datetime.now(datetime.timezone.utc).isoformat(),
 'gitopsDemo':{'applicationUid':a['metadata']['uid'],'source':a['spec']['source'],'destination':a['spec']['destination'],'syncPolicy':a['spec']['syncPolicy'],
 'revision':a['status']['sync']['revision'],'sync':a['status']['sync']['status'],'health':a['status']['health']['status'],'resources':a['status'].get('resources',[]),
 'configMapUid':cm['metadata']['uid'],'resourceVersion':cm['metadata']['resourceVersion'],'data':cm['data']},
 'restrictedAccount':{'uid':pwd.getpwnam('security-gitleaks').pw_uid,'forcedCommandRestrictions':prefixes,'entrySha256':hashlib.sha256(entry.encode()).hexdigest(),
 'entryMentionsGitPush':any(t in entry for t in ['git push','git-receive-pack','gitops']),
 'possibleExistingGitOpsEntrypoints':possible,'securityOrGitOpsAccountNames':[u.pw_name for u in pwd.getpwall() if 'gitops' in u.pw_name or u.pw_name.startswith('security-')]},
 'production':{'uid':d['metadata']['uid'],'generation':d['metadata']['generation'],'specSha256':sha(d['spec']),'ready':d['status'].get('readyReplicas',0),'desired':d['spec']['replicas'],
 'image':[v['image'] for v in d['spec']['template']['spec']['containers']],'argoRevision':pa['status']['sync']['revision'],'argoSync':pa['status']['sync']['status'],'argoHealth':pa['status']['health']['status'],
 'argoSpecSha256':sha(pa['spec']),'http':http,'nodes':{v['metadata']['name']:next(c['status'] for c in v['status']['conditions'] if c['type']=='Ready') for v in nodes['items']},'dockerSocketMode':format(os.stat('/run/docker.sock').st_mode&511,'04o')},'writes':0}))
'''
state=json.loads(p['m']['remote']('sudo -n python3 -',host,55))
previous=json.loads((PRIOR/'gitops-real/verified.json').read_text())['host']
assert state['gitopsDemo']['applicationUid']=='14cddc81-ea96-4789-ba3d-268423a876d9'
assert state['gitopsDemo']['configMapUid']==previous['demo']['configMapUid']
assert state['gitopsDemo']['data']=={'demo-stage':'baseline'}
result={'jenkins':jenkins,'host':state}
with (OUT/'preflight.json').open('x') as f:json.dump(result,f,indent=2)
print(json.dumps(result))
