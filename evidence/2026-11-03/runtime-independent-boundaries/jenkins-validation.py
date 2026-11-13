"""Manage ONLY the dedicated, non-release runtime-facts validation job."""
from pathlib import Path
import sys,json,subprocess,shlex,urllib.parse,base64
sys.dont_write_bytecode=True
sys.path.insert(0,'/Users/zhangsir/code/evidence/platform-20261011')
from jenkins_control import NODE
R=Path(__file__).resolve().parents[3];O=Path(__file__).resolve().parent
job='security-runtime-facts-20261102'
if sys.argv[1] in ['create-and-run','update-and-run']:
    pipeline=(R/'Jenkinsfile.runtime-facts').read_text()
    script='''
import groovy.json.JsonOutput
import org.jenkinsci.plugins.workflow.job.WorkflowJob
import org.jenkinsci.plugins.workflow.cps.CpsFlowDefinition
def name=%s
def exists=Jenkins.instance.getItemByFullName(name)
if(%s && exists!=null)throw new IllegalStateException('Refusing to change existing job')
if(exists?.lastBuild?.building)throw new IllegalStateException('Dedicated validation job still running')
def j=exists ?: Jenkins.instance.createProject(WorkflowJob,name)
j.setDescription('Dedicated controlled non-release validation; scoped test identities and authorized read-only service discovery only. No Summary V2, approval, promotion or production rollout.')
j.setDefinition(new CpsFlowDefinition(new String(java.util.Base64.decoder.decode('%s'),'UTF-8'),true));j.save()
def q=j.scheduleBuild2(0)
println(JsonOutput.toJson([job:j.fullName,scheduled:q!=null,definition:'DEDICATED_NONRELEASE_ONLY',productionJobModified:false]))
'''%(json.dumps(job),'true' if sys.argv[1]=='create-and-run' else 'false',base64.b64encode(pipeline.encode()).decode())
    name='jenkins-dedicated-r2-trigger.json' if sys.argv[1]=='update-and-run' else 'jenkins-created.json'
else:
    script=r'''
import groovy.json.JsonOutput
import groovy.json.JsonSlurperClassic
def j=Jenkins.instance.getItemByFullName(%s),b=j?.lastBuild
def artifacts=[:]
def artifactHashes=[:]
def regression=[]
if(b&&!b.building)b.artifacts.findAll{it.relativePath.startsWith('.devsecops/runtime-controlled/')&&it.relativePath.endsWith('.json')}.each{a->
 def f=new File(b.artifactsDir,a.relativePath);if(f.isFile()){artifacts[a.relativePath]=new JsonSlurperClassic().parseText(f.getText('UTF-8'));artifactHashes[a.relativePath]=java.security.MessageDigest.getInstance('SHA-256').digest(f.bytes).encodeHex().toString()}
}
if(b&&!b.building)b.artifacts.findAll{it.relativePath.startsWith('.devsecops/runtime-controlled/')&&it.relativePath.endsWith('/regression.log')}.each{a->
 def f=new File(b.artifactsDir,a.relativePath);if(f.isFile()){
  def text=f.getText('UTF-8'),counts=[:]
  (text=~/(?m)^(?:#|ℹ) (tests|pass|fail|cancelled|skipped|todo) (\d+)$/).each{m->counts[m[1]]=m[2].toInteger()}
  regression.add([path:a.relativePath,counts:counts,sha256:java.security.MessageDigest.getInstance('SHA-256').digest(text.getBytes('UTF-8')).encodeHex().toString()])
 }
}
println(JsonOutput.toJson([job:j?.fullName,build:b?.number,building:b?.building,result:b?.result?.toString(),duration:b?.duration,startedAtMs:b?.startTimeInMillis,artifacts:artifacts,artifactHashes:artifactHashes,regression:regression,definitionSha256:java.security.MessageDigest.getInstance('SHA-256').digest(j.definition.script.getBytes('UTF-8')).encodeHex().toString(),consoleTail:b?.getLog(45),productionJobModified:false]))
'''%json.dumps(job)
    name='jenkins-validation-state.json'
payload={'path':'/scriptText','method':'POST','type':'application/x-www-form-urlencoded','body':urllib.parse.urlencode({'script':script}),'timeout':45000}
ssh=['ssh','-o','BatchMode=yes','-o','ConnectTimeout=6','-o','StrictHostKeyChecking=yes','-o','HostName=192.168.64.11','-o','HostKeyAlias=192.168.1.58','zhang@192.168.1.58']
command='sudo -n kubectl exec -i -n ns-devops deploy/github-webhook-relay -- node --max-old-space-size=24 -e '+shlex.quote(NODE)
p=subprocess.run(ssh+[command],input=json.dumps(payload),capture_output=True,text=True,timeout=60)
if p.returncode:raise SystemExit('Trusted SSH failed: '+p.stderr[-600:])
response=json.loads(p.stdout)
if response['status']!=200:raise SystemExit('Jenkins HTTP '+str(response['status']))
try:data=json.loads(response['body'].split('\n',1)[0])
except Exception:
    (O/'jenkins-api-error.txt').write_text(response['body'][:2000]);raise SystemExit('Jenkins script failed; bounded evidence retained')
(O/name).write_text(json.dumps(data,indent=2)+'\n')
print(json.dumps({k:v for k,v in data.items() if k not in ['artifacts','artifactHashes','consoleTail']}))
if 'consoleTail' in data:print('\n'.join(data['consoleTail'][-20:]))
