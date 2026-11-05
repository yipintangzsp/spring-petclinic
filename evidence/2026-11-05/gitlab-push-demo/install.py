"""Install only a new trusted inline Job and one exact-branch project webhook. Never starts builds."""
import hashlib,json,runpy,shlex,sys
from pathlib import Path
from urllib.parse import urlencode
from xml.etree import ElementTree as X
sys.dont_write_bytecode=True
OUT=Path(__file__).resolve().parent
ROOT=OUT.parents[2]
p=runpy.run_path(str(OUT/'preflight.py'))
plan=json.loads((OUT/'prepared.json').read_text())
name='security-gitlab-push-demo'
pipeline=(ROOT/'infra/jenkins/gitlab-push-demo/Pipeline.groovy').read_text().replace('@EXPECTED_COMMIT@',plan['commit'])
payload={'path':'/pipeline-model-converter/validate','method':'POST','type':'application/x-www-form-urlencoded',
 'body':urlencode({'jenkinsfile':pipeline}),'timeout':15000}
r=json.loads(p['m']['remote']('sudo -n kubectl exec -i -n ns-devops deploy/github-webhook-relay -- node --max-old-space-size=24 -e '+shlex.quote(p['NODE']),json.dumps(payload),25))
assert r['status']==200 and 'Jenkinsfile successfully validated' in r['body'],r['body'][:600]
cfg=X.Element('flow-definition')
X.SubElement(cfg,'description').text='Fixed project 12 / security-demo/gitlab-push-20261105 / trusted inline echo-only push verification. No SCM or executor.'
X.SubElement(cfg,'keepDependencies').text='false'
X.SubElement(cfg,'properties')
d=X.SubElement(cfg,'definition',{'class':'org.jenkinsci.plugins.workflow.cps.CpsFlowDefinition'})
X.SubElement(d,'script').text=pipeline;X.SubElement(d,'sandbox').text='true'
X.SubElement(cfg,'triggers');X.SubElement(cfg,'disabled').text='false'
xml=X.tostring(cfg,encoding='unicode')
code=p['PREFIX']+"""
import com.dabsquared.gitlabjenkins.GitLabPushTrigger
import com.dabsquared.gitlabjenkins.trigger.filter.BranchFilterType
import com.dabsquared.gitlabjenkins.connection.GitLabConnectionConfig
import java.security.MessageDigest
def hash={String s->MessageDigest.getInstance('SHA-256').digest(s.getBytes('UTF-8')).encodeHex().toString()}
assert hash(j.configFile.asString())=='abedd817048170dcf0833853d3820347341a91bd77501a77a2fcf10fb07a8f25'
assert Jenkins.instance.getDescriptorByType(GitLabConnectionConfig.class).useAuthenticatedEndpoint
assert Jenkins.instance.getItemByFullName('security-gitlab-push-demo')==null
assert api('/projects/12').path_with_namespace=='root/petclinic-platform'
assert api('/projects/12/hooks').every{it.url=='http://jenkins.ns-devops.svc.cluster.local:8080/project/petclinic-ci' && it.push_events_branch_filter=='main'}
assert !api('/projects/12/repository/branches?search=security-demo%2Fgitlab-push-20261105').any{it.name=='security-demo/gitlab-push-20261105'}
def job=Jenkins.instance.createProjectFromXML('security-gitlab-push-demo',new ByteArrayInputStream(@XML@.getBytes('UTF-8')))
def trigger=new GitLabPushTrigger()
trigger.setTriggerOnPush(true)
trigger.setTriggerOnMergeRequest(false)
trigger.setTriggerOnAcceptedMergeRequest(false)
trigger.setTriggerOnClosedMergeRequest(false)
trigger.setTriggerOnApprovedMergeRequest(false)
trigger.setTriggerOnNoteRequest(false)
trigger.setTriggerOnPipelineEvent(false)
trigger.setTriggerToBranchDeleteRequest(false)
trigger.setCiSkip(true)
trigger.setBranchFilterType(BranchFilterType.NameBasedFilter)
trigger.setIncludeBranchesSpec('security-demo/gitlab-push-20261105')
trigger.setExcludeBranchesSpec('')
byte[] random=new byte[32];new java.security.SecureRandom().nextBytes(random)
String secret=random.encodeHex().toString()
trigger.setSecretToken(secret)
job.addTrigger(trigger);trigger.start(job,true);job.save()
def hookData=[url:'http://jenkins.ns-devops.svc.cluster.local:8080/project/security-gitlab-push-demo',
 token:secret,push_events:true,push_events_branch_filter:'security-demo/gitlab-push-20261105',
 branch_filter_strategy:'wildcard',merge_requests_events:false,tag_push_events:false,pipeline_events:false,
 enable_ssl_verification:true]
def c=new URL('http://gitlab-service.ns-devops.svc.cluster.local/api/v4/projects/12/hooks').openConnection()
c.setRequestProperty('PRIVATE-TOKEN',cred.password.plainText);c.connectTimeout=6000;c.readTimeout=12000
c.requestMethod='POST';c.doOutput=true;c.setRequestProperty('Content-Type','application/json')
c.outputStream.withWriter('UTF-8'){it<<JsonOutput.toJson(hookData)}
assert c.responseCode==201:'Hook creation HTTP '+c.responseCode
def hook=new JsonSlurper().parseText(c.inputStream.text)
assert hook.push_events_branch_filter=='security-demo/gitlab-push-20261105'
assert hook.url==hookData.url && job.lastBuild==null
println(JsonOutput.toJson([job:job.fullName,jobUrl:'http://jenkins.devops.local/job/security-gitlab-push-demo/',
 pipelineSha256:hash(job.definition.script),sandbox:job.definition.sandbox,agent:'none',checkout:false,
 secretConfigured:trigger.secretToken?true:false,authenticationRequired:true,
 hook:[id:hook.id,url:hook.url,branch:hook.push_events_branch_filter,push:hook.push_events],
 productionJobSha256:hash(j.configFile.asString()),buildStarted:false]))
"""
result=p['script'](code.replace('@XML@',json.dumps(xml)))
with (OUT/'installed.json').open('x') as f:json.dump(result,f,indent=2)
print(json.dumps(result))
