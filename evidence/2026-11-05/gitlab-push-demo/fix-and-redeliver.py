"""Fix only the demo's plugin compatibility; request GitLab to resend the original stored event."""
import hashlib,json,runpy
from pathlib import Path
OUT=Path(__file__).resolve().parent;ROOT=OUT.parents[2]
p=runpy.run_path(str(OUT/'preflight.py'))
plan=json.loads((OUT/'prepared.json').read_text())
prior=json.loads((OUT/'installed.json').read_text())
observed=json.loads((OUT/'observed.json').read_text())
compat=json.loads((OUT/'cause-compatibility.json').read_text())
delivery=compat['delivery'][0]['id']
assert delivery==336 and observed['build']['number']==1 and observed['build']['result']=='FAILURE'
assert "Cannot get property 'sourceProjectId' on null object" in observed['build']['console']
pipeline=(ROOT/'infra/jenkins/gitlab-push-demo/Pipeline.groovy').read_text().replace('@EXPECTED_COMMIT@',plan['commit']).replace('@EXPECTED_REPOSITORY@',compat['variables']['gitlabSourceRepoHttpUrl'])
assert '@EXPECTED_' not in pipeline
code=p['PREFIX']+"""
import org.jenkinsci.plugins.workflow.cps.CpsFlowDefinition
import java.security.MessageDigest
def hash={String s->MessageDigest.getInstance('SHA-256').digest(s.getBytes('UTF-8')).encodeHex().toString()}
def demo=Jenkins.instance.getItemByFullName('security-gitlab-push-demo')
assert !demo.isBuilding() && demo.lastBuild.number==1 && demo.lastBuild.result.toString()=='FAILURE'
assert hash(demo.definition.script)=='@OLD_HASH@'
def h=api('/projects/12/hooks/5')
assert h.push_events_branch_filter=='security-demo/gitlab-push-20261105'
assert h.url=='http://jenkins.ns-devops.svc.cluster.local:8080/project/security-gitlab-push-demo'
def oldEvent=api('/projects/12/hooks/5/events?per_page=5').find{it.id==336}
assert oldEvent!=null
def body=oldEvent.request_data
if(body instanceof String)body=new JsonSlurper().parseText(body)
assert body.after=='@SHA@' && body.ref=='refs/heads/security-demo/gitlab-push-20261105' && body.project_id==12
demo.definition=new CpsFlowDefinition(@PIPELINE@,true);demo.save()
assert demo.triggers.values().size()==1 && demo.triggers.values().first().includeBranchesSpec=='security-demo/gitlab-push-20261105'
def c=new URL('http://gitlab-service.ns-devops.svc.cluster.local/api/v4/projects/12/hooks/5/events/336/resend').openConnection()
c.setRequestProperty('PRIVATE-TOKEN',cred.password.plainText);c.connectTimeout=6000;c.readTimeout=12000;c.requestMethod='POST'
assert c.responseCode in [200,201,202,204]:'Stored-event redelivery HTTP '+c.responseCode
println(JsonOutput.toJson([onlyDemoDefinitionChanged:true,pipelineSha256:hash(demo.definition.script),
 gitlabStoredEventRedelivery:[hookId:5,originalEventId:336,status:c.responseCode,requestBodyModified:false],
 newGitPushInvocations:0,jenkinsBuildApiCalled:false,firstFailurePreserved:true]))
"""
for k,v in {'OLD_HASH':prior['pipelineSha256'],'SHA':plan['commit'],'PIPELINE':json.dumps(pipeline)}.items():code=code.replace('@'+k+'@',v)
with (OUT/'redelivery-attempt2.json').open('x') as f:json.dump({'hookId':5,'storedEventId':336,'newPush':False,'reason':'demo cause.data projection compatibility fix'},f,indent=2)
r=p['script'](code)
with (OUT/'redelivery.json').open('x') as f:json.dump(r,f,indent=2)
print(json.dumps(r))
