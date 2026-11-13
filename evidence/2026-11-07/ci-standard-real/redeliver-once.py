"""Resend the authentic stored Push, never manually start Jenkins."""
import json,runpy
from pathlib import Path
OUT=Path(__file__).resolve().parent
p=runpy.run_path(str(Path.cwd()/'evidence/2026-11-05/gitlab-push-demo/preflight.py'))
code=p['PREFIX']+r'''
def demo=Jenkins.instance.getItemByFullName('security-gitlab-push-demo')
assert !demo.isBuilding() && demo.lastBuild.number==7 && demo.nextBuildNumber==8
assert demo.lastBuild.result.toString()=='FAILURE'
def ev=api('/projects/12/hooks/5/events?per_page=5').find{it.id==342}
assert ev && ev.response_status.toString()=='200'
def body=ev.request_data
if(body instanceof String)body=new JsonSlurper().parseText(body)
assert body.after=='d7faa2a512ff00b88ac3a3848fa71292b3095819' && body.project_id==12 && body.ref=='refs/heads/security-demo/gitlab-push-20261105'
assert api('/projects/12/hooks/5').push_events_branch_filter=='security-demo/gitlab-push-20261105'
def c=new URL('http://gitlab-service.ns-devops.svc.cluster.local/api/v4/projects/12/hooks/5/events/342/resend').openConnection()
c.setRequestProperty('PRIVATE-TOKEN',cred.password.plainText);c.connectTimeout=6000;c.readTimeout=12000;c.requestMethod='POST'
assert c.responseCode in [200,201,202,204]
println(JsonOutput.toJson([hookId:5,originalEventId:342,status:c.responseCode,requestBodyModified:false,newPush:false,jenkinsBuildApiCalled:false]))
'''
with (OUT/'redelivery-attempt.json').open('x') as f:json.dump({'storedEvent':342,'reason':'user approved one resend; fixed Groovy heredoc newline; #7 started no scan'},f)
r=p['script'](code)
with (OUT/'redelivery.json').open('x') as f:json.dump(r,f,indent=2)
print(json.dumps(r))
