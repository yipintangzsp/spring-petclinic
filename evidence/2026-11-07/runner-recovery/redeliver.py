"""Resend the authentic stored Push, never manually start Jenkins."""
import json,runpy
from pathlib import Path
OUT=Path(__file__).resolve().parent
p=runpy.run_path(str(Path.cwd()/'evidence/2026-11-05/gitlab-push-demo/preflight.py'))
code=p['PREFIX']+r'''
def demo=Jenkins.instance.getItemByFullName('security-gitlab-push-demo')
assert !demo.isBuilding() && demo.lastBuild.number==9 && demo.nextBuildNumber==10
assert demo.lastBuild.result.toString()=='FAILURE'
def ev=api('/projects/12/hooks/5/events?per_page=5').find{it.id==344}
assert ev && ev.response_status.toString()=='200'
def body=ev.request_data
if(body instanceof String)body=new JsonSlurper().parseText(body)
assert body.after=='a69104ba1bf88b74cc57a420888ee692b88c8c48' && body.project_id==12 && body.ref=='refs/heads/security-demo/gitlab-push-20261105'
assert api('/projects/12/hooks/5').push_events_branch_filter=='security-demo/gitlab-push-20261105'
def c=new URL('http://gitlab-service.ns-devops.svc.cluster.local/api/v4/projects/12/hooks/5/events/344/resend').openConnection()
c.setRequestProperty('PRIVATE-TOKEN',cred.password.plainText);c.connectTimeout=6000;c.readTimeout=12000;c.requestMethod='POST'
assert c.responseCode in [200,201,202,204]
println(JsonOutput.toJson([hookId:5,originalEventId:344,status:c.responseCode,requestBodyModified:false,newPush:false,jenkinsBuildApiCalled:false]))
'''
assert json.loads((OUT/'preflight.json').read_text())['fixed700']['valid'] and json.loads((OUT/'negative-tests.json').read_text())['newScans']==0
with (OUT/'redelivery-attempt.json').open('x') as f:json.dump({'storedEvent':344,'reason':'user approved one NEW recovery execution; old #9 remains ERROR UNKNOWN'},f)
r=p['script'](code)
with (OUT/'redelivery.json').open('x') as f:json.dump(r,f,indent=2)
print(json.dumps(r))
