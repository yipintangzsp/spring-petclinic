"""Resend the authentic stored Push, never manually start Jenkins."""
import json,runpy
from pathlib import Path
OUT=Path(__file__).resolve().parent
p=runpy.run_path(str(OUT.parent/'gitlab-push-demo/preflight.py'))
code=p['PREFIX']+r'''
def demo=Jenkins.instance.getItemByFullName('security-gitlab-push-demo')
assert !demo.isBuilding() && demo.lastBuild.number==3
assert demo.lastBuild.result.toString()=='FAILURE'
def ev=api('/projects/12/hooks/5/events?per_page=5').find{it.id==338}
assert ev && ev.response_status.toString()=='200'
def body=ev.request_data
if(body instanceof String)body=new JsonSlurper().parseText(body)
assert body.after=='d21b1271982bd4d8d90857b889c312d522779fc2' && body.project_id==12 && body.ref=='refs/heads/security-demo/gitlab-push-20261105'
assert api('/projects/12/hooks/5').push_events_branch_filter=='security-demo/gitlab-push-20261105'
def c=new URL('http://gitlab-service.ns-devops.svc.cluster.local/api/v4/projects/12/hooks/5/events/338/resend').openConnection()
c.setRequestProperty('PRIVATE-TOKEN',cred.password.plainText);c.connectTimeout=6000;c.readTimeout=12000;c.requestMethod='POST'
assert c.responseCode in [200,201,202,204]
println(JsonOutput.toJson([hookId:5,originalEventId:338,status:c.responseCode,requestBodyModified:false,newPush:false,jenkinsBuildApiCalled:false]))
'''
with (OUT/'redelivery-attempt.json').open('x') as f:json.dump({'storedEvent':338,'reason':'fixed package excludes Mac opt-in; scan was not started by first build'},f)
r=p['script'](code)
with (OUT/'redelivery.json').open('x') as f:json.dump(r,f,indent=2)
print(json.dumps(r))
