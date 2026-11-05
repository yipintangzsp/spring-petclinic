"""Read only exact webhook/build; print progress without persistent polling reports."""
from common import *
prep=json.loads((OUT/'prepared.json').read_text());n=prep['allowedBuild']
code=p['PREFIX']+r'''
def demo=Jenkins.instance.getItemByFullName('security-gitlab-push-demo'),b=demo.getBuildByNumber(@BUILD@)
def events=api('/projects/12/hooks/5/events?per_page=5').collect{e->[id:e.id,status:e.response_status,createdAt:e.created_at,after:e.request_data?.after,ref:e.request_data?.ref,project:e.request_data?.project?.id]}.findAll{it.after=='@COMMIT@'}
def state=b?[number:b.number,building:b.building,result:b.result?.toString(),url:'http://jenkins.devops.local/job/security-gitlab-push-demo/'+b.number+'/',
 startedAt:b.timeInMillis,duration:b.duration,causes:b.causes.collect{c->[type:c.class.name,after:c.hasProperty('data')?c.data.after:null,branch:c.hasProperty('data')?c.data.sourceBranch:null]},
 tail:b.getLog(42).join('\n'),artifacts:b.artifacts.collect{it.relativePath}]:null
println(JsonOutput.toJson([build:state,events:events,queue:demo.isInQueue(),productionBuild:j.lastBuild.number]))
'''.replace('@BUILD@',str(n)).replace('@COMMIT@',prep['triggerCommit'])
r=script(code)
if r['build'] and not r['build']['building']:
 save('build-final.json',r)
print(json.dumps(r))
