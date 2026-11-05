"""Read the actual GitLab hook delivery and automatically created Jenkins build."""
import json,runpy,time
from pathlib import Path
OUT=Path(__file__).resolve().parent
p=runpy.run_path(str(OUT/'preflight.py'))
sha=json.loads((OUT/'prepared.json').read_text())['commit']
code=p['PREFIX']+r"""
import com.dabsquared.gitlabjenkins.cause.GitLabWebHookCause
import java.security.MessageDigest
def deliveries=api('/projects/12/hooks/5/events?per_page=5').collect{e->
 def d=e.request_data
 if(d instanceof String)d=new JsonSlurper().parseText(d)
 def headers=e.request_headers?:[:]
 [id:e.id,createdAt:e.created_at,url:e.url,httpStatus:e.response_status,
 trigger:e.trigger,executionDuration:e.execution_duration,
 eventUuid:headers['X-Gitlab-Event-UUID']?:headers['x-gitlab-event-uuid'],
 webhookUuid:headers['X-Gitlab-Webhook-UUID']?:headers['x-gitlab-webhook-uuid'],
 projectId:d?.project_id,ref:d?.ref,after:d?.after,before:d?.before]
}
def demo=Jenkins.instance.getItemByFullName('security-gitlab-push-demo'),b=demo.lastBuild
def c=b?.causes?.find{it instanceof GitLabWebHookCause}
def commit=api('/projects/12/repository/commits/@SHA@')
def diff=api('/projects/12/repository/commits/@SHA@/diff')
def hash={String s->MessageDigest.getInstance('SHA-256').digest(s.getBytes('UTF-8')).encodeHex().toString()}
println(JsonOutput.toJson([observedAt:new Date().format("yyyy-MM-dd'T'HH:mm:ssXXX",TimeZone.getTimeZone('UTC')),
 deliveries:deliveries,build:b?[number:b.number,result:b.result?.toString(),building:b.building,
 startedAt:b.timeInMillis,duration:b.duration,url:'http://jenkins.devops.local/job/security-gitlab-push-demo/'+b.number+'/',
 causes:b.causes.collect{it.class.name},cause:c?[projectId:c.data.sourceProjectId,branch:c.data.sourceBranch,
 action:c.data.actionType.toString(),after:c.data.after,before:c.data.before]:null,
 console:b.getLog(80).join('\n')]:null,
 commit:[id:commit.id,parents:commit.parent_ids,title:commit.title,committedAt:commit.committed_date],
 changedPaths:diff.collect{it.new_path},
 gitlabBranchPipelines:api('/projects/12/pipelines?ref=security-demo%2Fgitlab-push-20261105&per_page=5').collect{[id:it.id,status:it.status,sha:it.sha]},
 main:api('/projects/12/repository/branches/main').commit.id,
 productionJob:[lastBuild:j.lastBuild.number,building:j.lastBuild.building,result:j.lastBuild.result.toString(),definitionSha256:hash(j.configFile.asString()),
 summarySha256:hash(new File(j.getBuildByNumber(270).artifactsDir,'.devsecops/security-summary.json').text)],
 existingHook:api('/projects/12/hooks/4').findAll{k,v->k in ['id','url','push_events','push_events_branch_filter','branch_filter_strategy']}]))
"""
code=code.replace('@SHA@',sha)
if __name__=='__main__':
 r=None
 for attempt in range(4):
  r=p['script'](code)
  if r['build'] and r['build']['number']>=2 and not r['build']['building'] and len(r['deliveries'])>=2:break
  time.sleep(4)
 with (OUT/'observed-redelivery.json').open('x') as f:json.dump(r,f,indent=2)
 assert r['commit']['id']==sha and r['changedPaths']==['docs/security-demo-gitlab-push.md']
 deliveries=[d for d in r['deliveries'] if d['after']==sha and d['ref']=='refs/heads/security-demo/gitlab-push-20261105' and d['projectId']==12]
 assert len(deliveries)==2 and all(str(d['httpStatus']) in ['200','201','202'] for d in deliveries),deliveries
 b=r['build']
 assert b and not b['building'] and b['result']=='SUCCESS',b
 assert b['causes']==['com.dabsquared.gitlabjenkins.cause.GitLabWebHookCause'],b['causes']
 assert b['cause']=={'projectId':12,'branch':'security-demo/gitlab-push-20261105','action':'PUSH','after':sha,'before':'0'*40}
 assert 'GITLAB_PUSH_ACCEPTED project=12 branch=security-demo/gitlab-push-20261105 commit='+sha in b['console']
 assert 'SUCCESS: fixed documentation push verified' in b['console']
 assert r['main']=='340ef4b8c74e3c2a5820da8d98b0f134283bb8d9'
 assert r['productionJob']['lastBuild']==270 and r['productionJob']['result']=='SUCCESS'
 assert r['productionJob']['definitionSha256']=='abedd817048170dcf0833853d3820347341a91bd77501a77a2fcf10fb07a8f25'
 assert r['productionJob']['summarySha256']=='ec9ee51a06d4b9f61c6c0eaf50b374d1e25e6d3ca687908b7596d3a2c794f5d8'
 assert r['existingHook']['push_events_branch_filter']=='main'
 proof={'classification':'HISTORICAL','commit':sha,'branch':'security-demo/gitlab-push-20261105',
 'delivery':deliveries[0],'deliveries':deliveries,'triggerMode':'REAL_GITLAB_STORED_EVENT_REDELIVERY','firstBuild':json.loads((OUT/'observed.json').read_text())['build'],'build':b,'productionUnchanged':True,'releaseCount':0,'rolloutCount':0}
 with (OUT/'verified.json').open('x') as f:json.dump(proof,f,indent=2)
 print(json.dumps({'commit':sha,'delivery':deliveries[0],'buildUrl':b['url'],'result':b['result'],'cause':b['cause'],'gitlabPipelines':r['gitlabBranchPipelines']}))
