"""Read the actual GitLab hook delivery and automatically created Jenkins build."""
import json,runpy,time
from pathlib import Path
OUT=Path(__file__).resolve().parent
p=runpy.run_path(str(OUT.parent/'gitlab-push-demo/preflight.py'))
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

r=p["script"](code)
with (OUT/"observed-first.json").open("x") as f:json.dump(r,f,indent=2)
print(json.dumps(r))
