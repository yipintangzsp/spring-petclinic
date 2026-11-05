"""Read-only webhook/job isolation inventory; credentials remain inside the existing operator context."""
import json,runpy,shlex,sys
from pathlib import Path
from urllib.parse import urlencode
sys.dont_write_bytecode=True
OUT=Path(__file__).resolve().parent
m=runpy.run_path(str(OUT.parent/'security-manager-v2-loki/inspect-production.py'))
sys.path.insert(0,'/Users/zhangsir/code/evidence/platform-20261011')
from jenkins_control import NODE
def script(code):
 r=json.loads(m['remote']('sudo -n kubectl exec -i -n ns-devops deploy/github-webhook-relay -- node --max-old-space-size=24 -e '+shlex.quote(NODE),json.dumps({'path':'/scriptText','method':'POST','type':'application/x-www-form-urlencoded','body':urlencode({'script':code}),'timeout':25000}),38))
 if r['status']!=200:raise RuntimeError('Jenkins HTTP '+str(r['status']))
 try:return json.loads(r['body'].split('\n')[0])
 except ValueError:raise RuntimeError(r['body'][:700]) from None
PREFIX="""
import jenkins.model.Jenkins
import groovy.json.*
import com.cloudbees.plugins.credentials.CredentialsProvider
import com.cloudbees.plugins.credentials.common.StandardUsernamePasswordCredentials
def j=Jenkins.instance.getItemByFullName('petclinic-ci')
def cred=CredentialsProvider.findCredentialById('gitlab-creds',StandardUsernamePasswordCredentials.class,j.lastBuild);assert cred
def api={String path->
 def c=new URL('http://gitlab-service.ns-devops.svc.cluster.local/api/v4'+path).openConnection()
 c.setRequestProperty('PRIVATE-TOKEN',cred.password.plainText);c.connectTimeout=6000;c.readTimeout=8000
 assert c.responseCode==200:'GitLab HTTP '+c.responseCode
 new JsonSlurper().parseText(c.inputStream.text)
}
"""
CODE=PREFIX+"""
def p=api('/projects/12')
assert p.path_with_namespace=='root/petclinic-platform'
def hooks=api('/projects/12/hooks').collect{h->[id:h.id,url:h.url,push:h.push_events,branch:h.push_events_branch_filter,branchStrategy:h.branch_filter_strategy,disabledUntil:h.disabled_until,alertStatus:h.alert_status]}
def main=api('/projects/12/repository/branches/'+p.default_branch)
def ci=api('/projects/12/repository/files/.gitlab-ci.yml?ref='+main.commit.id)
def jobs=Jenkins.instance.getAllItems(hudson.model.Job.class).findAll{v->v.name.contains('petclinic')||v.name.contains('security')||v.triggers?.values()?.any{it.class.name.contains('GitLab')}}.collect{v->
 [name:v.fullName,disabled:v.isDisabled(),last:v.lastBuild?.number,
 triggers:v.triggers?.values()?.collect{t->
 [type:t.class.name,push:t.hasProperty('triggerOnPush')?t.triggerOnPush:null,branchType:t.hasProperty('branchFilterType')?t.branchFilterType.toString():null,
 include:t.hasProperty('includeBranchesSpec')?t.includeBranchesSpec:null,exclude:t.hasProperty('excludeBranchesSpec')?t.excludeBranchesSpec:null,
 secretConfigured:t.hasProperty('secretToken')?(t.secretToken?true:false):null]}]
}
println(JsonOutput.toJson([project:[id:p.id,path:p.path_with_namespace,url:p.web_url,defaultBranch:p.default_branch],
 hooks:hooks,jobs:jobs,main:main.commit.id,ci:new String(ci.content.decodeBase64(),'UTF-8'),
 integrations:api('/projects/12/integrations').findAll{it.active}.collect{[id:it.id,slug:it.slug,name:it.name]},
 demoBranch:'security-demo/gitlab-push-20261105',queue:Jenkins.instance.queue.items.size()]))
"""
if __name__=='__main__':
 result=script(CODE)
 with (OUT/'preflight.json').open('x') as f:json.dump(result,f,indent=2)
 print(json.dumps(result))
