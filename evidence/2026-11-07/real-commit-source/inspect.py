import pathlib,runpy,json,shlex,sys
sys.dont_write_bytecode=True
p=runpy.run_path('evidence/2026-11-05/gitlab-push-demo/preflight.py')
code=p['PREFIX']+r'''
def project=api('/projects/12?statistics=true');def branch=api('/projects/12/repository/branches/security-demo%2Fgitlab-push-20261105');def commit=api('/projects/12/repository/commits/'+branch.commit.id);def tree=api('/projects/12/repository/tree?ref='+branch.commit.id+'&per_page=100');def jobs=Jenkins.instance.getItemByFullName('security-gitlab-push-demo');def u=api('/users/4');def tokens=api('/personal_access_tokens?user_id=4&state=active').collect{[id:it.id,scopes:it.scopes,revoked:it.revoked,active:it.active,expiresAt:it.expires_at]}
println(JsonOutput.toJson([project:[id:project.id,path:project.path_with_namespace,visibility:project.visibility,repositoryBytes:project.statistics?.repository_size],branch:[name:branch.name,commit:branch.commit.id],commit:[id:commit.id,parentIds:commit.parent_ids],rootTree:tree.collect{[type:it.type,path:it.path,mode:it.mode]},job:[last:jobs.lastBuild.number,result:jobs.lastBuild.result?.toString(),next:jobs.nextBuildNumber,building:jobs.isBuilding()],writerIdentity:[id:u.id,admin:u.is_admin,state:u.state],activeTokenMetadata:tokens,hook:api('/projects/12/hooks/5').push_events_branch_filter]))
'''
x=p['script'](code)
remote=r'''
import pathlib,json,pwd,os
root=pathlib.Path('/var/tmp/security-manager-gitleaks-v2-linux-20261105');a=json.loads((root/'approval.json').read_text());entry=(root/'ssh-entry.py').read_text()
print(json.dumps({'approvalScope':a['scope'],'executionUid':a['executionUid'],'sourceApproval':[{k:s[k]for k in ['projectId','sourceDir','sourceRevision']}for s in a['sources']],'runnerCode':{'fileBudget16':'seen.length>16'in(root/'infra/security/manager-v2/gitleaks-real.mjs').read_text()if(root/'infra/security/manager-v2/gitleaks-real.mjs').exists()else None},'entryBytes':len(entry),'readSourceCredential':pathlib.Path('/var/lib/security-gitleaks/source-read-token').exists(),'ciCapability':pathlib.Path('/var/lib/security-gitleaks/manager-ci-capability.json').exists(),'channelExists':pathlib.Path('/var/lib/security-gitleaks/ci-channel').exists()}))
'''
x['linux']=json.loads(p['m']['remote']('sudo -n python3 -',remote,20))
with pathlib.Path('evidence/2026-11-07/real-commit-source/preflight.json').open('x')as f:json.dump(x,f,indent=2)
print(json.dumps(x))
