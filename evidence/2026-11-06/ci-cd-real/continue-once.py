"""One bounded repair attempt, reusing all identities/resources. No new privilege."""
from common import *
assert OUT.name=='attempt2'
first=BASE
state=script(p['PREFIX']+r'''
import java.security.MessageDigest
def d=Jenkins.instance.getItemByFullName('security-gitlab-push-demo')
assert !d.isBuilding() && d.lastBuild.number==5 && d.lastBuild.result.toString()=='FAILURE' && d.nextBuildNumber==6
println(JsonOutput.toJson([previousBuild:5,build:6,jobSha256:MessageDigest.getInstance('SHA-256').digest(d.configFile.file.bytes).encodeHex().toString(),triggerBase:api('/projects/12/repository/branches/security-demo%2Fgitlab-push-20261105').commit.id]))
''')
save('before.json',state)
inner=r'''
import json,pathlib,tempfile,subprocess
home=pathlib.Path('/var/lib/security-gitops-demo');cfg=json.loads((home/'authorization.json').read_text());remote=cfg['remote'];env={'PATH':'/usr/bin:/bin','HOME':str(home),'LANG':'C','GIT_CONFIG_GLOBAL':'/dev/null','GIT_CONFIG_SYSTEM':'/dev/null','GIT_TERMINAL_PROMPT':'0','GIT_ASKPASS':'/usr/local/libexec/security-gitops-demo-askpass','GIT_AUTHOR_NAME':'DevSecOps CI CD Demo','GIT_AUTHOR_EMAIL':'ci-cd-demo@localhost','GIT_COMMITTER_NAME':'DevSecOps CI CD Demo','GIT_COMMITTER_EMAIL':'ci-cd-demo@localhost'}
with tempfile.TemporaryDirectory(prefix='notify-fix-',dir=home/'state') as work:
 def git(a,input=None):
  r=subprocess.run(['/usr/bin/git','-c','core.hooksPath=/dev/null',*a],cwd=work,env=env,input=input,capture_output=True,text=True,timeout=20);assert r.returncode==0,'Preparation failed';return r.stdout.strip()
 git(['init','-q','--template=']);git(['fetch','--depth=1','--no-tags',remote,'refs/heads/security-demo/gitlab-push-20261105']);base=git(['rev-parse','FETCH_HEAD']);assert base=='f46f484ef635706bc208f3dd736632f2f5b60e67'
 git(['read-tree',base]);blob=git(['hash-object','-w','--stdin'],'# Nonproduction CI to CD demonstration\n\nReal Gitleaks PASS authorizes the fixed ConfigMap update and restore.\nJenkins notifies the existing Argo native webhook using the configured internal repository URL.\nNo production release or rollout.\n')
 git(['update-index','--add','--cacheinfo','100644',blob,'docs/security-demo-gitlab-push.md']);tree=git(['write-tree']);commit=git(['commit-tree',tree,'-p',base],'demo: notify existing Argo webhook after Gate-authorized GitOps push\n');git(['update-ref','refs/heads/security-demo/gitlab-push-20261105',commit])
 assert git(['diff-tree','--no-commit-id','--name-only','-r',commit])=='docs/security-demo-gitlab-push.md'
 git(['bundle','create',str(home/'state/trigger2.bundle'),'refs/heads/security-demo/gitlab-push-20261105','^'+base])
 git(['fetch','--depth=1','--no-tags',remote,'refs/heads/security-demo/gitops-20261105']);baseline=git(['rev-parse','FETCH_HEAD']);assert baseline=='8be6c988f4cc0419d04992761e9cb5765e78cff3'
 print(json.dumps({'triggerBase':base,'triggerCommit':commit,'gitopsBaseline':baseline,'baselineManifest':json.loads(git(['show',baseline+':infra/devops-lab/gitops-demo/configmap.yaml'])),'allowedBuild':6,'pushExecuted':False}))
'''
code=r'''
import json,subprocess,pathlib,os,time,shutil
home=pathlib.Path('/var/lib/security-gitops-demo')
def k(a):return json.loads(subprocess.check_output(['kubectl']+a,text=True,timeout=10))
a=k(['-n','argocd','get','application','petclinic-gitops-demo','-o','json']);cm=k(['-n','devsecops-test','get','configmap','petclinic-gitops-demo','-o','json'])
assert cm['data']=={'demo-stage':'baseline'} and a['status']['sync']['revision']=='8be6c988f4cc0419d04992761e9cb5765e78cff3' and a['status']['sync']['status']=='Synced'
r=json.loads(subprocess.check_output(['/usr/bin/setpriv','--reuid=24022','--regid=24022','--clear-groups','--no-new-privs','/usr/bin/python3','-I','-'],input=@INNER@,text=True,timeout=60))
cfg=json.loads((home/'authorization.json').read_text());assert cfg['build']==5
backup=home/'authorization.build5.json';assert not backup.exists();shutil.copyfile(home/'authorization.json',backup);backup.chmod(0o444)
cfg.update({'build':6,'triggerCommit':r['triggerCommit'],'baselineCommit':r['gitopsBaseline'],'notBefore':int(time.time())})
tmp=home/'authorization.next';fd=os.open(tmp,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o444)
with os.fdopen(fd,'w') as f:json.dump(cfg,f)
os.replace(tmp,home/'authorization.json')
r['reason']='One repair: existing Argo native webhook notification after each demo Git push; first attempt retained as FAILURE'
print(json.dumps(r))
'''.replace('@INNER@',repr(inner))
r=remote(code,85);save('prepared.json',r);print(json.dumps(r))
