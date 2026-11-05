"""Exactly one approved documentation Push, using the new project-only token on server."""
from common import *
import datetime
prep=json.loads((OUT/'prepared.json').read_text())
resume=sys.argv[1:]==['--bundle-fix-resume']
if resume:assert OUT.name=='attempt2' and (OUT/'trigger-attempt.json').exists() and not (OUT/'trigger-pushed.json').exists()
save('trigger-resume-attempt.json' if resume else 'trigger-attempt.json',{'commit':prep['triggerCommit'],'at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'budget':1,'resumeAfterPrePushBundleCheck':resume})
inner=r'''
import pathlib,json,subprocess,tempfile,os,datetime
home=pathlib.Path('/var/lib/security-gitops-demo');cfg=json.loads((home/'authorization.json').read_text());remote=cfg['remote'];branch='security-demo/gitlab-push-20261105'
env={'PATH':'/usr/bin:/bin','HOME':str(home),'LANG':'C','GIT_CONFIG_GLOBAL':'/dev/null','GIT_CONFIG_SYSTEM':'/dev/null','GIT_TERMINAL_PROMPT':'0','GIT_ASKPASS':'/usr/local/libexec/security-gitops-demo-askpass'}
with tempfile.TemporaryDirectory(prefix='trigger-',dir=home/'state') as work:
 def git(args):
  r=subprocess.run(['/usr/bin/git','-c','core.hooksPath=/dev/null','-c','http.followRedirects=false',*args],cwd=work,env=env,capture_output=True,text=True,timeout=20)
  assert r.returncode==0,'Restricted trigger git failed'
  return r.stdout.strip()
 git(['init','-q','--template=']);git(['fetch','--depth=1','--no-tags',remote,'refs/heads/'+branch]);assert git(['rev-parse','FETCH_HEAD'])=='@TRIGGER_BASE@'
 git(['bundle','verify',str(home/'state/@BUNDLE_NAME@')]);git(['fetch','--no-tags',str(home/'state/@BUNDLE_NAME@'),'refs/heads/'+branch]);assert git(['rev-parse','FETCH_HEAD'])==cfg['triggerCommit']
 assert git(['diff-tree','--no-commit-id','--name-only','-r','FETCH_HEAD'])=='docs/security-demo-gitlab-push.md'
 before=git(['ls-remote',remote,'refs/heads/main']).split()[0];assert before=='340ef4b8c74e3c2a5820da8d98b0f134283bb8d9'
 at=datetime.datetime.now(datetime.timezone.utc).isoformat()
 output=git(['push','--porcelain',remote,'FETCH_HEAD:refs/heads/'+branch])
 assert git(['ls-remote',remote,'refs/heads/main']).split()[0]==before
 print(json.dumps({'startedAt':at,'finishedAt':datetime.datetime.now(datetime.timezone.utc).isoformat(),'branch':branch,'commit':cfg['triggerCommit'],'gitPushExit':0,'actualPushes':1,'tokenScope':'project12-only Developer','productionMainUnchanged':True,'jenkinsBuildApiCalled':False}))
'''
inner=inner.replace('@TRIGGER_BASE@',prep['triggerBase']).replace('@BUNDLE_NAME@','trigger2.bundle' if OUT.name=='attempt2' else 'trigger.bundle')
code="import subprocess,json\nprint(subprocess.check_output(['/usr/bin/setpriv','--reuid=24022','--regid=24022','--clear-groups','--no-new-privs','/usr/bin/python3','-I','-'],input="+repr(inner)+",text=True,timeout=65))"
r=remote(code,80);save('trigger-pushed.json',r);print(json.dumps(r))
