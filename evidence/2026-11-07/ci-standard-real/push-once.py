import runpy,pathlib,shlex,json,datetime
h=pathlib.Path(__file__).resolve().parent;prep=json.loads((h/'prepared.json').read_text());assert json.loads((h/'push-isolation.json').read_text())['demoNext']==7
with(h/'push-once-marker.json').open('x')as f:json.dump({'at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'commit':prep['triggerCommit'],'maximumPushes':1},f)
p=runpy.run_path('evidence/2026-11-05/gitlab-push-demo/preflight.py')
inner=r'''
import pathlib,subprocess,tempfile,json,datetime
home=pathlib.Path('/var/lib/security-gitops-demo');meta=json.loads((home/'identity-metadata.json').read_text());remote='http://'+meta['gitlabIp']+':'+str(meta['gitlabPort'])+'/root/petclinic-platform.git';branch='security-demo/gitlab-push-20261105'
env={'PATH':'/usr/bin:/bin','HOME':str(home),'LANG':'C','GIT_CONFIG_GLOBAL':'/dev/null','GIT_CONFIG_SYSTEM':'/dev/null','GIT_TERMINAL_PROMPT':'0','GIT_ASKPASS':'/usr/local/libexec/security-ci-standard-askpass'}
with tempfile.TemporaryDirectory(prefix='ci-push-',dir=home/'state')as w:
 def git(a):
  p=subprocess.run(['git','-c','core.hooksPath=/dev/null','-c','http.followRedirects=false',*a],cwd=w,env=env,capture_output=True,text=True,timeout=25);assert p.returncode==0,'NONPRODUCTION_GIT_OPERATION_FAILED';return p.stdout.strip()
 git(['init','-q','--template=']);git(['fetch','--depth=1','--no-tags',remote,'refs/heads/'+branch]);assert git(['rev-parse','FETCH_HEAD'])=='@BASE@'
 before=git(['ls-remote',remote,'refs/heads/main']).split()[0];assert before=='340ef4b8c74e3c2a5820da8d98b0f134283bb8d9'
 git(['bundle','verify',str(home/'state/ci-standard-trigger.bundle')]);git(['fetch','--no-tags',str(home/'state/ci-standard-trigger.bundle'),'refs/heads/'+branch]);assert git(['rev-parse','FETCH_HEAD'])=='@COMMIT@';assert git(['diff-tree','--no-commit-id','--name-only','-r','FETCH_HEAD'])=='docs/security-demo-gitlab-push.md'
 at=datetime.datetime.now(datetime.timezone.utc).isoformat();git(['push','--porcelain',remote,'FETCH_HEAD:refs/heads/'+branch]);assert git(['ls-remote',remote,'refs/heads/main']).split()[0]==before
 print(json.dumps({'branch':branch,'commit':'@COMMIT@','startedAt':at,'completedAt':datetime.datetime.now(datetime.timezone.utc).isoformat(),'pushExit':0,'actualPushes':1,'mainUnchanged':True,'buildApiCalled':False}))
'''
inner=inner.replace('@BASE@',prep['triggerBase']).replace('@COMMIT@',prep['triggerCommit']);code="import subprocess;print(subprocess.check_output(['setpriv','--reuid=24022','--regid=24022','--clear-groups','--no-new-privs','python3','-I','-c',"+repr(inner)+"],text=True,timeout=100))"
x=json.loads(p['m']['remote']('sudo -n python3 -c '+shlex.quote(code),timeout=115))
with(h/'pushed.json').open('x')as f:json.dump(x,f,indent=2)
print(json.dumps(x))
