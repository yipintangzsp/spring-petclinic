import runpy,pathlib,shlex,json,os,hashlib,secrets,time,tempfile,sys
sys.dont_write_bytecode=True
h=pathlib.Path(__file__).resolve().parent;root=pathlib.Path.cwd();p=runpy.run_path('evidence/2026-11-05/gitlab-push-demo/preflight.py')
groovy=p['PREFIX']+r'''
def u=api('/users/4');assert !u.is_admin && u.state=='active';def m=api('/users/4/memberships');assert m.size()==1 && m[0].source_id==12 && m[0].access_level==30
def c=new URL('http://gitlab-service.ns-devops.svc.cluster.local/api/v4/users/4/personal_access_tokens').openConnection();c.setRequestProperty('PRIVATE-TOKEN',cred.password.plainText);c.requestMethod='POST';c.doOutput=true;c.setRequestProperty('Content-Type','application/json');c.connectTimeout=5000;c.readTimeout=8000;c.outputStream.withCloseable{it.write(JsonOutput.toJson([name:'ci-standard-one-push',scopes:['write_repository'],expires_at:java.time.LocalDate.now(java.time.ZoneOffset.UTC).plusDays(1).toString()]).getBytes('UTF-8'))};assert c.responseCode==201
println(c.inputStream.text)
'''
inner=r'''
import pathlib,json,subprocess,tempfile,os
home=pathlib.Path('/var/lib/security-gitops-demo');meta=json.loads((home/'identity-metadata.json').read_text());url='http://'+meta['gitlabIp']+':'+str(meta['gitlabPort'])+'/root/petclinic-platform.git';branch='security-demo/gitlab-push-20261105'
env={'PATH':'/usr/bin:/bin','HOME':str(home),'LANG':'C','GIT_CONFIG_GLOBAL':'/dev/null','GIT_CONFIG_SYSTEM':'/dev/null','GIT_TERMINAL_PROMPT':'0','GIT_ASKPASS':'/usr/local/libexec/security-ci-standard-askpass','GIT_AUTHOR_NAME':'Security Manager CI Demo','GIT_AUTHOR_EMAIL':'ci@localhost','GIT_COMMITTER_NAME':'Security Manager CI Demo','GIT_COMMITTER_EMAIL':'ci@localhost'}
with tempfile.TemporaryDirectory(prefix='ci-standard-',dir=home/'state')as w:
 def git(a,i=None):
  q=subprocess.run(['git','-c','core.hooksPath=/dev/null','-c','http.followRedirects=false',*a],cwd=w,env=env,input=i,capture_output=True,text=True,timeout=25);assert q.returncode==0,'FIXED_GIT_PREPARATION_FAILED';return q.stdout.strip()
 git(['init','-q','--template=']);git(['fetch','--depth=1','--no-tags',url,'refs/heads/'+branch]);base=git(['rev-parse','FETCH_HEAD']);assert base=='41413cc9bc1a5037f50a76f71b57118e10b90366'
 git(['read-tree',base]);blob=git(['hash-object','-w','--stdin'],'# Independent nonproduction security CI\n\nOne GitLab webhook calls the shared Security Manager with a fixed Gitleaks Clean fixture. No image or deployment operation.\n');git(['update-index','--add','--cacheinfo','100644',blob,'docs/security-demo-gitlab-push.md']);tree=git(['write-tree']);commit=git(['commit-tree',tree,'-p',base],'demo: shared Security Manager standard CI intake\n');git(['update-ref','refs/heads/'+branch,commit]);git(['bundle','create',str(home/'state/ci-standard-trigger.bundle'),'refs/heads/'+branch,'^'+base]);print(json.dumps({'triggerBase':base,'triggerCommit':commit,'branch':branch,'pushExecuted':False}))
'''
capToken=secrets.token_hex(32)
payload={'node':p['NODE'],'groovy':groovy,'inner':inner,'wrapper':(root/'infra/security/manager-v2/ci/ssh-dispatch.py').read_text(),'ciToken':capToken}
code=r'''
import subprocess,json,sys,pathlib,urllib.parse,os,hashlib,datetime
x=json.load(sys.stdin)
r=subprocess.run(['kubectl','exec','-i','-n','ns-devops','deploy/github-webhook-relay','--','node','--max-old-space-size=24','-e',x['node']],input=json.dumps({'path':'/scriptText','method':'POST','type':'application/x-www-form-urlencoded','body':urllib.parse.urlencode({'script':x['groovy']}),'timeout':25000}),capture_output=True,text=True,timeout=40);assert r.returncode==0
response=json.loads(r.stdout);assert response['status']==200
pat=json.loads(response['body'].splitlines()[0]);assert pat['user_id']==4 and pat['scopes']==['write_repository']
home=pathlib.Path('/var/lib/security-gitops-demo');token=home/'ci-standard-git-token';assert not token.exists();token.write_text(pat['token']);os.chown(token,24022,24022);token.chmod(0o400)
ask=pathlib.Path('/usr/local/libexec/security-ci-standard-askpass');assert not ask.exists();ask.write_text("#!/usr/bin/python3\nimport pathlib,sys\nprint('oauth2' if 'username' in sys.argv[1].lower() else pathlib.Path('/var/lib/security-gitops-demo/ci-standard-git-token').read_text())\n");ask.chmod(0o555)
prep=json.loads(subprocess.check_output(['setpriv','--reuid=24022','--regid=24022','--clear-groups','--no-new-privs','python3','-I','-c',x['inner']],text=True,timeout=90))
f=pathlib.Path('/usr/local/libexec/security-manager-ci-dispatch.py');assert not f.exists();f.write_text(x['wrapper']);f.chmod(0o555)
keys=pathlib.Path('/var/lib/security-gitleaks/.ssh/authorized_keys');old=keys.read_text();st=keys.stat();oldcmd='command="/usr/bin/python3 -I /usr/local/libexec/security-gitleaks-ci-proof.py"';lines=old.splitlines(True);assert sum('security-gitleaks-demo-ssh'in l for l in lines)==1
new=''.join(l.replace(oldcmd,'command="/usr/bin/python3 -I /usr/local/libexec/security-manager-ci-dispatch.py"')if 'security-gitleaks-demo-ssh'in l else l for l in lines);assert new!=old
backup=keys.with_name('authorized_keys.before-manager-ci-20261107');assert not backup.exists();backup.write_text(old);backup.chmod(0o600);keys.write_text(new);os.chown(keys,st.st_uid,st.st_gid);keys.chmod(st.st_mode&511)
f=pathlib.Path('/var/lib/security-gitleaks/manager-ci-capability.json');assert not f.exists();f.write_text(json.dumps({'token':x['ciToken']}));os.chown(f,0,24021);f.chmod(0o440)
d=pathlib.Path('/var/lib/security-gitleaks/ci-channel');d.mkdir(mode=0o710);os.chown(d,1000,24021)
print(json.dumps({**prep,'writerTokenId':pat['id'],'writerUserId':4,'writerScopes':pat['scopes'],'scannerKeysBackup':str(backup),'scannerKeysBeforeSha256':hashlib.sha256(old.encode()).hexdigest(),'scannerKeysAfterSha256':hashlib.sha256(new.encode()).hexdigest(),'socketDirectory':str(d),'runtimeIdentityUnchanged':True}))
'''
x=json.loads(p['m']['remote']('sudo -n python3 -c '+shlex.quote(code),json.dumps(payload),timeout=170))
state=pathlib.Path(tempfile.gettempdir())/('security-v2-view-'+str(os.getuid())+'-'+hashlib.sha256(str((root/'infra/security/manager-v2/view').resolve()).encode()).hexdigest()[:12]);assert state.is_dir()
cap={'token':capToken,'projectId':'python-fixture','commitSha':x['triggerCommit'],'buildId':7,'expiresAt':int(time.time()*1000)+3600000,'stateDirectory':str(state)}
f=root/'.devsecops/security-view-ci-capability-v1.json';fd=os.open(f,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
with os.fdopen(fd,'w')as out:json.dump(cap,out)
with(h/'prepared.json').open('x')as out:json.dump({**x,'localSocket':str(state/'ci.sock'),'expiryMs':cap['expiresAt']},out,indent=2)
print(json.dumps({**x,'localSocket':str(state/'ci.sock'),'tokenOnlyProtectedStores':True}))
