"""Create dedicated Jenkins SSH credential and prepare one trigger commit; no Push."""
from common import *
import base64
key=script(r'''
import groovy.json.JsonOutput
import com.cloudbees.plugins.credentials.*
import com.cloudbees.plugins.credentials.domains.Domain
import com.cloudbees.jenkins.plugins.sshcredentials.impl.BasicSSHUserPrivateKey
def provider=SystemCredentialsProvider.instance
assert !provider.credentials.any{it.id=='security-gitops-demo-ssh'}
def tmp=java.nio.file.Files.createTempDirectory('gitops-demo-key-').toFile()
try{
 def file=new File(tmp,'key');def proc=new ProcessBuilder(['/usr/bin/ssh-keygen','-q','-t','ed25519','-N','','-C','security-gitops-demo-ssh','-f',file.absolutePath]).start()
 assert proc.waitFor(6,java.util.concurrent.TimeUnit.SECONDS)&&proc.exitValue()==0
 String pub=new File(tmp,'key.pub').text.trim()
 def credential=new BasicSSHUserPrivateKey(CredentialsScope.GLOBAL,'security-gitops-demo-ssh','security-gitops-demo',new BasicSSHUserPrivateKey.DirectEntryPrivateKeySource(file.text),'','Nonproduction fixed branch/field; server forced command is boundary, not Job-isolated')
 assert provider.store.addCredentials(Domain.global(),credential);provider.save()
 println(JsonOutput.toJson([id:credential.id,username:credential.username,publicKey:pub,privateKeyExported:false]))
}finally{assert tmp.deleteDir()}
''')
save('ssh-credential.json',key)
inner=r'''
import json,subprocess,os,tempfile,base64,hashlib
home='/var/lib/security-gitops-demo'
meta=json.load(open(home+'/identity-metadata.json'))
remote='http://'+meta['gitlabIp']+':'+str(meta['gitlabPort'])+'/root/petclinic-platform.git'
env={'PATH':'/usr/bin:/bin','HOME':home,'LANG':'C','GIT_CONFIG_GLOBAL':'/dev/null','GIT_CONFIG_SYSTEM':'/dev/null','GIT_TERMINAL_PROMPT':'0','GIT_ASKPASS':'/usr/local/libexec/security-gitops-demo-askpass','GIT_AUTHOR_NAME':'DevSecOps CI CD Demo','GIT_AUTHOR_EMAIL':'ci-cd-demo@localhost','GIT_COMMITTER_NAME':'DevSecOps CI CD Demo','GIT_COMMITTER_EMAIL':'ci-cd-demo@localhost'}
with tempfile.TemporaryDirectory(prefix='prepare-',dir=home+'/state') as work:
 def git(a,input=None):
  r=subprocess.run(['/usr/bin/git','-c','core.hooksPath=/dev/null','-c','http.followRedirects=false',*a],cwd=work,env=env,input=input,capture_output=True,text=True,timeout=20)
  assert r.returncode==0,'Bounded preparation failed, no stdout secrets'
  return r.stdout.strip()
 git(['init','-q','--template=']);git(['fetch','--depth=1','--no-tags',remote,'refs/heads/security-demo/gitlab-push-20261105'])
 base=git(['rev-parse','FETCH_HEAD']);assert base=='d21b1271982bd4d8d90857b889c312d522779fc2'
 git(['read-tree',base]);blob=git(['hash-object','-w','--stdin'],'# Nonproduction CI to CD demonstration\n\nReal Gitleaks Gate PASS authorizes only the fixed GitOps ConfigMap update and restore.\nNo production release or rollout.\n')
 git(['update-index','--add','--cacheinfo','100644',blob,'docs/security-demo-gitlab-push.md'])
 tree=git(['write-tree']);commit=git(['commit-tree',tree,'-p',base],'demo: real security Gate controls isolated GitOps CD\n')
 git(['update-ref','refs/heads/security-demo/gitlab-push-20261105',commit])
 assert git(['diff-tree','--no-commit-id','--name-only','-r',commit])=='docs/security-demo-gitlab-push.md'
 git(['fetch','--depth=1','--no-tags',remote,'refs/heads/security-demo/gitops-20261105'])
 baseline=git(['rev-parse','FETCH_HEAD']);assert baseline=='9f3124056fb078736b1898db45822cb0cedac109'
 manifest=json.loads(git(['show',baseline+':infra/devops-lab/gitops-demo/configmap.yaml']))
 print(json.dumps({'triggerBase':base,'triggerCommit':commit,'gitopsBaseline':baseline,'baselineManifest':manifest}))
 # Preserve the tiny incremental trigger object bundle in private server state only.
 git(['bundle','create',home+'/state/trigger.bundle','refs/heads/security-demo/gitlab-push-20261105','^'+base])
'''
code=r'''
import json,os,pathlib,subprocess,time,datetime
home=pathlib.Path('/var/lib/security-gitops-demo')
public=@PUBLIC@
assert public.startswith('ssh-ed25519 ') and public.endswith(' security-gitops-demo-ssh')
keys=home/'.ssh/authorized_keys';assert not keys.exists()
fd=os.open(keys,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o640)
with os.fdopen(fd,'w') as f:f.write('restrict,command="/usr/bin/python3 -I /usr/local/libexec/security-gitops-demo-entry.py" '+public+'\n')
os.chown(keys,0,24022)
r=json.loads(subprocess.check_output(['/usr/bin/setpriv','--reuid=24022','--regid=24022','--clear-groups','--no-new-privs','/usr/bin/python3','-I','-'],input=@INNER@,text=True,timeout=60))
meta=json.loads((home/'identity-metadata.json').read_text())
cfg={'build':@BUILD@,'job':'security-gitlab-push-demo','triggerCommit':r['triggerCommit'],'baselineCommit':r['gitopsBaseline'],'baselineManifest':r['baselineManifest'],
 'notBefore':int(time.time()),'gitlabIp':meta['gitlabIp'],'gitlabPort':meta['gitlabPort'],'remote':'http://'+meta['gitlabIp']+':'+str(meta['gitlabPort'])+'/root/petclinic-platform.git'}
fd=os.open(home/'authorization.json',os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o444)
with os.fdopen(fd,'w') as f:json.dump(cfg,f)
r['allowedBuild']=@BUILD@;r['pushExecuted']=False
print(json.dumps(r))
'''
before=json.loads((OUT/'before.json').read_text())
for k,v in {'PUBLIC':repr(key['publicKey']),'INNER':repr(inner),'BUILD':str(before['build'])}.items():code=code.replace('@'+k+'@',v)
r=remote(code,90);save('prepared.json',r);print(json.dumps(r))
