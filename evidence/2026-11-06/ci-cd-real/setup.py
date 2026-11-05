"""Approved account, short project token and proof/writer entries. No Job start."""
from common import *
import base64,shlex,hashlib
inspect=script(p['PREFIX']+r'''
import com.cloudbees.plugins.credentials.SystemCredentialsProvider
def demo=Jenkins.instance.getItemByFullName('security-gitlab-push-demo')
assert demo.lastBuild.number==4 && !demo.isBuilding()
assert !SystemCredentialsProvider.instance.credentials.any{it.id=='security-gitops-demo-ssh'}
println(JsonOutput.toJson([build:demo.nextBuildNumber,jobSha256:java.security.MessageDigest.getInstance('SHA-256').digest(demo.configFile.file.bytes).encodeHex().toString(),
trigger:api('/projects/12/repository/branches/security-demo%2Fgitlab-push-20261105').commit.id,
gitops:api('/projects/12/repository/branches/security-demo%2Fgitops-20261105').commit.id,main:api('/projects/12/repository/branches/main').commit.id]))
''')
save('before.json',inspect)
node=p['NODE']
payload={name:base64.b64encode((ROOT/'infra/jenkins/gitlab-push-demo'/name).read_bytes()).decode() for name in ['gate-proof-entry.py','gitops-entry.py']}
code=r'''
import json,os,pathlib,subprocess,stat,datetime,urllib.request,urllib.error,urllib.parse,hashlib
FILES=@FILES@;NODE=@NODE@
home=pathlib.Path('/var/lib/security-gitops-demo');proofs=pathlib.Path('/var/lib/security-gitops-demo-proofs')
for db,value in [('passwd','security-gitops-demo'),('passwd','24022'),('group','security-gitops-demo'),('group','24022')]:assert subprocess.run(['getent',db,value],capture_output=True).returncode==2
assert not home.exists() and not proofs.exists()
for path in ['/usr/local/libexec/security-gitleaks-ci-proof.py','/usr/local/libexec/security-gitops-demo-entry.py','/usr/local/libexec/security-gitops-demo-askpass']:assert not pathlib.Path(path).exists()
deploy=json.loads(subprocess.check_output(['kubectl','-n','ns-devops','get','deployment','jenkins','-o','json'],text=True,timeout=10))
sa=deploy['spec']['template']['spec'].get('serviceAccountName','default')
rights={kind:subprocess.check_output(['kubectl','auth','can-i','get',kind,'-n',ns,'--as=system:serviceaccount:ns-devops:'+sa],text=True,timeout=6).strip() for kind,ns in [('configmaps','devsecops-test'),('applications.argoproj.io','argocd')]}
assert all(v=='yes' for v in rights.values()),'Existing Jenkins GET rights insufficient; stop without RBAC change'
# Existing authorized management channel only. No new Git token enters Jenkins.
groovy="""import groovy.json.JsonOutput
import com.cloudbees.plugins.credentials.CredentialsProvider
import com.cloudbees.plugins.credentials.common.StandardUsernamePasswordCredentials
def j=Jenkins.instance.getItemByFullName('petclinic-ci')
def c=CredentialsProvider.findCredentialById('gitlab-creds',StandardUsernamePasswordCredentials.class,j.lastBuild);assert c
println(JsonOutput.toJson([token:c.password.plainText]))"""
request={'path':'/scriptText','method':'POST','type':'application/x-www-form-urlencoded','body':urllib.parse.urlencode({'script':groovy}),'timeout':10000}
raw=subprocess.check_output(['kubectl','exec','-i','-n','ns-devops','deploy/github-webhook-relay','--','node','--max-old-space-size=24','-e',NODE],input=json.dumps(request),text=True,timeout=18)
response=json.loads(raw);assert response['status']==200
admin=json.loads(response['body'].splitlines()[0])['token']
svc=json.loads(subprocess.check_output(['kubectl','-n','ns-devops','get','service','gitlab-service','-o','json'],text=True,timeout=8))
ip=svc['spec']['clusterIP'];port=next(x['port'] for x in svc['spec']['ports'] if x['port']==80)
base='http://'+ip+':'+str(port);op=urllib.request.build_opener(urllib.request.ProxyHandler({}))
def api(path,method='GET',body=None,headers=None):
 req=urllib.request.Request(base+'/api/v4'+path,method=method,data=None if body is None else json.dumps(body).encode(),headers={'PRIVATE-TOKEN':admin,'Content-Type':'application/json',**(headers or {})})
 try:
  with op.open(req,timeout=10) as r:return r.status,json.load(r)
 except urllib.error.HTTPError as e:return e.code,None
status,existing=api('/projects/12/access_tokens');assert status==200 and not any(x['name']=='security-gitops-demo-20261106' and x['active'] for x in existing)
expiry=(datetime.datetime.now(datetime.timezone.utc).date()+datetime.timedelta(days=7)).isoformat()
status,token=api('/projects/12/access_tokens','POST',{'name':'security-gitops-demo-20261106','scopes':['write_repository'],'access_level':30,'expires_at':expiry})
assert status==201,'Project-only short token unavailable; stop without broader fallback'
assert token['scopes']==['write_repository'] and token['access_level']==30
status,user=api('/users/'+str(token['user_id']));assert status==200 and not user['is_admin']
status,memberships=api('/users/'+str(token['user_id'])+'/memberships');assert status==200
assert memberships and all(x['source_type']=='Project' and x['source_id']==12 and x['access_level']==30 for x in memberships)
subprocess.run(['groupadd','--gid','24022','security-gitops-demo'],check=True)
subprocess.run(['useradd','--system','--no-create-home','--uid','24022','--gid','24022','--home-dir',str(home),'--shell','/bin/sh','security-gitops-demo'],check=True)
home.mkdir(mode=0o755);ssh=home/'.ssh';ssh.mkdir(mode=0o750);os.chown(ssh,0,24022)
state=home/'state';state.mkdir(mode=0o700);os.chown(state,24022,24022)
private=home/'git-token';fd=os.open(private,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o400)
with os.fdopen(fd,'w') as f:f.write(token['token'])
os.chown(private,24022,24022)
proofs.mkdir(mode=0o2750);os.chown(proofs,24021,24022);proofs.chmod(0o2750)
lib=pathlib.Path('/usr/local/libexec');lib.mkdir(mode=0o755,exist_ok=True)
import base64
for source,target in [('gate-proof-entry.py','security-gitleaks-ci-proof.py'),('gitops-entry.py','security-gitops-demo-entry.py')]:
 dest=lib/target;fd=os.open(dest,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o555)
 with os.fdopen(fd,'wb') as f:f.write(base64.b64decode(FILES[source]))
ask=lib/'security-gitops-demo-askpass'
ask.write_text('#!/bin/sh\ncase "$1" in *Username*) printf "%s\\n" oauth2 ;; *Password*) exec /usr/bin/cat /var/lib/security-gitops-demo/git-token ;; *) exit 1 ;; esac\n');ask.chmod(0o555)
keys=pathlib.Path('/var/lib/security-gitleaks/.ssh/authorized_keys');original=keys.read_bytes();lines=original.decode().splitlines(True)
assert len(lines)==2 and sum('security-gitleaks-demo-ssh' in x for x in lines)==1
backup=keys.parent/('authorized_keys.before-cd-proof-'+datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ'))
fd=os.open(backup,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
with os.fdopen(fd,'wb') as f:f.write(original)
updated=[]
for line in lines:
 if 'security-gitleaks-demo-ssh' in line:
  old='command="/usr/bin/python3 -I /var/tmp/security-manager-gitleaks-v2-linux-20261105/ssh-entry.py"'
  assert line.startswith('restrict,') and old in line
  line=line.replace(old,'command="/usr/bin/python3 -I /usr/local/libexec/security-gitleaks-ci-proof.py"')
 updated.append(line)
keys.write_bytes(''.join(updated).encode());assert stat.S_IMODE(keys.stat().st_mode)==0o640
assert [x for x in lines if 'security-gitleaks-demo-ssh' not in x]==[x for x in updated if 'security-gitleaks-demo-ssh' not in x]
assert subprocess.check_output(['id','-G','security-gitops-demo'],text=True).strip()=='24022'
assert not os.access('/no-such-path',os.R_OK)
metadata={'tokenId':token['id'],'userId':token['user_id'],'username':user['username'],'expiresAt':token['expires_at'],'scopes':token['scopes'],'accessLevel':30,
 'gitlabIp':ip,'gitlabPort':port,'jenkinsServiceAccount':sa,'existingGetRights':rights,'scannerKeysBackup':str(backup),'scannerKeysBeforeSha256':hashlib.sha256(original).hexdigest(),'scannerKeysAfterSha256':hashlib.sha256(keys.read_bytes()).hexdigest(),
 'memberships':[{'type':x['source_type'],'id':x['source_id'],'accessLevel':x['access_level']} for x in memberships],
 'tokenOnlyOnServer':True,'newPermissionsGrantedToExistingAccounts':False,'servicesRestarted':False}
fd=os.open(home/'identity-metadata.json',os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o444)
with os.fdopen(fd,'w') as f:json.dump(metadata,f)
print(json.dumps(metadata))
'''.replace('@FILES@',repr(payload)).replace('@NODE@',repr(node))
r=remote(code,105);save('identity.json',r);print(json.dumps(r))
