"""Read-only confirmation before the two specifically approved authorization changes."""
import json,runpy,shlex,subprocess,sys
from pathlib import Path
sys.dont_write_bytecode=True
OUT=Path(__file__).resolve().parent
p=runpy.run_path(str(OUT.parent/'gitlab-push-demo/preflight.py'))
code=p['PREFIX']+"""
import com.cloudbees.plugins.credentials.common.StandardCredentials
import hudson.security.ACL
import java.security.MessageDigest
def hash={String s->MessageDigest.getInstance('SHA-256').digest(s.getBytes('UTF-8')).encodeHex().toString()}
def demo=Jenkins.instance.getItemByFullName('security-gitlab-push-demo')
def creds=CredentialsProvider.lookupCredentialsInItem(StandardCredentials.class,demo,ACL.SYSTEM2,[])
def users=hudson.model.User.all.collect{u->[id:u.id,local:u.getProperty(hudson.security.HudsonPrivateSecurityRealm.Details.class)!=null]}
println(JsonOutput.toJson([demo:[lastBuild:demo.lastBuild.number,result:demo.lastBuild.result.toString(),
 definitionSha256:hash(demo.configFile.asString()),scriptSha256:hash(demo.definition.script),sandbox:demo.definition.sandbox,
 triggers:demo.triggers.values().collect{[type:it.class.name,include:it.includeBranchesSpec,secretConfigured:it.secretToken?true:false]}],
 newCredentialAbsent:!creds.any{it.id=='security-gitleaks-demo-ssh'},
 requiredPlugins:['credentials-binding','ssh-credentials','workflow-basic-steps','pipeline-utility-steps'].collectEntries{[(it):Jenkins.instance.pluginManager.getPlugin(it)?.active]},
 realm:Jenkins.instance.securityRealm.class.name,signup:Jenkins.instance.securityRealm.allowsSignup(),users:users,
 hooks:api('/projects/12/hooks').collect{[id:it.id,url:it.url,branch:it.push_events_branch_filter,push:it.push_events]},
 branchHead:api('/projects/12/repository/branches/security-demo%2Fgitlab-push-20261105').commit.id,
 main:api('/projects/12/repository/branches/main').commit.id,
 production:[lastBuild:j.lastBuild.number,result:j.lastBuild.result.toString(),definitionSha256:hash(j.configFile.asString()),
 summarySha256:hash(new File(j.getBuildByNumber(270).artifactsDir,'.devsecops/security-summary.json').text)]]))
"""
host=r"""
import os,pwd,grp,stat,json,pathlib,hashlib,subprocess,shutil
base=pathlib.Path('/var/tmp/security-manager-gitleaks-v2-linux-20261105')
key=pathlib.Path('/var/lib/security-gitleaks/.ssh/authorized_keys')
u=pwd.getpwnam('security-gitleaks')
assert u.pw_uid==u.pw_gid==24021
assert not [g.gr_gid for g in grp.getgrall() if u.pw_name in g.gr_mem and g.gr_gid!=24021]
def meta(p):
 s=p.lstat();assert p.resolve()==p and s.st_uid==0 and not s.st_mode&0o022
 return {'mode':oct(stat.S_IMODE(s.st_mode)),'uid':s.st_uid,'gid':s.st_gid,'sha256':hashlib.sha256(p.read_bytes()).hexdigest() if p.is_file() else None}
lines=key.read_text().splitlines()
assert len(lines)==1 and lines[0].startswith('restrict,command="/usr/bin/python3 -I '+str(base)+'/ssh-entry.py" ')
assert 'security-gitleaks-demo-ssh' not in key.read_text()
memory=next(int(l.split()[1]) for l in pathlib.Path('/proc/meminfo').read_text().splitlines() if l.startswith('MemAvailable:'))
public=pathlib.Path('/etc/ssh/ssh_host_ed25519_key.pub').read_text().split()
print(json.dumps({'host':os.uname().nodename,'arch':os.uname().machine,'account':{'uid':u.pw_uid,'gid':u.pw_gid,'home':u.pw_dir},
 'authorizedKeys':meta(key),'sshDirectory':meta(key.parent),'forcedEntry':meta(base/'ssh-entry.py'),
 'hostKeyType':public[0],'hostKey':public[1],'memAvailableKiB':memory,'freeTmpBytes':shutil.disk_usage('/var/tmp').free,
 'socketMode':oct(stat.S_IMODE(os.stat('/run/docker.sock').st_mode))}))
"""
if __name__=='__main__':
 import concurrent.futures
 with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
  j=pool.submit(p['script'],code);h=pool.submit(p['m']['remote'],'sudo -n python3 -',host,40)
  result={'jenkins':j.result(),'host':json.loads(h.result())}
 trusted=subprocess.check_output(['ssh-keygen','-F','192.168.1.58','-f',str(Path.home()/'.ssh/known_hosts')],text=True)
 matches=[l.split()[1:3] for l in trusted.splitlines() if l and not l.startswith('#')]
 assert [result['host']['hostKeyType'],result['host']['hostKey']] in matches,'Host key does not match existing trust'
 assert result['jenkins']['newCredentialAbsent'] and all(result['jenkins']['requiredPlugins'].values())
 assert result['jenkins']['branchHead']=='37e28037c1d10ec74b5cb8acb212b1ccf4ee7b4b'
 assert result['jenkins']['production']['lastBuild']==270 and result['jenkins']['production']['result']=='SUCCESS'
 result['trustedHostKeyVerified']=True
 with (OUT/'approved-preflight.json').open('x') as f:json.dump(result,f,indent=2)
 print(json.dumps(result))
