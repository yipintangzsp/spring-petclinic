"""Only the two approved authorization changes; no private key leaves Jenkins."""
import json,runpy
from pathlib import Path
OUT=Path(__file__).resolve().parent
p=runpy.run_path(str(OUT.parent/'gitlab-push-demo/preflight.py'))
before=json.loads((OUT/'approved-preflight.json').read_text())
CREATE=r"""
import jenkins.model.Jenkins
import groovy.json.JsonOutput
import com.cloudbees.plugins.credentials.CredentialsScope
import com.cloudbees.plugins.credentials.SystemCredentialsProvider
import com.cloudbees.plugins.credentials.domains.Domain
import com.cloudbees.jenkins.plugins.sshcredentials.impl.BasicSSHUserPrivateKey
import java.util.concurrent.TimeUnit
def provider=SystemCredentialsProvider.instance
assert !provider.credentials.any{it.id=='security-gitleaks-demo-ssh'}:'Credential already exists'
def tmp=java.nio.file.Files.createTempDirectory('security-gitleaks-demo-ssh-').toFile()
try{
 def key=new File(tmp,'id_ed25519')
 def process=new ProcessBuilder(['/usr/bin/ssh-keygen','-q','-t','ed25519','-N','','-C','security-gitleaks-demo-ssh','-f',key.absolutePath]).redirectErrorStream(true).start()
 process.outputStream.close()
 assert process.waitFor(8,TimeUnit.SECONDS) && process.exitValue()==0:'Dedicated key generation failed'
 String privateText=key.getText('UTF-8')
 String publicText=new File(tmp,'id_ed25519.pub').getText('UTF-8').trim()
 assert publicText.startsWith('ssh-ed25519 ') && publicText.endsWith(' security-gitleaks-demo-ssh')
 def credential=new BasicSSHUserPrivateKey(CredentialsScope.GLOBAL,'security-gitleaks-demo-ssh','security-gitleaks',
  new BasicSSHUserPrivateKey.DirectEntryPrivateKeySource(privateText),'',
  'Approved nonproduction demo; server-side forced command is the permission boundary. Not Job-isolated.')
 assert provider.store.addCredentials(Domain.global(),credential)
 provider.save()
 assert provider.credentials.find{it.id=='security-gitleaks-demo-ssh'}.username=='security-gitleaks'
 println(JsonOutput.toJson([credentialId:'security-gitleaks-demo-ssh',username:'security-gitleaks',
 publicKey:publicText,privateKeyExported:false,productionCredentialChanged:false,jobIsolationClaim:false]))
}finally{
 assert tmp.canonicalPath.startsWith('/tmp/security-gitleaks-demo-ssh-')
 assert tmp.deleteDir():'Temporary private key cleanup failed'
}
"""
APPEND=r"""
import os,stat,json,pathlib,hashlib,datetime
key=pathlib.Path('/var/lib/security-gitleaks/.ssh/authorized_keys')
public=PUBLIC
assert public.startswith('ssh-ed25519 ') and public.endswith(' security-gitleaks-demo-ssh') and len(public.split())==3
s=key.lstat()
assert key.resolve()==key and s.st_uid==0 and s.st_gid==24021 and stat.S_IMODE(s.st_mode)==0o640
original=key.read_bytes()
assert hashlib.sha256(original).hexdigest()==BEFORE_SHA
assert len(original.decode().splitlines())==1 and b'security-gitleaks-demo-ssh' not in original
entry='restrict,command="/usr/bin/python3 -I /var/tmp/security-manager-gitleaks-v2-linux-20261105/ssh-entry.py" '+public+'\n'
# Snapshot is private and independent; no old evidence is modified.
backup=key.parent/('authorized_keys.before-jenkins-demo-'+datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ'))
fd=os.open(backup,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
with os.fdopen(fd,'wb') as f:f.write(original);f.flush();os.fsync(f.fileno())
assert backup.stat().st_uid==0 and backup.read_bytes()==original
fd=os.open(key,os.O_WRONLY|os.O_APPEND|os.O_NOFOLLOW)
try:
 assert os.fstat(fd).st_ino==s.st_ino and key.read_bytes()==original
 payload=(b'' if original.endswith(b'\n') else b'\n')+entry.encode()
 assert os.write(fd,payload)==len(payload)
 os.fsync(fd)
finally:os.close(fd)
updated=key.read_bytes()
assert updated==original+payload and stat.S_IMODE(key.stat().st_mode)==0o640
print(json.dumps({'authorizedKeys':str(key),'beforeSha256':hashlib.sha256(original).hexdigest(),
 'afterSha256':hashlib.sha256(updated).hexdigest(),'backup':str(backup),'backupSha256':hashlib.sha256(backup.read_bytes()).hexdigest(),
 'addedKeyCount':1,'restrict':True,'forcedEntry':'/var/tmp/security-manager-gitleaks-v2-linux-20261105/ssh-entry.py',
 'oldEntriesPreserved':True,'sshdConfigChanged':False,'serviceRestarted':False}))
"""
if __name__=='__main__':
 r=p['script'](CREATE)
 with (OUT/'credential-created.json').open('x') as f:json.dump(r,f,indent=2)
 script=APPEND.replace('PUBLIC',repr(r['publicKey'])).replace('BEFORE_SHA',repr(before['host']['authorizedKeys']['sha256']))
 result=json.loads(p['m']['remote']('sudo -n python3 -',script,25))
 with (OUT/'authorized-key-added.json').open('x') as f:json.dump(result,f,indent=2)
 print(json.dumps({'credential':{k:v for k,v in r.items() if k!='publicKey'},'authorization':result}))
