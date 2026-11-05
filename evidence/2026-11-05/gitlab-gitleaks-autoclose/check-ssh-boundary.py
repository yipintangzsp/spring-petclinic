"""Small real negative SSH checks with the newly authorized credential; no scan."""
import json,runpy
from pathlib import Path
OUT=Path(__file__).resolve().parent
p=runpy.run_path(str(OUT.parent/'gitlab-push-demo/preflight.py'))
pre=json.loads((OUT/'approved-preflight.json').read_text())
code=r"""
import groovy.json.JsonOutput
import com.cloudbees.plugins.credentials.SystemCredentialsProvider
import java.util.concurrent.TimeUnit
def c=SystemCredentialsProvider.instance.credentials.find{it.id=='security-gitleaks-demo-ssh'}
assert c && c.username=='security-gitleaks'
assert new File('/usr/bin/ssh').canExecute() && new File('/usr/bin/node').canExecute()
def tmp=java.nio.file.Files.createTempDirectory('gitleaks-ssh-negative-').toFile()
try{
 def key=new File(tmp,'key');key.text=c.privateKeys[0];key.setReadable(false,false);key.setWritable(false,false);assert key.setReadable(true,true)&&key.setWritable(true,true)
 def known=new File(tmp,'known_hosts');known.text='192.168.1.58 ssh-ed25519 @HOST_KEY@\n'
 def base=['/usr/bin/ssh','-F','/dev/null','-n','-i',key.absolutePath,
 '-o','BatchMode=yes','-o','IdentitiesOnly=yes','-o','IdentityAgent=none','-o','StrictHostKeyChecking=yes',
 '-o','UpdateHostKeys=no','-o','HostKeyAlias=192.168.1.58','-o','UserKnownHostsFile='+known.absolutePath,
 '-o','GlobalKnownHostsFile=/dev/null','-o','HostKeyAlgorithms=ssh-ed25519','-o','ConnectTimeout=4','-o','ConnectionAttempts=1']
 def results=[]
 [['name':'arbitraryCommand','opts':['-T'],'tail':['security-gitleaks@192.168.64.11','id']],
  ['name':'pty','opts':['-tt'],'tail':['security-gitleaks@192.168.64.11','id']],
  ['name':'directForward','opts':['-T','-W','127.0.0.1:22'],'tail':['security-gitleaks@192.168.64.11']]].each{t->
  def pb=new ProcessBuilder(base+t.opts+t.tail);pb.redirectErrorStream(true);pb.environment().clear();pb.environment().putAll([PATH:'/usr/bin:/bin',HOME:tmp.absolutePath,LANG:'C'])
  def proc=pb.start();proc.outputStream.close();def output=new StringBuffer();proc.consumeProcessOutput(output,output)
  if(!proc.waitFor(10,TimeUnit.SECONDS)){proc.destroyForcibly();throw new Exception('Bounded SSH test timed out')}
  String observed=output.toString()
  assert proc.exitValue()!=0 && observed.length()<4096
  if(t.name=='arbitraryCommand')assert observed.contains('FIXED_COMMAND_REQUIRED')&&!observed.contains('uid=')
  if(t.name=='pty')assert observed.contains('PTY allocation request failed')
  if(t.name=='directForward')assert observed.contains('administratively prohibited')
  results<<[test:t.name,exit:proc.exitValue(),output:observed]
 }
 println(JsonOutput.toJson([strictHostKeyChecking:true,trustedHostKeyReused:true,
 credential:'security-gitleaks-demo-ssh',results:results,scannerStarted:false,privateKeyExported:false]))
}finally{assert tmp.canonicalPath.startsWith('/tmp/gitleaks-ssh-negative-');assert tmp.deleteDir()}
"""
r=p['script'](code.replace('@HOST_KEY@',pre['host']['hostKey']))
with (OUT/'ssh-boundary.json').open('x') as f:json.dump(r,f,indent=2)
print(json.dumps(r))
