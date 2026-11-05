"""Two direct rejection tests only; no Git writes or scans."""
from common import *
mode=sys.argv[1];assert mode in ['expired','replay']
prep=json.loads((OUT/'prepared.json').read_text())
if mode=='expired':proof=json.loads((OUT/'negative-ssh.json').read_text())['findingReceipt'];want='RECEIPT_EXPIRED'
else:proof=json.loads((OUT/'result.json').read_text())['gateReceipt'];want='RECEIPT_ALREADY_USED'
host=json.loads((PRIOR/'gitlab-gitleaks-autoclose/approved-preflight.json').read_text())['host']['hostKey']
command=' '.join(['update-v1',proof['receiptId'],proof['receiptDigest'],str(prep['allowedBuild']),prep['triggerCommit']])
code=r'''
import groovy.json.*
import com.cloudbees.plugins.credentials.SystemCredentialsProvider
def tmp=java.nio.file.Files.createTempDirectory('receipt-denial-').toFile()
try{
 def c=SystemCredentialsProvider.instance.credentials.find{it.id=='security-gitops-demo-ssh'}
 def key=new File(tmp,'key');key.text=c.privateKeys[0];key.setReadable(false,false);key.setWritable(false,false);assert key.setReadable(true,true)&&key.setWritable(true,true)
 def known=new File(tmp,'known');known.text='192.168.1.58 ssh-ed25519 @HOST@\n'
 def pb=new ProcessBuilder(['/usr/bin/ssh','-F','/dev/null','-T','-n','-i',key.absolutePath,'-o','BatchMode=yes','-o','IdentitiesOnly=yes','-o','IdentityAgent=none','-o','StrictHostKeyChecking=yes','-o','UpdateHostKeys=no','-o','HostKeyAlias=192.168.1.58','-o','UserKnownHostsFile='+known.absolutePath,'-o','GlobalKnownHostsFile=/dev/null','-o','HostKeyAlgorithms=ssh-ed25519','-o','ClearAllForwardings=yes','-o','ConnectTimeout=4','security-gitops-demo@192.168.64.11','@COMMAND@'])
 pb.environment().clear();pb.environment().putAll([PATH:'/usr/bin:/bin',LANG:'C']);pb.redirectErrorStream(true)
 def proc=pb.start();proc.outputStream.close();def output=new StringBuffer();def reader=proc.consumeProcessOutputStream(output)
 assert proc.waitFor(10,java.util.concurrent.TimeUnit.SECONDS);reader.join(1000)
 assert proc.exitValue()!=0 && output.toString().contains('@WANT@')
 println(JsonOutput.toJson([test:'@MODE@',reason:'@WANT@',exit:proc.exitValue(),gitWrites:0]))
}finally{assert tmp.deleteDir()}
'''
for k,v in {'HOST':host,'COMMAND':command,'WANT':want,'MODE':mode}.items():code=code.replace('@'+k+'@',v)
r=script(code);save('negative-'+mode+'.json',r);print(json.dumps(r))
