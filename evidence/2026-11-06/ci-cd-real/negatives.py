"""Small real SSH/identity negatives; Finding is existing controlled fixture only."""
from common import *
import uuid
prep=json.loads((OUT/'prepared.json').read_text());run='web-'+str(uuid.uuid4())
hostkey=json.loads((PRIOR/'gitlab-gitleaks-autoclose/approved-preflight.json').read_text())['host']['hostKey']
code=r'''
import groovy.json.*
import com.cloudbees.plugins.credentials.SystemCredentialsProvider
import java.util.concurrent.TimeUnit
def tmp=java.nio.file.Files.createTempDirectory('ci-cd-negatives-').toFile()
def provider=SystemCredentialsProvider.instance
try{
 def keyfiles=[:]
 ['security-gitleaks-demo-ssh','security-gitops-demo-ssh'].each{id->
  def key=new File(tmp,id);key.text=provider.credentials.find{it.id==id}.privateKeys[0]
  key.setReadable(false,false);key.setWritable(false,false);assert key.setReadable(true,true)&&key.setWritable(true,true);keyfiles[id]=key.absolutePath
 }
 def known=new File(tmp,'known');known.text='192.168.1.58 ssh-ed25519 @HOST@\n'
 def base=['/usr/bin/ssh','-F','/dev/null','-n','-o','BatchMode=yes','-o','IdentitiesOnly=yes','-o','IdentityAgent=none','-o','StrictHostKeyChecking=yes','-o','UpdateHostKeys=no','-o','HostKeyAlias=192.168.1.58','-o','UserKnownHostsFile='+known.absolutePath,'-o','GlobalKnownHostsFile=/dev/null','-o','HostKeyAlgorithms=ssh-ed25519','-o','ConnectTimeout=4','-o','ConnectionAttempts=1']
 def call={String id,String command,List opts=['-T']->
  def c=provider.credentials.find{it.id==id};def pb=new ProcessBuilder(base+['-i',keyfiles[id]]+opts+[c.username+'@192.168.64.11']+(command?[command]:[]));pb.environment().clear();pb.environment().putAll([PATH:'/usr/bin:/bin',LANG:'C',HOME:tmp.absolutePath]);pb.redirectErrorStream(true)
  def proc=pb.start();proc.outputStream.close();def buf=new StringBuffer();def reader=proc.consumeProcessOutputStream(buf)
  if(!proc.waitFor(32,TimeUnit.SECONDS)){proc.destroyForcibly();throw new Exception('Bounded SSH negative timeout')};reader.join(1000);assert !reader.alive
  [exit:proc.exitValue(),output:buf.toString()]
 }
 def finding=call('security-gitleaks-demo-ssh','finding-v1 @RUN@');assert finding.exit==0:'Finding fixture scan did not complete'
 def packet=new JsonSlurper().parseText(finding.output),proof=packet.gateReceipt
 assert proof.policyDecision=='FAIL' && proof.scenarioId=='controlled-finding' && proof.evaluationCount==1
 String prefix='update-v1 '+proof.receiptId+' '+proof.receiptDigest+' @BUILD@ @COMMIT@'
 def cases=[
  [name:'FindingFAIL',cmd:prefix,want:'GATE_NOT_PASS'],
  [name:'TamperedDigest',cmd:'update-v1 '+proof.receiptId+' '+('0'*64)+' @BUILD@ @COMMIT@',want:'RECEIPT_DIGEST_MISMATCH'],
  [name:'ForgedPASS',cmd:'update-v1 '+('a'*48)+' '+('0'*64)+' @BUILD@ @COMMIT@',want:'RECEIPT_NOT_FOUND'],
  [name:'ArbitraryGitMain',cmd:'git push origin main',want:'FIXED_COMMAND_REQUIRED'],
  [name:'FieldOrRefInjection',cmd:prefix+' main data.other=override',want:'FIXED_COMMAND_REQUIRED'],
  [name:'PrivilegeEscalation',cmd:'sudo id',want:'FIXED_COMMAND_REQUIRED']]
 def results=cases.collect{t->def r=call('security-gitops-demo-ssh',t.cmd);assert r.exit!=0 && r.output.contains(t.want):t.name+' was not denied';[name:t.name,exit:r.exit,reason:t.want]}
 def pty=call('security-gitops-demo-ssh','id',['-tt']);assert pty.exit!=0 && pty.output.contains('PTY allocation request failed');results<<[name:'PTY',exit:pty.exit,reason:'PTY_DENIED']
 def forward=call('security-gitops-demo-ssh','',['-T','-W','127.0.0.1:22']);assert forward.exit!=0 && forward.output.contains('administratively prohibited');results<<[name:'Forwarding',exit:forward.exit,reason:'FORWARD_DENIED']
 println(JsonOutput.toJson([cases:results,findingReceipt:proof,findingRun:'@RUN@',gitWrites:0,privateKeysExported:false]))
}finally{assert tmp.deleteDir()}
'''
for k,v in {'HOST':hostkey,'RUN':run,'BUILD':str(prep['allowedBuild']),'COMMIT':prep['triggerCommit']}.items():code=code.replace('@'+k+'@',v)
r=script(code);save('negative-ssh.json',r);print(json.dumps(r))
host=r'''
import json,pathlib,subprocess,urllib.request,urllib.error,base64
home=pathlib.Path('/var/lib/security-gitops-demo');meta=json.loads((home/'identity-metadata.json').read_text())
token=(home/'git-token').read_text()
op=urllib.request.build_opener(urllib.request.ProxyHandler({}));base='http://'+meta['gitlabIp']+':'+str(meta['gitlabPort'])
results=[]
for repo in ['petclinic-platform','cook-gitops']:
 req=urllib.request.Request(base+'/root/'+repo+'.git/info/refs?service=git-receive-pack',headers={'Authorization':'Basic '+base64.b64encode(('oauth2:'+token).encode()).decode()})
 try:
  with op.open(req,timeout=8) as response:status=response.status
 except urllib.error.HTTPError as e:status=e.code
 results.append({'repository':repo,'receivePackAuthorizationHttp':status})
assert results[0]['receivePackAuthorizationHttp']==200 and results[1]['receivePackAuthorizationHttp'] in [401,403,404]
probe=r"""import os,json,pathlib
proof=pathlib.Path('/var/lib/security-gitops-demo-proofs/forged.json')
try:fd=os.open(proof,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o440);os.close(fd);raise RuntimeError('Writer could forge server proof')
except PermissionError:pass
print(json.dumps({'uid':os.getuid(),'groups':os.getgroups(),'cannotForgeProof':True,'dockerReadable':os.access('/run/docker.sock',os.R_OK),'kubeReadable':os.access('/etc/rancher/k3s/k3s.yaml',os.R_OK),'oldScannerOutputsReadable':os.access('/var/tmp/security-manager-gitleaks-v2-linux-20261105/outputs',os.R_OK)}))
"""
identity=json.loads(subprocess.check_output(['/usr/bin/setpriv','--reuid=24022','--regid=24022','--clear-groups','--no-new-privs','/usr/bin/python3','-I','-c',probe],text=True,timeout=5))
assert not identity['dockerReadable'] and not identity['kubeReadable'] and not identity['oldScannerOutputsReadable']
print(json.dumps({'gitLabReceivePackChecks':results,'identity':identity,'mainWritePolicyProof':{'projectRole':30,'protectedMainMinimumRole':40,'mainWriteAttempted':False,'forcedCommandMainDenied':True},'tokenExported':False,'gitWrites':0}))
'''
h=remote(host,35);save('negative-identity.json',h);print(json.dumps(h))
