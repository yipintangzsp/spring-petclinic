from pathlib import Path
import json,subprocess,shlex,sys,urllib.parse
O=Path(__file__).resolve().parent;sys.dont_write_bytecode=True;sys.path.insert(0,'/Users/zhangsir/code/evidence/platform-20261011');from jenkins_control import NODE
script=r'''import groovy.json.JsonOutput
import java.security.MessageDigest
def rows=['petclinic-ci','security-runtime-facts-20261102'].collect{name->
 def j=Jenkins.instance.getItemByFullName(name);assert j!=null
 def builds=j.builds.collect{b->
  def hits=b.artifacts.findAll{a->a.relativePath==~/.*(?i:v2ray|xray|binConfigs|config\.json).*/}.collect{a->
   def f=new File(b.artifactsDir,a.relativePath)
   [path:a.relativePath,bytes:f.length(),sha256:f.isFile()&&f.length()<1048576?MessageDigest.getInstance('SHA-256').digest(f.bytes).encodeHex().toString():null]
  }
  [build:b.number,result:b.result?.toString(),started:b.startTimeInMillis,artifactCount:b.artifacts.size(),candidateArtifacts:hits]
 }
 [job:name,latest:j.lastBuild.number,builds:builds]
}
println(JsonOutput.toJson([classification:'READ_ONLY_EXISTING_JENKINS_ARCHIVE_METADATA_SEARCH',jobs:rows,consoleContentsRead:false,credentialsRead:false,newBuilds:0]))'''
payload={'path':'/scriptText','method':'POST','type':'application/x-www-form-urlencoded','body':urllib.parse.urlencode({'script':script}),'timeout':45000}
S=['ssh','-o','BatchMode=yes','-o','ConnectTimeout=6','-o','StrictHostKeyChecking=yes','-o','HostName=192.168.64.11','-o','HostKeyAlias=192.168.1.58','zhang@192.168.1.58']
p=subprocess.run(S+['sudo -n kubectl exec -i -n ns-devops deploy/github-webhook-relay -- node --max-old-space-size=24 -e '+shlex.quote(NODE)],input=json.dumps(payload),capture_output=True,text=True,timeout=60)
assert p.returncode==0,'TRUSTED_SSH_READ_FAILED';r=json.loads(p.stdout);assert r['status']==200,'ARCHIVE_QUERY_REJECTED'
x=json.loads(r['body'].split('\n',1)[0]);(O/'jenkins-archive-search.json').write_text(json.dumps(x,indent=2)+'\n')
print(json.dumps({'jobs':[{'job':j['job'],'buildsInspected':len(j['builds']),'artifactsInspected':sum(b['artifactCount'] for b in j['builds']),'candidateCount':sum(len(b['candidateArtifacts']) for b in j['builds'])} for j in x['jobs']]}))
