from pathlib import Path
import sys,json,subprocess,shlex,urllib.parse,hashlib
O=Path(__file__).resolve().parent;sys.dont_write_bytecode=True;sys.path.insert(0,'/Users/zhangsir/code/evidence/platform-20261011');from jenkins_control import NODE
script=r'''
import groovy.json.JsonOutput
import groovy.json.JsonSlurperClassic
import java.security.MessageDigest
def job=Jenkins.instance.getItemByFullName('security-runtime-facts-20261102')
def rows=(21..30).collect{n->
 def b=job.getBuildByNumber(n),f=new File(b.artifactsDir,'runtime-source-bundle.json'),e=b.execution
 def text=(e?.metaClass?.respondsTo(e,'getScript'))?e.getScript():null
 [build:n,result:b.result.toString(),runtimeSourceBundle:f.isFile()?new JsonSlurperClassic().parseText(f.getText('UTF-8')):null,definition:text,definitionSha256:text==null?null:MessageDigest.getInstance('SHA-256').digest(text.getBytes('UTF-8')).encodeHex().toString()]
}
println(JsonOutput.toJson(rows))
'''
payload={'path':'/scriptText','method':'POST','type':'application/x-www-form-urlencoded','body':urllib.parse.urlencode({'script':script}),'timeout':45000};S=['ssh','-o','BatchMode=yes','-o','ConnectTimeout=6','-o','StrictHostKeyChecking=yes','-o','HostName=192.168.64.11','-o','HostKeyAlias=192.168.1.58','zhang@192.168.1.58'];p=subprocess.run(S+['sudo -n kubectl exec -i -n ns-devops deploy/github-webhook-relay -- node -e '+shlex.quote(NODE)],input=json.dumps(payload),capture_output=True,text=True,timeout=55);assert p.returncode==0;r=json.loads(p.stdout);assert r['status']==200
rows=json.loads(r['body'].split('\n',1)[0]);summary=[]
for x in rows:
 n=x['build'];m=x.pop('runtimeSourceBundle');script=x.pop('definition')
 if m is not None:(O/f'build-{n}-runtime-source-bundle.json').write_text(json.dumps(m,indent=2)+'\n')
 if script is not None:(O/f'Jenkinsfile.build-{n}').write_text(script)
 summary.append({**x,'archivedBundlePresent':m is not None,'archivedDefinitionPresent':script is not None})
(O/'validation-build-identities.json').write_text(json.dumps(summary,indent=2)+'\n');print(json.dumps(summary))
