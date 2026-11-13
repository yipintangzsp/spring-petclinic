from pathlib import Path
import json,subprocess,shlex,urllib.parse,sys
sys.dont_write_bytecode=True;sys.path.insert(0,'/Users/zhangsir/code/evidence/platform-20261011');from jenkins_control import NODE
O=Path(__file__).resolve().parent
script=r'''
import groovy.json.JsonOutput
import groovy.json.JsonSlurperClassic
import com.cloudbees.plugins.credentials.CredentialsProvider
import com.cloudbees.plugins.credentials.common.StandardUsernamePasswordCredentials
def c=CredentialsProvider.lookupCredentials(StandardUsernamePasswordCredentials.class,Jenkins.instance,null,null).find{it.id=='harbor-creds'}
if(c==null)throw new IllegalStateException('Existing authorized read credential absent; no fallback')
def refs=['489cb821573ff1f98edd846d5949d74bf3391b24e2f1fe5bcfb71c6be0793137','a8c03e462e44ec81d4b685dd88618ab5fd0b3847411ddcd067d8a92b2071e268','2fbaea65ab030c56c60c62e3ee9fbe362deb8bbbb8216a891ef4c7bbbcea6d55','83c2ae787a3d160cad1681228a669ac46afb19000558f4eefb45da50f08bf05c']
def rows=refs.collect{d->
 def con=new URL('http://harbor-core.harbor.svc.cluster.local/api/v2.0/projects/petclinic/repositories/petclinic/artifacts/sha256:'+d).openConnection()
 con.setRequestMethod('GET');con.setConnectTimeout(8000);con.setReadTimeout(12000)
 con.setRequestProperty('Authorization','Basic '+(c.username+':'+c.password.plainText).bytes.encodeBase64().toString())
 def code=con.responseCode,v=code==200?new JsonSlurperClassic().parseText(con.inputStream.getText('UTF-8')):null
 [digest:'sha256:'+d,httpStatus:code,tags:v?.tags?.collect{[name:it.name,immutable:it.immutable]},references:v?.references?.collect{[digest:it.child_digest,platform:it.platform]}]
}
def j=Jenkins.instance.getItemByFullName('security-runtime-facts-20261102')
println(JsonOutput.toJson([method:'GET_ONLY',registryMutations:0,artifacts:rows,validationBuild:[number:j.lastBuild.number,result:j.lastBuild.result.toString(),building:j.lastBuild.building]]))
'''
payload={'path':'/scriptText','method':'POST','type':'application/x-www-form-urlencoded','body':urllib.parse.urlencode({'script':script}),'timeout':55000};S=['ssh','-o','BatchMode=yes','-o','ConnectTimeout=6','-o','StrictHostKeyChecking=yes','-o','HostName=192.168.64.11','-o','HostKeyAlias=192.168.1.58','zhang@192.168.1.58'];p=subprocess.run(S+['sudo -n kubectl exec -i -n ns-devops deploy/github-webhook-relay -- node -e '+shlex.quote(NODE)],input=json.dumps(payload),capture_output=True,text=True,timeout=65);assert p.returncode==0;r=json.loads(p.stdout);assert r['status']==200
try:x=json.loads(r['body'].split('\n',1)[0])
except Exception:raise SystemExit('Authorized registry read failed; no credential or response-body output')
(O/'registry-retention-final.json').write_text(json.dumps(x,indent=2)+'\n');print(json.dumps(x))
