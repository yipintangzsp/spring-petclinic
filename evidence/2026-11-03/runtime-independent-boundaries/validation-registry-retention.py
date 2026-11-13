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
def refs=new JsonSlurperClassic().parseText('[{"kind": "wrong-key", "reference": "ci-32-wrong-key", "expectedStatus": 200, "subjectDigest": "sha256:f798eb548f648cc099f5d44a424be6b7bbb13001c40eca2c6891fa6846d8591b"}, {"kind": "wrong-key-signature", "reference": "sha256-f798eb548f648cc099f5d44a424be6b7bbb13001c40eca2c6891fa6846d8591b.sig", "expectedStatus": 200, "subjectDigest": "sha256:f798eb548f648cc099f5d44a424be6b7bbb13001c40eca2c6891fa6846d8591b"}, {"kind": "signed", "reference": "ci-32-signed", "expectedStatus": 200, "subjectDigest": "sha256:a786348b1bfb3125c150d94d58d6edc51beb36fb832ad258e000b03fbab7d899"}, {"kind": "signed-signature", "reference": "sha256-a786348b1bfb3125c150d94d58d6edc51beb36fb832ad258e000b03fbab7d899.sig", "expectedStatus": 200, "subjectDigest": "sha256:a786348b1bfb3125c150d94d58d6edc51beb36fb832ad258e000b03fbab7d899"}, {"kind": "unsigned", "reference": "ci-32-unsigned", "expectedStatus": 200, "subjectDigest": "sha256:f17f3fdaee27ea057580ed001bf8ac61bad962b2e9c2dbd101dbefffb93eb64b"}, {"kind": "unsigned-signature", "reference": "sha256-f17f3fdaee27ea057580ed001bf8ac61bad962b2e9c2dbd101dbefffb93eb64b.sig", "expectedStatus": 404, "subjectDigest": "sha256:f17f3fdaee27ea057580ed001bf8ac61bad962b2e9c2dbd101dbefffb93eb64b"}]')
def rows=refs.collect{r->
 def con=new URL('http://harbor-core.harbor.svc.cluster.local/api/v2.0/projects/petclinic/repositories/signature-fixtures/artifacts/'+r.reference).openConnection()
 con.setRequestMethod('GET');con.setConnectTimeout(8000);con.setReadTimeout(12000)
 con.setRequestProperty('Authorization','Basic '+(c.username+':'+c.password.plainText).bytes.encodeBase64().toString())
 def code=con.responseCode,v=code==200?new JsonSlurperClassic().parseText(con.inputStream.getText('UTF-8')):null
 assert code==r.expectedStatus
 [kind:r.kind,reference:r.reference,httpStatus:code,artifactDigest:v?.digest,subjectDigest:r.subjectDigest,classification:'VALIDATION_ONLY',retention:'VALIDATION_RETAINED']
}
def j=Jenkins.instance.getItemByFullName('security-runtime-facts-20261102')
println(JsonOutput.toJson([method:'GET_ONLY',registryMutations:0,artifacts:rows,validationBuild:[number:j.lastBuild.number,result:j.lastBuild.result.toString(),building:j.lastBuild.building]]))
'''
payload={'path':'/scriptText','method':'POST','type':'application/x-www-form-urlencoded','body':urllib.parse.urlencode({'script':script}),'timeout':55000};S=['ssh','-o','BatchMode=yes','-o','ConnectTimeout=6','-o','StrictHostKeyChecking=yes','-o','HostName=192.168.64.11','-o','HostKeyAlias=192.168.1.58','zhang@192.168.1.58'];p=subprocess.run(S+['sudo -n kubectl exec -i -n ns-devops deploy/github-webhook-relay -- node -e '+shlex.quote(NODE)],input=json.dumps(payload),capture_output=True,text=True,timeout=65);assert p.returncode==0;r=json.loads(p.stdout);assert r['status']==200
try:x=json.loads(r['body'].split('\n',1)[0])
except Exception:raise SystemExit('Authorized registry read failed; no credential or response-body output')
(O/'validation-registry-retention.json').write_text(json.dumps(x,indent=2)+'\n');print(json.dumps(x))
