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
def refs=["sha256:4e885a110390c5cb1dd56573f0ce418b4ed4cf51515647ae2d0f9a12bf16202a", "sha256:19f5e9e77fa4622c56e66e4e1e38ae38ff19e97a3e67fff098207207f2f9a3d5", "sha256:1eab3ddc626879b1efb7290b3dc1d7fd55922c2bf175d1a3ee59e08c00aff489", "sha256:30409763d6fe3e530047d15eec4a14058aa87c880af0f3f1b9b4b3dd43d0a2d1", "sha256:324b3017b67442f414cd31daaefc1f91d2da97b7cb560781b01dd2d345e181e5", "sha256:34a52e2f3e15b663c8d002c3beb80a32950fab21a7974592efcb4418f239c240", "sha256:59c43f6162318b26f8274103d114c26096a47858537461abdaae6bd3258e1a9a", "sha256:6359a27f2ff194de2c35b3d442afe65c9ab84bdf85ffb1c3cbdc8e27f3f81dc7", "sha256:6968ab32cef3878b3172c275985321d8bf3864dabe234c05c2c98797ec4970fd", "sha256:6bf073eaf46f4930106bfa1b78e7a1623fa73bfa1638b63de46eb5e5cc992570", "sha256:84f6dabe138f552cd5e5375ba24a5683fc961e3c062da8a5b5afeec51bacf364", "sha256:9c6a31c999bcda2b81d917784d6add32d887874c787f2253f14daab7581ff265", "sha256:a399b857351d6a94a2b0684d44d9c05c419b868ffe72e2826a1b4606184fdb15", "sha256:a6cf4653c121314624c1e0f1aed512892f6932923801a2b01effb94b2adbcd72", "sha256:afb78941b56b46d9e89af7cf99660caf1f94c31e4890dcda7f111b4e4c0bd6e0", "sha256:e229cb52cc5cd0b4c775edcd3cb082b39671a20988b8a77a9d47719d7712913f"]
def rows=refs.collect{d->
 def con=new URL('http://harbor-core.harbor.svc.cluster.local/api/v2.0/projects/petclinic/repositories/petclinic/artifacts/'+d+'?with_tag=true&with_accessory=true').openConnection()
 con.setRequestMethod('GET');con.setConnectTimeout(8000);con.setReadTimeout(12000)
 con.setRequestProperty('Authorization','Basic '+(c.username+':'+c.password.plainText).bytes.encodeBase64().toString())
 def code=con.responseCode,v=code==200?new JsonSlurperClassic().parseText(con.inputStream.getText('UTF-8')):null
 [digest:d,httpStatus:code,type:v?.type,size:v?.size,tags:v?.tags?.collect{[name:it.name,immutable:it.immutable]},references:v?.references?.collect{[digest:it.child_digest,platform:it.platform]},accessories:v?.accessories,accessoryEvidenceScope:v?.containsKey('accessories')?'API_FIELD_OBSERVED':'NOT_EXPOSED_NOT_PROOF_OF_ABSENCE',manifestLinks:v?.addition_links,artifactType:v?.artifact_type]
}
def j=Jenkins.instance.getItemByFullName('security-runtime-facts-20261102')
println(JsonOutput.toJson([method:'GET_ONLY',registryMutations:0,artifacts:rows,validationBuild:[number:j.lastBuild.number,result:j.lastBuild.result.toString(),building:j.lastBuild.building]]))
'''
payload={'path':'/scriptText','method':'POST','type':'application/x-www-form-urlencoded','body':urllib.parse.urlencode({'script':script}),'timeout':55000};S=['ssh','-o','BatchMode=yes','-o','ConnectTimeout=6','-o','StrictHostKeyChecking=yes','-o','HostName=192.168.64.11','-o','HostKeyAlias=192.168.1.58','zhang@192.168.1.58'];p=subprocess.run(S+['sudo -n kubectl exec -i -n ns-devops deploy/github-webhook-relay -- node -e '+shlex.quote(NODE)],input=json.dumps(payload),capture_output=True,text=True,timeout=65);assert p.returncode==0;r=json.loads(p.stdout);assert r['status']==200
try:x=json.loads(r['body'].split('\n',1)[0])
except Exception:raise SystemExit('Authorized registry read failed; no credential or response-body output')
(O/'harbor-unknown-graph.json').write_text(json.dumps(x,indent=2)+'\n');print(json.dumps(x))
