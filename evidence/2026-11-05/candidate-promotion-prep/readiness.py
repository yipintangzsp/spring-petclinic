"""Read-only registry, GitOps and archived approval preflight. No pull/scan/sign/build."""
import json,runpy
from pathlib import Path
OUT=Path(__file__).resolve().parent
p=runpy.run_path(str(OUT.parent/'gitlab-push-demo/preflight.py'))
code=p['PREFIX']+r'''
import java.security.MessageDigest
def hash={byte[] b->MessageDigest.getInstance('SHA-256').digest(b).encodeHex().toString()}
def branch=api('/projects/12/repository/branches/main')
def file=api('/projects/12/repository/files/k8s%2Fproduction%2Fpetclinic.yaml?ref='+branch.commit.id)
def b=j.getBuildByNumber(270),af=b.artifacts.collect{it.relativePath}
def summaryFile=new File(b.artifactsDir,'.devsecops/security-summary.json')
def summary=new JsonSlurper().parse(summaryFile)
def approvalNames=['candidate-sbom.json','approval-signing.json','approved-release.json','approved-release.sig','promotion-result.json']
def approvals=approvalNames.collectEntries{n->[(n):af.contains('.devsecops/'+n)]}
def bp=b.getAction(hudson.model.ParametersAction)
def c=CredentialsProvider.findCredentialById('harbor-creds',StandardUsernamePasswordCredentials.class,b);assert c
String base='http://harbor-core.harbor.svc.cluster.local'
def basic='Basic '+(c.username+':'+c.password.plainText).getBytes('UTF-8').encodeBase64().toString()
def request={String path,String auth,String method->
 def v=new URL(base+path).openConnection();v.setInstanceFollowRedirects(false);v.requestMethod=method
 v.setRequestProperty('Authorization',auth);v.setRequestProperty('Accept','application/vnd.oci.image.index.v1+json, application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.list.v2+json, application/vnd.docker.distribution.manifest.v2+json, application/json')
 v.connectTimeout=4000;v.readTimeout=6000
 int status=v.responseCode
 byte[] bytes=status==200&&method=='GET'?v.inputStream.readNBytes(131073):new byte[0]
 assert bytes.length<=131072
 v.disconnect()
 [status:status,bytes:bytes]
}
def parse={byte[] bytes->new JsonSlurper().parseText(new String(bytes,'UTF-8'))}
def t=request('/service/token?service=harbor-registry&scope=repository%3Apetclinic%2Fpetclinic%3Apull',basic,'GET');assert t.status==200
String bearer='Bearer '+parse(t.bytes).token
String repo='/v2/petclinic/petclinic/'
def manifest={String dg->
 def r=request(repo+'manifests/'+dg,bearer,'GET');assert r.status==200:'Manifest read HTTP '+r.status
 assert 'sha256:'+hash(r.bytes)==dg
 parse(r.bytes)
}
def blobs=[:]
def indexes=['sha256:2fbaea65ab030c56c60c62e3ee9fbe362deb8bbbb8216a891ef4c7bbbcea6d55','sha256:489cb821573ff1f98edd846d5949d74bf3391b24e2f1fe5bcfb71c6be0793137'].collect{index->
 def v=manifest(index)
 def platforms=v.manifests.findAll{it.platform?.os=='linux' && it.platform?.architecture in ['arm64','amd64']}.collect{x->
  def child=manifest(x.digest)
  def ds=([child.config.digest]+child.layers.collect{it.digest}).unique()
  ds.each{dg->if(!blobs.containsKey(dg))blobs[dg]=request(repo+'blobs/'+dg,bearer,'HEAD').status}
  [arch:x.platform.architecture,digest:x.digest,config:child.config.digest,blobCount:ds.size(),allBlobsHttp200:ds.every{blobs[it]==200}]
 }
 def sig=request(repo+'manifests/'+index.replace(':','-')+'.sig',bearer,'HEAD').status
 [index:index,mediaType:v.mediaType,platforms:platforms,legacySignatureTagHttp:sig]
}
println(JsonOutput.toJson([observedAt:new Date().format("yyyy-MM-dd'T'HH:mm:ssXXX",TimeZone.getTimeZone('UTC')),
 gitops:[head:branch.commit.id,branch:'main',file:file.file_path,fileSha256:file.content_sha256,protectedBranch:branch.protected],
 security:[build:b.number,result:b.result.toString(),promotionAction:bp?.getParameter('PROMOTION_ACTION')?.value,
 auditCandidate:summary.auditTargetImage,source:summary.source,summarySha256:hash(summaryFile.bytes),high:summary.trivy_high,critical:summary.trivy_critical,
 targetScope:summary.targetScope,artifacts:approvals],harbor:[scope:'pull',indexes:indexes,blobCount:blobs.size(),blobStatusCounts:blobs.values().countBy{it}],
 productionJob:[latest:j.lastBuild.number,result:j.lastBuild.result.toString(),definitionSha256:hash(j.configFile.file.bytes)]]))
'''
r=p['script'](code)
with (OUT/'registry-gitops.json').open('x') as f:json.dump(r,f,indent=2)
print(json.dumps(r))
