import runpy,json,pathlib
HERE=pathlib.Path(__file__).resolve().parent
p=runpy.run_path('evidence/2026-11-05/gitlab-push-demo/preflight.py')
code=p['PREFIX']+r'''
import java.security.MessageDigest
def hash={byte[] b->MessageDigest.getInstance('SHA-256').digest(b).encodeHex().toString()}
def b=j.getBuildByNumber(270),c=Jenkins.instance.getItemByFullName('petclinic-candidate-build').getBuildByNumber(2)
def doc={build,name->def f=new File(build.artifactsDir,name);assert f.canonicalPath.startsWith(build.artifactsDir.canonicalPath+'/');f.exists()&&f.length()<524288?[path:name,sha256:hash(f.bytes),body:new JsonSlurper().parse(f)]:null}
def sboms=[]
[b,c].each{v->v.artifacts.findAll{it.relativePath.toLowerCase()=~ /sbom|cyclonedx|bom\.json/}.take(12).each{a->
 def f=new File(v.artifactsDir,a.relativePath);assert f.canonicalPath.startsWith(v.artifactsDir.canonicalPath+'/')
 def row=[job:v.parent.fullName,build:v.number,path:a.relativePath,bytes:f.length()]
 if(f.length()>0&&f.length()<4194304&&a.relativePath.endsWith('.json')){
  def d=new JsonSlurper().parse(f);row.sha256=hash(f.bytes)
  if(d.bomFormat=='CycloneDX')row+=[format:d.bomFormat,specVersion:d.specVersion,componentCount:d.components?.size()?:0,metadata:d.metadata,components:d.components?.take(30)?.collect{x->[name:x.name,version:x.version,purl:x.purl,type:x.type]}]
  else row.document=d
 };sboms<<row
}}
def hc=CredentialsProvider.findCredentialById('harbor-creds',StandardUsernamePasswordCredentials.class,b);assert hc
def basic='Basic '+(hc.username+':'+hc.password.plainText).getBytes('UTF-8').encodeBase64().toString()
def req={String path,String auth,String method->
 def x=new URL('http://harbor-core.harbor.svc.cluster.local'+path).openConnection();x.setInstanceFollowRedirects(false);x.requestMethod=method;x.setRequestProperty('Authorization',auth);x.setRequestProperty('Accept','application/vnd.oci.image.index.v1+json, application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.v2+json, application/json');x.connectTimeout=5000;x.readTimeout=9000
 int st=x.responseCode;byte[] bytes=st==200&&method=='GET'?x.inputStream.readNBytes(524289):new byte[0];assert bytes.length<=524288
 def d=bytes.length?new JsonSlurper().parseText(new String(bytes,'UTF-8')):null;x.disconnect();[status:st,body:d,sha256:bytes.length?hash(bytes):null]
}
String dg='sha256:2fbaea65ab030c56c60c62e3ee9fbe362deb8bbbb8216a891ef4c7bbbcea6d55'
def a=req('/api/v2.0/projects/petclinic/repositories/petclinic/artifacts/'+dg+'?with_tag=true',basic,'GET');assert a.status==200&&a.body.digest==dg
def t=req('/service/token?service=harbor-registry&scope=repository%3Apetclinic%2Fpetclinic%3Apull',basic,'GET');assert t.status==200
String bearer='Bearer '+t.body.token
 def idx=req('/v2/petclinic/petclinic/manifests/'+dg,bearer,'GET');assert 'sha256:'+idx.sha256==dg
 def signatures=([dg]+a.body.references.findAll{it.platform?.architecture in ['amd64','arm64']}.collect{it.child_digest}).collect{d->[digest:d,legacySignatureHttp:req('/v2/petclinic/petclinic/manifests/'+d.replace(':','-')+'.sig',bearer,'HEAD').status,referrers:req('/v2/petclinic/petclinic/referrers/'+d,bearer,'GET')]}
 def accessories=req('/api/v2.0/projects/petclinic/repositories/petclinic/artifacts/'+dg+'/accessories',basic,'GET')
def summary=doc(b,'.devsecops/security-summary.json')
println(JsonOutput.toJson([observedAt:new Date().format("yyyy-MM-dd'T'HH:mm:ssXXX",TimeZone.getTimeZone('UTC')),harbor:[digest:dg,tags:a.body.tags?.collect{it.name},mediaType:a.body.media_type,references:a.body.references?.collect{[digest:it.child_digest,platform:it.platform]},indexHashVerified:true,signatures:signatures,accessories:accessories],
 sboms:sboms,candidateArtifactNames:c.artifacts.collect{it.relativePath},approvalArtifacts:b.artifacts.findAll{it.relativePath=~/approved-release|approval-signing|promotion-result|candidate-sbom/}.collect{it.relativePath},
 candidateBuild:[job:c.parent.fullName,number:c.number,result:c.result.toString(),commit:c.getAction(hudson.plugins.git.util.BuildData)?.lastBuiltRevision?.sha1?.name(),provenance:doc(c,'.devsecops/build-provenance.json'),verification:doc(c,'.devsecops/build-attestation-verification.json'),metadata:doc(c,'target/platform/image-build-metadata.json')],
 securityBuild:[job:b.parent.fullName,number:b.number,result:b.result.toString(),promotionAction:b.getAction(hudson.model.ParametersAction)?.getParameter('PROMOTION_ACTION')?.value,summary:summary],mutations:0,release:0,rollout:0]))
'''
x=p['script'](code)
with(HERE/'sources.json').open('x')as f:json.dump(x,f,indent=2)
print(json.dumps({'observedAt':x['observedAt'],'harbor':x['harbor'],'sboms':x['sboms'],'candidateArtifactNames':x['candidateArtifactNames'],'approvalArtifacts':x['approvalArtifacts'],'securityBuildAction':x['securityBuild']['promotionAction']}))
