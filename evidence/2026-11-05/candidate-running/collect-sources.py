"""GET-only GitOps and Harbor lookup; credentials and pull token stay inside Jenkins."""
import runpy,json
from pathlib import Path
OUT=Path(__file__).resolve().parent
p=runpy.run_path(str(OUT.parent/'gitlab-push-demo/preflight.py'))
h=json.loads((OUT/'host.json').read_text());a=h['argo'];assert a['source']=={'path':'k8s/production','repoURL':'http://gitlab-service.ns-devops.svc.cluster.local/root/petclinic-platform.git','targetRevision':'main'}
image=h['deployment']['containers'][0]['image'];digest=image.split('@')[1]
assert digest.startswith('sha256:') and len(digest)==71
code=p['PREFIX']+r'''
import java.security.MessageDigest
import java.net.URLEncoder
def hash={byte[] b->MessageDigest.getInstance('SHA-256').digest(b).encodeHex().toString()}
def enc={String s->URLEncoder.encode(s,'UTF-8')}
def branch=api('/projects/12/repository/branches/main')
def revisions=[branch.commit.id,'@SYNC_REVISION@'].unique()
def gitops=revisions.collect{rev->
 def f=api('/projects/12/repository/files/k8s%2Fproduction%2Fpetclinic.yaml?ref='+rev)
 byte[] bytes=f.content.decodeBase64();assert bytes.length<131072
 assert f.content_sha256==hash(bytes)
 [revision:rev,path:f.file_path,sha256:hash(bytes),contentBase64:bytes.encodeBase64().toString(),
 tree:api('/projects/12/repository/tree?path=k8s%2Fproduction&ref='+rev+'&per_page=100').collect{[name:it.name,type:it.type]}]
}
def hc=CredentialsProvider.findCredentialById('harbor-creds',StandardUsernamePasswordCredentials.class,j.getBuildByNumber(270));assert hc
def base='http://harbor-core.harbor.svc.cluster.local'
def basic='Basic '+(hc.username+':'+hc.password.plainText).getBytes('UTF-8').encodeBase64().toString()
def get={String path,String auth->
 def c=new URL(base+path).openConnection();c.setRequestProperty('Authorization',auth)
 c.setRequestProperty('Accept','application/vnd.oci.image.index.v1+json, application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.list.v2+json, application/vnd.docker.distribution.manifest.v2+json, application/json')
 c.connectTimeout=6000;c.readTimeout=10000
 assert c.responseCode==200:'Read-only Harbor GET HTTP '+c.responseCode
 byte[] b=c.inputStream.readNBytes(524289);assert b.length<=524288
 [bytes:b,document:new JsonSlurper().parseText(new String(b,'UTF-8'))]
}
def token=get('/service/token?service=harbor-registry&scope=repository%3Apetclinic%2Fpetclinic%3Apull',basic).document.token
assert token
def manifests=[:]
def raw={String dg->
 def r=get('/v2/petclinic/petclinic/manifests/'+dg,'Bearer '+token)
 assert 'sha256:'+hash(r.bytes)==dg
 manifests[dg]=r.document
 r.document
}
def artifacts=['sha256:2fbaea65ab030c56c60c62e3ee9fbe362deb8bbbb8216a891ef4c7bbbcea6d55','@RUNNING_DIGEST@'].unique().collect{dg->
 def r=get('/api/v2.0/projects/petclinic/repositories/petclinic/artifacts/'+dg+'?with_tag=true',basic).document
 assert r.digest==dg
 def index=raw(dg)
 [digest:r.digest,http:200,type:r.type,mediaType:r.media_type,
 tags:r.tags?.collect{it.name},pushTime:r.push_time,references:r.references?.collect{[digest:it.child_digest,platform:it.platform]}]
}
def running=manifests['@RUNNING_DIGEST@']
assert running.manifests instanceof List
running.manifests.findAll{it.platform?.os=='linux' && it.platform?.architecture in ['arm64','amd64']}.each{raw(it.digest)}
def b=j.getBuildByNumber(270),sf=new File(b.artifactsDir,'.devsecops/security-summary.json')
println(JsonOutput.toJson([observedAt:new Date().format("yyyy-MM-dd'T'HH:mm:ssXXX",TimeZone.getTimeZone('UTC')),
 gitops:[projectId:12,repository:'http://gitlab-service.ns-devops.svc.cluster.local/root/petclinic-platform.git',branch:'main',head:branch.commit.id,files:gitops],
 harbor:[artifacts:artifacts,manifests:manifests,rawManifestDigestsVerified:true,pullOnly:true],
 historicalReleaseVerification:[build:270,source:'.devsecops/gates/Read-Only-Release-Verification.txt',
 content:new File(b.artifactsDir,'.devsecops/gates/Read-Only-Release-Verification.txt').text],
 productionJob:[latestBuild:j.lastBuild.number,result:j.lastBuild.result.toString(),definitionSha256:hash(j.configFile.file.bytes),summarySha256:hash(sf.bytes)],release:0,rollout:0]))
'''
code=code.replace('@SYNC_REVISION@',a['sync']['revision']).replace('@RUNNING_DIGEST@',digest)
r=p['script'](code)
with (OUT/'sources.json').open('x') as f:json.dump(r,f,indent=2)
print(json.dumps({'observedAt':r['observedAt'],'gitopsHead':r['gitops']['head'],'revisions':[x['revision'] for x in r['gitops']['files']],
 'harborArtifacts':r['harbor']['artifacts'],'verifiedManifests':list(r['harbor']['manifests']),'historicalReleaseVerification':r['historicalReleaseVerification']}))
