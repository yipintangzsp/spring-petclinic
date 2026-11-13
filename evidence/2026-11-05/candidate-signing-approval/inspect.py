"""Bounded read-only signature/approval check. Never starts jobs or signs."""
import json
import runpy
from pathlib import Path

OUT = Path(__file__).resolve().parent
p = runpy.run_path(str(OUT.parent / 'gitlab-push-demo/preflight.py'))
code = p['PREFIX'] + r'''
import java.security.MessageDigest
def hash={byte[] b->MessageDigest.getInstance('SHA-256').digest(b).encodeHex().toString()}
def b=j.getBuildByNumber(270)
def params=b.getAction(hudson.model.ParametersAction)
def sf=new File(b.artifactsDir,'.devsecops/security-summary.json')
def summary=new JsonSlurper().parse(sf)
def names=b.artifacts.collect{it.relativePath}
def c=CredentialsProvider.findCredentialById('harbor-creds',StandardUsernamePasswordCredentials.class,b);assert c
String base='http://harbor-core.harbor.svc.cluster.local'
def basic='Basic '+(c.username+':'+c.password.plainText).getBytes('UTF-8').encodeBase64().toString()
def req={String path,String auth,String method->
 def v=new URL(base+path).openConnection();v.setInstanceFollowRedirects(false);v.requestMethod=method
 v.setRequestProperty('Authorization',auth)
 v.setRequestProperty('Accept','application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.v2+json, application/json')
 v.connectTimeout=4000;v.readTimeout=5000
 int status=v.responseCode
 byte[] bytes=status==200&&method=='GET'?v.inputStream.readNBytes(16385):new byte[0]
 assert bytes.length<=16384
 v.disconnect();[status:status,bytes:bytes]
}
def t=req('/service/token?service=harbor-registry&scope=repository%3Apetclinic%2Fpetclinic%3Apull',basic,'GET');assert t.status==200
String bearer='Bearer '+new JsonSlurper().parseText(new String(t.bytes,'UTF-8')).token
def signatures=['index':'sha256:2fbaea65ab030c56c60c62e3ee9fbe362deb8bbbb8216a891ef4c7bbbcea6d55',
 'arm64':'sha256:06a515708b6783db7d545544bbefb02e9f94abfc0fdf13a7355ccbe2deb3ed42',
 'amd64':'sha256:2bd9c1c445afbf55e390bfc41910551c32e09913143f7a137038cc87941b7c94'].collectEntries{k,dg->
 [(k):[digest:dg,legacySignatureTag:dg.replace(':','-')+'.sig',http:req('/v2/petclinic/petclinic/manifests/'+dg.replace(':','-')+'.sig',bearer,'HEAD').status]]
}
def branch=api('/projects/12/repository/branches/main')
println(JsonOutput.toJson([observedAt:new Date().format("yyyy-MM-dd'T'HH:mm:ssXXX",TimeZone.getTimeZone('UTC')),
 source:'LIVE_READ_ONLY',productionJob:[latest:j.lastBuild.number,result:j.lastBuild.result?.toString(),building:j.isBuilding(),definitionSha256:hash(j.configFile.file.bytes),queueItems:Jenkins.instance.queue.items.findAll{it.task==j}.size()],
 build270:[result:b.result?.toString(),promotionAction:params?.getParameter('PROMOTION_ACTION')?.value,
 candidate:summary.auditTargetImage,source:summary.source,summarySha256:hash(sf.bytes),
 securitySummary:summary.findAll{k,v->k in ['securityGate','gate','mode','status','targetScope','trivy_high','trivy_critical']},
 approvalArtifacts:['candidate-sbom.json','approval-signing.json','approved-release.json','approved-release.sig','promotion-result.json'].collectEntries{n->[(n):names.contains('.devsecops/'+n)]}],
 gitopsMain:branch.commit.id,signatureLookup:signatures,lookupScope:'repository:petclinic/petclinic:pull; HEAD legacy tags used by current Cosign workflow',
 releaseCount:0,rolloutCount:0]))
'''
result = p['script'](code)
with (OUT / 'observed.json').open('x') as f:
    json.dump(result, f, indent=2)
print(json.dumps(result))
