"""Read existing Jenkins archives and one exact Harbor artifact; no build or write API."""
import runpy,json,datetime
from pathlib import Path
OUT=Path(__file__).resolve().parent
p=runpy.run_path(str(OUT.parent/'gitlab-push-demo/preflight.py'))
code=p['PREFIX']+r'''
import java.security.MessageDigest
def hash={byte[] b->MessageDigest.getInstance('SHA-256').digest(b).encodeHex().toString()}
def build={job,n->Jenkins.instance.getItemByFullName(job).getBuildByNumber(n)}
def safeBuild={b->[job:b.parent.fullName,number:b.number,result:b.result.toString(),timestamp:b.timeInMillis,duration:b.duration,
 url:'http://jenkins.devops.local/job/'+b.parent.fullName+'/'+b.number+'/',commit:b.getAction(hudson.plugins.git.util.BuildData)?.lastBuiltRevision?.sha1?.name()]}
def c=build('petclinic-candidate-build',2),b=build('petclinic-ci',270)
def read={v,name->
 def file=new File(v.artifactsDir,name)
 assert file.canonicalPath.startsWith(v.artifactsDir.canonicalPath+'/') && file.length()<524288
 file.exists()?[path:name,sha256:hash(file.bytes),body:new JsonSlurper().parse(file)]:null
}
def s=read(b,'.devsecops/security-summary.json')
def summary=[:];['schema','build','build_result','project','pipeline','source','recorded_at','securityMode','securityProfile','auditTargetImage','runtimeImage',
'gitleaks_status','gitleaks_findings','semgrep_status','semgrep_blocking','cosign_status','cosign_verified','build_provenance_status','trivy_status','sonar_status','missing'].each{k->if(s.body.containsKey(k))summary[k]=s.body[k]}
def scanReports=['.devsecops/provenance.json','.devsecops/build-attestation-verification.json','.devsecops/security-manager.json']
def builderReports=['.devsecops/build-provenance.json','.devsecops/build-attestation-verification.json','target/platform/image-build-metadata.json']
def hc=CredentialsProvider.findCredentialById('harbor-creds',StandardUsernamePasswordCredentials.class,b);assert hc
String image='sha256:2fbaea65ab030c56c60c62e3ee9fbe362deb8bbbb8216a891ef4c7bbbcea6d55'
def url='http://harbor-core.harbor.svc.cluster.local/api/v2.0/projects/petclinic/repositories/petclinic/artifacts/'+image+'?with_tag=true'
def h=new URL(url).openConnection();h.setRequestProperty('Authorization','Basic '+(hc.username+':'+hc.password.plainText).getBytes('UTF-8').encodeBase64().toString());h.connectTimeout=6000;h.readTimeout=12000
assert h.responseCode==200:'Harbor read HTTP '+h.responseCode
def a=new JsonSlurper().parseText(h.inputStream.text)
def harbor=[http:h.responseCode,id:a.id,digest:a.digest,repositoryId:a.repository_id,type:a.type,mediaType:a.media_type,size:a.size,pushTime:a.push_time,
 tags:a.tags?.collect{[name:it.name,pushTime:it.push_time]},extraAttributes:a.extra_attrs,labels:a.labels?.collect{[name:it.name,value:it.value]},references:a.references?.collect{[digest:it.child_digest,platform:it.platform]}]
def logs=b.getLog(1200).findAll{line->line.contains('Gate')||line.contains('gate exit')||line.contains('Finished:')||line.contains('build-attestation')||line.contains('Read Only Release')}.take(50)
println(JsonOutput.toJson([observedAt:new Date().format("yyyy-MM-dd'T'HH:mm:ssXXX",TimeZone.getTimeZone('UTC')),
 securityBuild:safeBuild(b),summary:summary,summarySha256:s.sha256,securityReports:scanReports.collect{read(b,it)},
 candidateBuild:safeBuild(c),candidateArtifacts:c.artifacts.collect{it.relativePath},builderReports:builderReports.collect{read(c,it)},
 gateLogExcerpt:logs,harbor:harbor,productionJobDefinitionSha256:hash(j.configFile.file.bytes),latestProductionBuild:j.lastBuild.number,
 productionMain:api('/projects/12/repository/branches/main').commit.id,release:0,rollout:0]))
'''
r=p['script'](code)
with (OUT/'sources.json').open('x') as f:json.dump(r,f,indent=2)
print(json.dumps({k:r[k] for k in ['observedAt','securityBuild','summary','candidateBuild','harbor','candidateArtifacts','gateLogExcerpt']}))
