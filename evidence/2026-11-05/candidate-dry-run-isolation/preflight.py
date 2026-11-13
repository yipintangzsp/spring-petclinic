"""GET-only target/isolation check. Does not start the conditionally approved run."""
import json
import runpy
from pathlib import Path

OUT = Path(__file__).resolve().parent
p = runpy.run_path(str(OUT.parent / 'gitlab-push-demo/preflight.py'))
code = p['PREFIX'] + r'''
import java.security.MessageDigest
import org.jenkinsci.plugins.plaincredentials.StringCredentials
def hash={byte[] v->MessageDigest.getInstance('SHA-256').digest(v).encodeHex().toString()}
def b=j.getBuildByNumber(270)
def source='9a78cc89f22fa98fb1ffcc43e2ae279299471793'
def file={String name->def f=api('/projects/12/repository/files/'+java.net.URLEncoder.encode(name,'UTF-8')+'?ref='+source);new String(f.content.decodeBase64(),'UTF-8')}
def target=new JsonSlurper().parseText(file('infra/security/governance/dojo-target.json'))
def adapter=new JsonSlurper().parseText(file('resources/security-manager/petclinic-adapter.json'))
def sonar=adapter.find{it.id=='sonarqube'}
def oldDojo=new JsonSlurper().parse(new File(b.artifactsDir,'.devsecops/defectdojo-import.json'))
def readJson={String url,String auth->
 def c=new URL(url).openConnection();c.setInstanceFollowRedirects(false);c.setRequestProperty('Authorization',auth);c.connectTimeout=3000;c.readTimeout=4000
 int status=c.responseCode
 def data=null
 if(status==200){byte[] raw=c.inputStream.readNBytes(65537);assert raw.length<=65536;data=new JsonSlurper().parseText(new String(raw,'UTF-8'))}
 c.disconnect();[http:status,data:data]
}
def dc=CredentialsProvider.findCredentialById('defectdojo-api-token',StringCredentials.class,b);assert dc
def product=readJson(target.baseUrl+'/api/v2/products/'+target.product+'/','Token '+dc.secret.plainText)
def engagement=readJson(target.baseUrl+'/api/v2/engagements/'+target.engagement+'/','Token '+dc.secret.plainText)
def sc=CredentialsProvider.findCredentialById('sonar-token',StringCredentials.class,b);assert sc
def sonarProject=readJson('http://sonarqube-sonarqube.sonarqube.svc.cluster.local:9000/api/components/show?component=petclinic','Basic '+(sc.secret.plainText+':').getBytes('UTF-8').encodeBase64().toString())
def sf=new File(b.artifactsDir,'.devsecops/security-summary.json')
def branch=api('/projects/12/repository/branches/main')
println(JsonOutput.toJson([observedAt:new Date().format("yyyy-MM-dd'T'HH:mm:ssXXX",TimeZone.getTimeZone('UTC')),
 source:source,job:[latest:j.lastBuild.number,result:j.lastBuild.result?.toString(),building:j.isBuilding(),definitionSha256:hash(j.configFile.file.bytes),scmBranches:j.definition.scm.branches.collect{it.name},scriptPath:j.definition.scriptPath],
 sonar:[command:sonar.command,http:sonarProject.http,project:sonarProject.data?.component?.findAll{k,v->k in ['key','name','qualifier','visibility']}],
 dojo:[configuredTarget:target,productHttp:product.http,product:product.data?.findAll{k,v->k in ['id','name','description','prod_type']},engagementHttp:engagement.http,engagement:engagement.data?.findAll{k,v->k in ['id','name','product','engagement_type']},
 historicalBuild270:[status:oldDojo.status,product:oldDojo.product,engagement:oldDojo.engagement,importCount:oldDojo.imports?.size(),reviewedFalsePositiveCount:oldDojo.reviewedFalsePositives?.size()],
 equalsHistoricalProduct:target.product==oldDojo.product,equalsHistoricalEngagement:target.engagement==oldDojo.engagement],
 v1SummarySha256:hash(sf.bytes),gitopsMain:branch.commit.id,newBuildStarted:false,releaseCount:0,rolloutCount:0]))
'''
result = p['script'](code)
with (OUT / 'isolation.json').open('x') as f:
    json.dump(result, f, indent=2, ensure_ascii=False)
print(json.dumps(result, ensure_ascii=False))
