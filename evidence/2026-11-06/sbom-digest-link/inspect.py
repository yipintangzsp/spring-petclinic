import runpy,json,pathlib
p=runpy.run_path('evidence/2026-11-05/gitlab-push-demo/preflight.py')
code=p['PREFIX']+r'''
import java.security.MessageDigest
def sha={byte[] b->MessageDigest.getInstance('SHA-256').digest(b).encodeHex().toString()}
def ci=j.getBuildByNumber(270),builder=Jenkins.instance.getItemByFullName('petclinic-candidate-build').getBuildByNumber(2)
def read={b,name->def f=new File(b.artifactsDir,name);if(!f.exists())return null;assert f.canonicalPath.startsWith(b.artifactsDir.canonicalPath+'/')&&f.length()<1048576;[path:name,sha256:sha(f.bytes),body:new JsonSlurper().parse(f)]}
def s=read(ci,'.devsecops/sbom-summary.json'),prov=read(builder,'.devsecops/build-provenance.json')
def bomFile=new File(ci.artifactsDir,'.devsecops/sbom.json');assert bomFile.length()<1048576;def bom=new JsonSlurper().parse(bomFile)
def docs=['.devsecops/build-compilation.json','.devsecops/candidate-sbom.json','.devsecops/sbom-verification.json','.devsecops/build-attestation-verification.json'].collect{[path:it,securityBuild:read(ci,it),candidateBuild:read(builder,it)]}
def candidateJar=prov.body.context.files.find{it.name=='target/spring-petclinic-4.0.0-SNAPSHOT.jar'}
println(JsonOutput.toJson([queriedAt:new Date().format("yyyy-MM-dd'T'HH:mm:ssXXX",TimeZone.getTimeZone('UTC')),candidate:[indexDigest:prov.body.buildkit.outputDigest,sourceCommit:prov.body.source.commit,build:2,jarSha256:prov.body.compilation.jarSha256,contextJar:candidateJar,completedAt:prov.body.finishedAt,platforms:prov.body.platforms,provenanceContainsSbomReference:prov.body.toString().toLowerCase().contains('sbom')],
 sbom:[job:'petclinic-ci',build:270,summary:s,actualSha256:sha(bomFile.bytes),bomFormat:bom.bomFormat,specVersion:bom.specVersion,components:bom.components.size(),subject:bom.metadata.component,metadataProperties:bom.metadata.properties],possibleBindingDocuments:docs,
 archiveAvailability:[candidateBuild:builder.artifacts.collect{it.relativePath},securityBuild:ci.artifacts.findAll{it.relativePath=~/.*(\.jar|\.tar|sbom|compilation|provenance).*/}.collect{it.relativePath}],newOperations:0]))
'''
x=p['script'](code)
with pathlib.Path('evidence/2026-11-06/sbom-digest-link/inspection.json').open('x')as f:json.dump(x,f,indent=2)
print(json.dumps({'candidate':x['candidate'],'sbom':{k:v for k,v in x['sbom'].items()if k not in ['subject','metadataProperties']},'archiveAvailability':x['archiveAvailability'],'availableBindingDocs':[{'path':d['path'],'securityBuild':bool(d['securityBuild']),'candidateBuild':bool(d['candidateBuild'])}for d in x['possibleBindingDocuments']]}))
