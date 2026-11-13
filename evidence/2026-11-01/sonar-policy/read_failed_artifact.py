from collect import call
import json
script=r'''
import groovy.json.JsonOutput
import groovy.json.JsonSlurper
 def b=Jenkins.instance.getItemByFullName('petclinic-ci').getBuildByNumber(174)
 def path='target/platform/sonar-quality.json'
 def f=b.artifactManager.root().child(path)
 assert f.exists():'Archived Sonar quality report missing'
 def report=new JsonSlurper().parseText(f.open().getText('UTF-8'))
 def a=b.getAllActions().findAll{it?.getClass()?.getName()?.toLowerCase()?.contains('sonar')}.collect{it.getClass().getName()}
 def artifactPaths=b.getArtifacts().collect{it.relativePath}
 def lines=[]
 b.logFile.withReader('UTF-8'){r -> r.eachLine{l -> if(l=~/\[ERROR\]\s+QUALITY GATE STATUS:\s+FAILED/)lines<<l}}
 println(JsonOutput.toJson([job:b.parent.fullName,build:b.number,result:b.result.toString(),artifactPath:path,gate:report.gate,sonarActionClasses:a,artifactPaths:artifactPaths,gateFailureLog:lines,analysisTaskBinding:'Not present in this archived report; project-level quality query only']))
'''
x=call(script,'build-174-failed-gate-artifact.json')
print(json.dumps({'build':x['build'],'gate':x['gate'],'sonarActions':x['sonarActionClasses'],'taskArtifacts':[p for p in x['artifactPaths'] if 'report-task' in p or 'analysis' in p.lower()],'gateFailureLog':x['gateFailureLog']},indent=2))
