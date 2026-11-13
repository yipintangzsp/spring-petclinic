"""Inspect historical records only: never enqueue or edit a Jenkins job."""
from collect import call
import json
script=r'''
import groovy.json.JsonOutput
 def job=Jenkins.instance.getItemByFullName('petclinic-ci')
 def builds=job.builds.findAll{!it.isBuilding() && it.result?.toString()=='FAILURE'}.take(300)
 def rows=[];long total=0;long budget=200*1024*1024
 for(b in builds){
  def f=b.logFile
  if(!f.exists()){rows<<[build:b.number,missingLog:true];continue}
  if(total+f.length()>budget){rows<<[build:b.number,skipped:'bounded 200MiB read budget'];break}
  total+=f.length();def actual=[];def identity=[]
  f.withReader('UTF-8'){reader -> reader.eachLine{line ->
   if(line=~/\[(?:ERROR|INFO)\]\s+QUALITY GATE STATUS:\s+(FAILED|PASSED)/){if(actual.size()<10)actual<<line.replaceAll('\u001B\\[[0-9;]*m','')}
   if(line.contains('/api/ce/task?id=')||line.contains('ceTaskId=')||line.contains('analysisId=')){if(identity.size()<10)identity<<line.take(600)}
  }}
  def matches=b.getArtifacts().findAll{a -> (a.relativePath=~/(?i)(report-task\.txt|sonar[^\/]*\.(json|log)|quality[^\/]*\.json)$/)}.take(25).collect{[path:it.relativePath]}
  rows<<[build:b.number,result:b.result.toString(),timestamp:b.startTimeInMillis,duration:b.duration,actualGateLines:actual,identityLines:identity,artifacts:matches]
 }
 println(JsonOutput.toJson([job:job.fullName,examined:rows.size(),failureBuildsAvailable:builds.size(),logBytes:total,scope:'Completed FAILURE builds only; actual Maven Gate lines; Jenkins FAILURE alone is not Sonar failure',rows:rows]))
'''
x=call(script,'historical-failure-search.json')
print(json.dumps({'examined':x['examined'],'available':x['failureBuildsAvailable'],'logMiB':round(x['logBytes']/1048576,2),'actualSonarFailures':[r for r in x['rows'] if any('FAILED' in l for l in r.get('actualGateLines',[]))],'artifactCandidates':[r for r in x['rows'] if r.get('artifacts') or r.get('identityLines')]},indent=2))
