from collect import call
import json
script=r'''
import groovy.json.JsonOutput
import groovy.json.JsonSlurper
import com.cloudbees.plugins.credentials.CredentialsProvider
import org.jenkinsci.plugins.plaincredentials.StringCredentials
import java.net.URLEncoder
 def cred=CredentialsProvider.lookupCredentials(StringCredentials.class,Jenkins.instance,null,null).find{it.id=='sonar-token'}
 assert cred!=null:'Existing sonar-token not found'
 def base='http://sonarqube-sonarqube.sonarqube.svc.cluster.local:9000'
 def partial=[:]
 def get={String path ->
  def connection=new URL(base+path).openConnection();connection.setConnectTimeout(10000);connection.setReadTimeout(15000)
  connection.setRequestProperty('Authorization','Bearer '+cred.secret.plainText)
  if(connection.responseCode!=200){println(JsonOutput.toJson([status:'BLOCKED',endpoint:path,httpStatus:connection.responseCode,partial:partial]));throw new RuntimeException('READ_ONLY_STOP')}
  def value=new JsonSlurper().parseText(connection.inputStream.getText('UTF-8'));partial[path]=value;value
 }
 def props=new Properties();def file=new File('/var/jenkins_home/workspace/petclinic-ci/target/sonar/report-task.txt');file.withInputStream{props.load(it)}
 assert props.projectKey=='petclinic' && props.ceTaskId==~/[a-f0-9-]+/
 def task=get('/api/ce/task?id='+props.ceTaskId)
 assert task.task.status=='SUCCESS' && task.task.componentKey==props.projectKey && task.task.analysisId
 def id=task.task.analysisId
 def gate=get('/api/qualitygates/project_status?analysisId='+URLEncoder.encode(id,'UTF-8'))
 def analyses=get('/api/project_analyses/search?project='+props.projectKey+'&ps=100')
 def analysis=analyses.analyses.find{it.key==id};assert analysis!=null:'Exact analysis absent from returned history'
 def b=Jenkins.instance.getItemByFullName('petclinic-ci').getBuildByNumber(270)
 def revisions=b.getAllActions().findAll{it?.getClass()?.getName()?.contains('BuildData')}.collect{it.lastBuiltRevision?.SHA1String}
 def log=b.getLog(20000).findAll{it.contains('QUALITY GATE STATUS:')}
 println(JsonOutput.toJson([collectedAt:new Date().format("yyyy-MM-dd'T'HH:mm:ssXXX"),reportTask:[projectKey:props.projectKey,ceTaskId:props.ceTaskId,serverVersion:props.serverVersion,modifiedAt:file.lastModified()],task:task,analysis:analysis,gate:gate,jenkins:[job:b.parent.fullName,build:b.number,result:b.result.toString(),startedAt:b.startTimeInMillis,duration:b.duration,sourceRevisions:revisions,gateLog:log],bindingLimitations:'Task identity from preserved workspace report-task; corroborated using analysis revision and build/stage timestamps, not a Jenkins SonarAnalysisAction.']))
'''
x=call(script,'sonar-analysis-evidence.json')
print(json.dumps(x,indent=2))
