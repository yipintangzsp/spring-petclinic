// Local execution of only the unchanged approval/promotion stage fragment. No actual Jenkins steps.
import groovy.json.JsonSlurper
import groovy.json.JsonOutput

def text=new File('Jenkinsfile.security-audit').text
int start=text.indexOf("stage('Candidate Approval Evidence') {")
int end=text.indexOf('\n}\npost {',start)
assert start>=0 && end>start
def fragment=text.substring(start,end)
def mainText=new File('Jenkinsfile').text
def mainStart=mainText.indexOf("stage('Git Promotion') {")
def mainEnd=mainText.indexOf("stage('Wait for ArgoCD Sync') {",mainStart)
def mainFragment=mainText.substring(mainStart,mainEnd)
def outputs=[]
new JsonSlurper().parse(new File(args[0])).each{ row ->
 def state=[params:[PROMOTION_ACTION:row.action],currentBuild:[currentResult:row.initialResult],env:[:]],selected=[],commands=[],failure=null,currentStage=''
 boolean enabled=false
 def script=new GroovyShell(new Binding(state)).parse(row.variant=='private-main'?mainFragment:fragment)
 def fail={ key ->if(row.stepErrors[key])throw new RuntimeException(row.stepErrors[key]) }
 script.metaClass.stage={ String name,Closure body ->
  currentStage=name
  enabled=true
  try{body()}catch(Exception error){state.currentBuild.currentResult='FAILURE';failure=error.message}
 }
 script.metaClass.when={ Closure body ->enabled=false;body() }
 script.metaClass.expression={ Closure body ->enabled=body() }
 script.metaClass.steps={ Closure body ->if(enabled){selected<<currentStage;fail('stage:'+currentStage);body()} }
 script.metaClass.string={ Map c ->c }
 script.metaClass.file={ Map c ->c }
 script.metaClass.usernamePassword={ Map c ->c }
 script.metaClass.withCredentials={ List c,Closure body ->fail('credentials:'+currentStage);body() }
 script.metaClass.withEnv={ List values,Closure body ->fail('environment:'+currentStage);body() }
 script.metaClass.script={ Closure body ->body() }
 script.metaClass.sh={ Object arg ->
  def opts=arg instanceof Map?arg:[script:arg.toString()]
  commands<<opts.script;fail('sh:'+currentStage)
  if(opts.returnStdout)return row.approvedDigest+'\n'
  def phase=opts.script.contains('release-preflight.mjs')?'preflight':opts.script.contains('promote-private.mjs')?'privateMain':currentStage=='Candidate Approval Evidence'?'evidence':currentStage=='Candidate Sign and Approve'?'sign':'promote'
  if(row.codes[phase]!=0)throw new RuntimeException('original step nonzero: '+phase)
  return 0
 }
 script.run()
 outputs<<[name:row.name,selected:selected,commands:commands,failed:failure!=null,reason:failure,result:state.currentBuild.currentResult,approvedDigest:state.env.APPROVED_DIGEST,fragment:'Unchanged 3 stage source, inert Summary and Jenkins DSL; no actual summary run']
}
println(JsonOutput.toJson(outputs))
