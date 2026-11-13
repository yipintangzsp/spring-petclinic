// Execute original Security Manager locally; isolate Trivy, inert Jenkins DSL, no real checkout/credentials/Summary.
import groovy.json.JsonSlurper
import groovy.json.JsonOutput

def slurper=new JsonSlurper(),results=[]
slurper.parse(new File(args[0])).each{ row ->
 def raw=row.raw,env=[BUILD_NUMBER:'270',JOB_NAME:'fixture-job',JOB_BASE_NAME:'fixture-job'],current=[currentResult:'SUCCESS'],writes=[:],commands=[],selected=[],trace=[]
 def script=new GroovyShell(new Binding([env:env,currentBuild:current])).parse(new File('vars/securityManager.groovy'))
 def step={ key ->trace<<key;if(raw.steps[key]?.error)throw new RuntimeException(raw.steps[key].error) }
 script.metaClass.error={ Object msg ->throw new RuntimeException(msg.toString()) }
 script.metaClass.echo={ Object msg -> }
 script.metaClass.pwd={ ->'/fixture/project' }
 script.metaClass.libraryResource={ String name ->
  if(name=='security-manager/petclinic-adapter.json')return JsonOutput.toJson(slurper.parse(new File('resources/'+name)).findAll{it.id=='trivy'})
  return new File('resources/'+name).text
 }
 script.metaClass.readJSON={ Map o ->slurper.parseText(o.text) }
 script.metaClass.dir={ String location,Closure body ->body() }
 script.metaClass.withEnv={ List vars,Closure body ->def saved=new LinkedHashMap(env);try{vars.each{v->def p=v.split('=',2);env[p[0]]=p.length>1?p[1]:''};body()}finally{env.clear();env.putAll(saved)} }
 script.metaClass.checkout={ Map config ->step('checkout') }
 script.metaClass.usernamePassword={ Map options ->step('credential-binding');options }
 script.metaClass.withCredentials={ List credentials,Closure body ->step('credentials');body() }
 script.metaClass.stage={ String name,Closure body ->step(name=='Security Gate'?'gate':'module-stage');body() }
 script.metaClass.catchError={ Map options,Closure body ->try{body()}catch(Exception ignored){current.currentResult='FAILURE'} }
 script.metaClass.writeJSON={ Map options ->step(options.file.endsWith('manager-config.json')?'config-write':'manager-write');writes[options.file]=options.json }
 script.metaClass.writeFile={ Map options ->step(options.file.endsWith('.git-sha')?'source-write':'summary-script-write') }
 script.metaClass.archiveArtifacts={ Map options ->step('archive') }
 script.metaClass.securityProvenance={ Map cfg ->[status:'skipped'] }
 script.metaClass.securityBuildProvenance={ Map cfg ->[status:'skipped'] }
 def doSh={ Map options ->
  def command=options.script;commands<<command
  if(command.contains(' > .devsecops/gates/trivy.log')){step('scan-sh');selected<<command;return row.operationExitCode as Integer}
  if(options.returnStdout)return 'a'*40+'\n'
  if(command.contains('heavy-lease.mjs acquire'))step('lease-acquire')
  else if(command.contains('heavy-lease.mjs release'))step('lease-release')
  else if(command=='node .security-manager-summary.mjs')step('summary-inert-step')
  else step('setup-sh')
  return 0
 }
 script.metaClass.sh={ Object value ->doSh(value instanceof Map?value:[script:value.toString()]) }
 def result,failed=false,reason
 try{result=script.call(raw.cfg)}catch(Exception error){failed=true;reason=error.message}
 failed=failed||current.currentResult=='FAILURE'
 def modules=result?:writes['.devsecops/security-manager.json']?.modules?:[]
 def regression=modules.find{it.tool=='trivy'}
 results<<[name:row.name,failed:failed,reason:reason,module:regression,moduleStatus:regression?.status?:'unavailable',selected: selected,commands:commands,trace:trace,scope:'Trivy only; other generic modules disabled; production resource plan filtered to Trivy for isolated original wrapper replay']
}
println(JsonOutput.toJson(results))
