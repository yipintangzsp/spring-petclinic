// Local-only harness: execute the unchanged Shared Library with inert Jenkins DSL steps.
import groovy.json.JsonSlurper
import groovy.json.JsonOutput

def inputs=new JsonSlurper().parse(new File(args[0]))
def results=[]
inputs.each { row ->
 def raw=row.raw
 def state=[env:new LinkedHashMap(raw.environment),params:raw.params]
 def script=new GroovyShell(new Binding(state)).parse(new File('vars/securityProvenance.groovy'))
 def trace=[],writes=[:],currentAction='',markedFailure=false
 def failStep={ key -> if(raw.steps[key]?.error)throw new RuntimeException(raw.steps[key].error) }
 script.metaClass.pwd={ -> '/fixture/project' }
 script.metaClass.echo={ Object message -> }
 script.metaClass.error={ Object message -> throw new RuntimeException(message.toString()) }
 script.metaClass.file={ Map value -> value }
 script.metaClass.usernamePassword={ Map value -> value }
 script.metaClass.stage={ String name, Closure body -> currentAction=['Generate Provenance':'generate','Create Attestation':'create','Verify Attestation':'verify'][name];failStep('stage-'+currentAction);body() }
 script.metaClass.withEnv={ List values, Closure body ->
  def key=values.any{it.startsWith('PROVENANCE_SOURCE_ROOT=')}?'source-withEnv':'operations-withEnv';failStep(key)
  def saved=new LinkedHashMap(state.env)
  try{values.each{v->def pair=v.split('=',2);state.env[pair[0]]=pair.length>1?pair[1]:''};body()}finally{state.env.clear();state.env.putAll(saved)}
 }
 script.metaClass.withCredentials={ List bindings, Closure body -> failStep('credentials-'+currentAction);body() }
 script.metaClass.sh={ Map options ->
  if(options.returnStdout){def key=options.script.contains('rev-parse')?'commit':'repository';if(raw.git[key].error)throw new RuntimeException(raw.git[key].error);return raw.git[key].value}
  trace<<[action:currentAction,environment:new LinkedHashMap(state.env),command:options.script]
  def observation=row.exitCodes[currentAction]
  if(observation==null)throw new RuntimeException('Missing action observation')
  return observation as Integer
 }
 script.metaClass.catchError={ Map options, Closure body ->try{body()}catch(Exception failure){markedFailure=true} }
 script.metaClass.writeJSON={ Map value ->failStep('status-write');writes[value.file]=value.json }
 def output
 try{
  def report=script.call(raw.cfg)
  def decision=report.status=='skipped'?null:report.status=='warn'?'WARN':report.status=='failed'||markedFailure?'FAIL':'PASS'
  output=[decision:decision,report:report,trace:trace,writes:writes]
 }catch(Exception failure){output=[decision:'FAIL',reason:failure.message,trace:trace,writes:writes]}
 results<<[name:row.name,result:output]
}
println(JsonOutput.toJson(results))
