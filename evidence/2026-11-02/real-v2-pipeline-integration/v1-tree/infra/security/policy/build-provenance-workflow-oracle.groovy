// Execute original Shared Library locally with no real Jenkins steps or credentials.
import groovy.json.JsonSlurper
import groovy.json.JsonOutput

def results=[]
new JsonSlurper().parse(new File(args[0])).each{ row ->
 def raw=row.raw,state=[env:new LinkedHashMap(raw.environment)]
 def script=new GroovyShell(new Binding(state)).parse(new File('vars/securityBuildProvenance.groovy'))
 def trace=[],writes=[:]
 def step={ k ->if(raw.steps[k]?.error)throw new RuntimeException(raw.steps[k].error) }
 script.metaClass.error={ Object message -> throw new RuntimeException(message.toString()) }
 script.metaClass.echo={ Object message -> }
 script.metaClass.usernamePassword={ Map binding -> binding }
 script.metaClass.stage={ String name, Closure body ->step('stage');body() }
 script.metaClass.withEnv={ List vars, Closure body ->step('withEnv');def saved=new LinkedHashMap(state.env);try{vars.each{v->def p=v.split('=',2);state.env[p[0]]=p.length>1?p[1]:''};body()}finally{state.env.clear();state.env.putAll(saved)} }
 script.metaClass.withCredentials={ List bindings, Closure body ->step('credentials');body() }
 script.metaClass.sh={ Map options ->trace<<[command:options.script,environment:new LinkedHashMap(state.env)];return row.exitCode as Integer }
 script.metaClass.catchError={ Map options, Closure body ->try{body()}catch(Exception ignored){} }
 script.metaClass.writeJSON={ Map options ->step('status-write');writes[options.file]=options.json }
 def result
 try{def report=script.call(raw.cfg);result=[decision:report.status=='skipped'?null:report.status=='warn'?'WARN':report.status=='failed'?'FAIL':'PASS',status:report.status=='skipped'?'SKIPPED':report.status,report:report,trace:trace,writes:writes]}catch(Exception error){result=[decision:'FAIL',reason:error.message,trace:trace,writes:writes]}
 results<<[name:row.name,result:result]
}
println(JsonOutput.toJson(results))
