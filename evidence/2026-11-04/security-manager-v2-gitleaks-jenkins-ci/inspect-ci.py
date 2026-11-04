"""Bounded read-only Jenkins inventory. Never returns credentials, scripts or logs."""
from pathlib import Path
import subprocess,json,sys,shlex,urllib.parse
sys.dont_write_bytecode=True
sys.path.insert(0,'/Users/zhangsir/code/evidence/platform-20261011')
from jenkins_control import NODE
O=Path(__file__).resolve().parent
S=['ssh','-o','BatchMode=yes','-o','ConnectTimeout=6','-o','StrictHostKeyChecking=yes','-o','HostName=192.168.64.11','-o','HostKeyAlias=192.168.1.58','zhang@192.168.1.58']
script=r'''
import groovy.json.JsonOutput
import java.security.MessageDigest
def j=Jenkins.instance
def hash={s->MessageDigest.getInstance('SHA-256').digest(s.getBytes('UTF-8')).encodeHex().toString()}
def computers=j.computers.collect{c->[name:c.name,online:c.online,executors:c.numExecutors,busy:c.countBusy(),nodeClass:c.node?.class?.name,remoteFS:c.name?c.node?.remoteFS:j.rootDir.absolutePath,labels:c.node?.assignedLabels?.collect{it.name},mode:c.node?.mode?.toString(),launcher:c.node?.metaClass?.respondsTo(c.node,'getLauncher')?c.node.launcher.class.name:null]}
def jobs=j.allItems.findAll{it instanceof hudson.model.Job}.collect{v->
 def d=v.metaClass.hasProperty(v,'definition')?v.definition:null
 def s=d?.metaClass?.hasProperty(d,'script')?d.script:null
 [name:v.fullName,jobClass:v.class.name,disabled:v.metaClass.hasProperty(v,'disabled')?v.disabled:null,latest:v.lastBuild?.number,result:v.lastBuild?.result?.toString(),building:v.lastBuild?.building,definitionClass:d?.class?.name,scriptSha256:s==null?null:hash(s),scriptPath:d?.metaClass?.hasProperty(d,'scriptPath')?d.scriptPath:null,usesCredentials:s?.contains('withCredentials'),usesDocker:s?.toLowerCase()?.contains('docker'),usesDeploy:s?.contains('kubectl'),parameterNames:v.getProperty(hudson.model.ParametersDefinitionProperty)?.parameterDefinitions?.collect{it.name}]
}
def auth=jenkins.model.Jenkins.getAuthentication2()
def x=[identity:auth.name,permissions:[jobCreate:j.hasPermission(hudson.model.Item.CREATE),agentCreate:j.hasPermission(hudson.model.Computer.CREATE),administer:j.hasPermission(Jenkins.ADMINISTER)],authorizationStrategy:j.authorizationStrategy.class.name,securityRealm:j.securityRealm.class.name,computers:computers,jobs:jobs,queue:j.queue.items.collect{[id:it.id,task:it.task.fullDisplayName,why:it.why]},plugins:['kubernetes','ssh-slaves','workflow-job','workflow-cps','script-security','credentials','matrix-auth'].collectEntries{p->[(p):j.pluginManager.getPlugin(p)?.version]},mutations:0]
println(JsonOutput.toJson(x))
'''
payload={'path':'/scriptText','method':'POST','type':'application/x-www-form-urlencoded','body':urllib.parse.urlencode({'script':script}),'timeout':30000}
command='sudo -n kubectl exec -i -n ns-devops deploy/github-webhook-relay -- node --max-old-space-size=24 -e '+shlex.quote(NODE)
p=subprocess.run(S+[command],input=json.dumps(payload),text=True,capture_output=True,timeout=50)
assert p.returncode==0,p.stderr[-500:]
r=json.loads(p.stdout);assert r['status']==200,{'status':r['status']}
try:x=json.loads(r['body'].split('\n')[0])
except json.JSONDecodeError:
 (O/'ci-inventory-error.json').write_text(json.dumps({'http':r['status'],'body':r['body'][:4000]},indent=2)+'\n');raise SystemExit(r['body'][:1000])
with (O/('ci-inventory-after.json' if len(sys.argv)>1 and sys.argv[1]=='after' else 'ci-inventory.json')).open('x') as f:json.dump(x,f,indent=2);f.write('\n')
print(json.dumps({'computers':x['computers'],'jobCount':len(x['jobs']),'queueCount':len(x['queue']),'validationJobPresent':any(j['name']=='security-manager-v2-gitleaks-validation' for j in x['jobs']),'mutations':0}))
