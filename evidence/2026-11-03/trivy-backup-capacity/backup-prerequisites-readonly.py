from pathlib import Path
import json,subprocess,shlex,urllib.parse,sys
sys.dont_write_bytecode=True;sys.path.insert(0,'/Users/zhangsir/code/evidence/platform-20261011');from jenkins_control import NODE
O=Path(__file__).resolve().parent
script=r'''
import groovy.json.JsonOutput
import groovy.json.JsonSlurperClassic
import com.cloudbees.plugins.credentials.CredentialsProvider
import com.cloudbees.plugins.credentials.common.StandardUsernamePasswordCredentials
def c=CredentialsProvider.lookupCredentials(StandardUsernamePasswordCredentials.class,Jenkins.instance,null,null).find{it.id=='harbor-creds'}
if(c==null)throw new IllegalStateException('Existing authorized read credential absent; no fallback')
def calls=['/api/v2.0/system/gc?page=1&page_size=10','/api/v2.0/replication/executions?page=1&page_size=10']
def observations=calls.collect{p->
 def con=new URL('http://harbor-core.harbor.svc.cluster.local'+p).openConnection();con.setRequestMethod('GET');con.setConnectTimeout(8000);con.setReadTimeout(12000);con.setRequestProperty('Authorization','Basic '+(c.username+':'+c.password.plainText).bytes.encodeBase64().toString())
 def status=con.responseCode,body=status==200?new JsonSlurperClassic().parseText(con.inputStream.getText('UTF-8')):null
 [path:p,httpStatus:status,jobs:body instanceof List?body.collect{j->[id:j.id,status:j.status,jobStatus:j.job_status,start:j.start_time,end:j.end_time,creation:j.creation_time]}:null]
}
def jobs=Jenkins.instance.getAllItems(hudson.model.Job.class).collect{j->[name:j.fullName,latest:j.lastBuild?.number,building:j.lastBuild?.building,result:j.lastBuild?.result?.toString()]}
println(JsonOutput.toJson([method:'READ_ONLY_MANAGEMENT',jobs:jobs,activeJobs:jobs.findAll{it.building},registryMaintenance:observations,mutations:0]))
'''
payload={'path':'/scriptText','method':'POST','type':'application/x-www-form-urlencoded','body':urllib.parse.urlencode({'script':script}),'timeout':55000};S=['ssh','-o','BatchMode=yes','-o','ConnectTimeout=6','-o','StrictHostKeyChecking=yes','-o','HostName=192.168.64.11','-o','HostKeyAlias=192.168.1.58','zhang@192.168.1.58'];p=subprocess.run(S+['sudo -n kubectl exec -i -n ns-devops deploy/github-webhook-relay -- node -e '+shlex.quote(NODE)],input=json.dumps(payload),capture_output=True,text=True,timeout=65);assert p.returncode==0;r=json.loads(p.stdout);assert r['status']==200
try:x=json.loads(r['body'].split('\n',1)[0])
except Exception:raise SystemExit('Authorized registry read failed; no credential or response-body output')
(O/'backup-prerequisites-readonly.json').write_text(json.dumps(x,indent=2)+'\n');print(json.dumps(x))
