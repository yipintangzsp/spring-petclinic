"""Read-only evidence collection using an already trusted SSH host identity."""
import json,subprocess,shlex,sys,urllib.parse
from pathlib import Path
sys.path.insert(0,'/Users/zhangsir/code/evidence/platform-20261011')
from jenkins_control import NODE
BASE=Path(__file__).parent
SSH=['ssh','-o','BatchMode=yes','-o','ConnectTimeout=5','-o','StrictHostKeyChecking=yes','-o','HostName=192.168.64.11','-o','HostKeyAlias=192.168.1.58','zhang@192.168.1.58']
def call(script,name):
 payload={'path':'/scriptText','method':'POST','timeout':45000,'type':'application/x-www-form-urlencoded','body':urllib.parse.urlencode({'script':script})}
 cmd='sudo -n kubectl exec -i -n ns-devops deploy/github-webhook-relay -- node --max-old-space-size=24 -e '+shlex.quote(NODE)
 p=subprocess.run(SSH+[cmd],input=json.dumps(payload),text=True,capture_output=True,timeout=60)
 if p.returncode:raise RuntimeError(p.stderr[-500:])
 r=json.loads(p.stdout)
 if r['status']!=200:raise RuntimeError('Jenkins HTTP '+str(r['status']))
 try:data=json.loads(r['body'].split('\n',1)[0])
 except Exception:raise RuntimeError('Read-only evidence script returned non-JSON: '+r['body'][:1100])
 (BASE/name).write_text(json.dumps(data,indent=2));return data
if __name__=='__main__':
 script=r'''
import groovy.json.JsonOutput
 def job=Jenkins.instance.getItemByFullName('petclinic-ci')
 def rows=job.builds.take(15).collect{ b ->
  def a=b.getAllActions().find{it?.getClass()?.getName()?.contains('SonarAnalysisAction')}
  def info=[:]
  if(a) for(k in ['ceTaskId','serverUrl','installationName','url']) {try{info[k]=a."$k"}catch(ignored){}}
  def lines=b.getLog(20000).findAll{it.contains('QUALITY GATE STATUS:')||it.contains('api/ce/task?id=')||it.contains('ANALYSIS SUCCESSFUL')}
  [build:b.number,result:b.result?.toString(),building:b.isBuilding(),timestamp:b.startTimeInMillis,sonar:info,gateLog:lines]
 }
 println(JsonOutput.toJson([job:job.fullName,builds:rows]))
'''
 data=call(script,'jenkins-analysis-binding.json')
 print(json.dumps(data,indent=2))
