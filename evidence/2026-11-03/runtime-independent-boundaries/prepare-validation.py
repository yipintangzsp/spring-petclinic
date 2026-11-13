from pathlib import Path
import json,subprocess,shlex,sys,urllib.parse,hashlib
O=Path(__file__).resolve().parent;sys.dont_write_bytecode=True
sys.path.insert(0,'/Users/zhangsir/code/evidence/platform-20261011');from jenkins_control import NODE
S=['ssh','-o','BatchMode=yes','-o','ConnectTimeout=6','-o','StrictHostKeyChecking=yes','-o','HostName=192.168.64.11','-o','HostKeyAlias=192.168.1.58','zhang@192.168.1.58']
def remote(command,data=None):
 p=subprocess.run(S+[command],input=data,capture_output=True,timeout=60);assert p.returncode==0,p.stderr.decode()[-500:];return p.stdout
def k(a):return json.loads(remote('sudo -n kubectl '+shlex.join(a)))
script='''import groovy.json.JsonOutput
import org.jenkinsci.plugins.workflow.graph.FlowGraphWalker
import org.jenkinsci.plugins.workflow.actions.WorkspaceAction
def j=Jenkins.instance.getItemByFullName('security-runtime-facts-20261102'),b=j.lastBuild
assert !b.building
def spaces=[];new FlowGraphWalker(b.execution).each{n->def a=n.getAction(WorkspaceAction);if(a&&!a.path.contains('@script'))spaces.add([node:a.node,path:a.path])}
println(JsonOutput.toJson([job:j.fullName,build:b.number,building:b.building,workspaces:spaces.unique()]))'''
payload={'path':'/scriptText','method':'POST','type':'application/x-www-form-urlencoded','body':urllib.parse.urlencode({'script':script}),'timeout':45000}
x=json.loads(remote('sudo -n kubectl exec -i -n ns-devops deploy/github-webhook-relay -- node --max-old-space-size=24 -e '+shlex.quote(NODE),json.dumps(payload).encode()));assert x['status']==200
j=json.loads(x['body'].split('\n',1)[0]);assert len(j['workspaces'])==1 and j['workspaces'][0]['path']=='/var/jenkins_home/workspace/security-runtime-facts-20261102';(O/'validation-workspace-before.json').write_text(json.dumps(j,indent=2)+'\n')
for file in ['health-final.json','node-lease-postflight.json','live-jenkins-final.json']:
 (O/(file.replace('-final','')+'.before')).write_bytes((O/file).read_bytes())
for kind,name,file,ns in [('clusterpolicy','devsecops-signed-images','production-signature-policy-before.json',None),('application','petclinic','argocd-before.json','argocd'),('deployment','petclinic','deployment-before.json','petclinic')]:
 a=(['-n',ns] if ns else [])+['get',kind,name,'-o','json'];(O/file).write_text(json.dumps(k(a),indent=2)+'\n')
archive=(O/'nonrelease-source.tar.gz').read_bytes();remote('sudo -n kubectl exec -i -n ns-devops deploy/jenkins -c jenkins -- tar xzf - -C '+shlex.quote(j['workspaces'][0]['path']),archive)
(O/'validation-transfer.json').write_text(json.dumps({'workspace':j['workspaces'][0]['path'],'archiveSha256':hashlib.sha256(archive).hexdigest(),'productionWorkspaceTouched':False,'previousBuild':j['build']},indent=2)+'\n');print('DEDICATED_VALIDATION_WORKSPACE_VERIFIED_AND_BUNDLE_TRANSFERRED')
