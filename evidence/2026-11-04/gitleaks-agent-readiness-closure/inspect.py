"""Targeted read-only readiness closure. No scanner, writes, Pod or Node creation.

Only candidate node devops is resource-sampled. All-node Ready is health-only.
Jenkins admin credentials remain inside the existing authorized relay process.
"""
from pathlib import Path
import concurrent.futures,datetime,hashlib,importlib.util,json,shlex,subprocess,sys,urllib.parse
sys.dont_write_bytecode=True
OUT=Path(__file__).resolve().parent;ROOT=OUT.parents[2]
SSH=['ssh','-o','BatchMode=yes','-o','ConnectTimeout=6','-o','ConnectionAttempts=1',
     '-o','StrictHostKeyChecking=yes','-o','HostName=192.168.64.11','-o','HostKeyAlias=192.168.1.58','zhang@192.168.1.58']
def save(name,x):
    with (OUT/name).open('x') as f:json.dump(x,f,indent=2);f.write('\n')
def remote(command,data=None,timeout=120):
    p=subprocess.run(SSH+[command],input=data,text=True,capture_output=True,timeout=timeout)
    if p.returncode:raise RuntimeError('Read-only inspection failed: '+p.stderr[-500:])
    return p.stdout
def baseline():
    previous=ROOT/'evidence/2026-11-04/gitleaks-ephemeral-agent-plan'
    paths=set(json.loads((previous/'protected-before.json').read_text())['files'])
    paths.update(str(p.relative_to(ROOT)) for p in previous.rglob('*') if p.is_file())
    # Candidate evolution is explicitly approved; freeze previous bytes in Git,
    # not by rewriting historical code/evidence seals to match current files.
    candidate='infra/jenkins/gitleaks-validation/ephemeral-agent/'
    hashes={name:hashlib.sha256((ROOT/name).read_bytes()).hexdigest() for name in sorted(paths) if not name.startswith(candidate)}
    sources={str(p.relative_to(ROOT)):hashlib.sha256(p.read_bytes()).hexdigest() for p in (ROOT/candidate).rglob('*') if p.is_file()}
    save('baseline.json',{'head':subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip(),'protectedFiles':hashes,'approvedCandidateBefore':sources})
def jenkins(phase):
    sys.path.insert(0,'/Users/zhangsir/code/evidence/platform-20261011')
    from jenkins_control import NODE
    script=r'''
import groovy.json.JsonOutput
import java.security.MessageDigest
def j=Jenkins.instance
def hash={s->MessageDigest.getInstance('SHA-256').digest(s.getBytes('UTF-8')).encodeHex().toString()}
def b=j.getItemByFullName('petclinic-ci')?.getBuildByNumber(270)
def f=b?.artifacts?.find{it.relativePath=='.devsecops/security-summary.json'}
def text=f?new File(b.artifactsDir,f.relativePath).getText('UTF-8'):null
def permissions=[agentCreate:j.hasPermission(hudson.model.Computer.CREATE),agentConfigure:j.hasPermission(hudson.model.Computer.CONFIGURE),agentDelete:j.hasPermission(hudson.model.Computer.DELETE),administer:j.hasPermission(Jenkins.ADMINISTER)]
def result=[version:Jenkins.VERSION,webSocket:jenkins.websocket.WebSockets.isSupported(),rootUrl:j.rootUrl,
 kubernetesPlugin:j.pluginManager.getPlugin('kubernetes')?.version,cloudCount:j.clouds.size(),
 nodes:j.computers.collect{c->[name:c.name,online:c.online,executors:c.numExecutors,busy:c.countBusy(),labels:c.node?.assignedLabels?.collect{it.name}]},
 permissions:permissions,identity:Jenkins.getAuthentication2().name,authorizationStrategy:j.authorizationStrategy.class.name,
 apiCapabilities:[addNode:Jenkins.class.methods.any{it.name=='addNode'},removeNode:Jenkins.class.methods.any{it.name=='removeNode'},
  inboundLauncherClass:hudson.slaves.JNLPLauncher.class.name,webSocketLauncherProperty:hudson.slaves.JNLPLauncher.class.methods.any{it.name=='setWebSocket'},
  nodeCredentialAccessorPresent:hudson.slaves.SlaveComputer.class.methods.any{it.name=='getJnlpMac'},secretAccessorInvoked:false,
  dumbSlaveConstructors:hudson.slaves.DumbSlave.class.constructors.collect{it.parameterTypes.collect{it.name}}],
 validationJobExists:j.getItemByFullName('security-manager-v2-gitleaks-validation')!=null,
 queue:j.queue.items.collect{[id:it.id,task:it.task.fullDisplayName]},
 production:[build270:b?.number,result:b?.result?.toString(),building:b?.building,summarySha256:text==null?null:hash(text),jobDefinitionSha256:hash(j.getItemByFullName('petclinic-ci').getConfigFile().asString())],
 mutations:0,nodeSecretRead:false]
println(JsonOutput.toJson(result))
'''
    payload={'path':'/scriptText','method':'POST','type':'application/x-www-form-urlencoded','body':urllib.parse.urlencode({'script':script}),'timeout':30000}
    r=json.loads(remote('sudo -n kubectl exec -i -n ns-devops deploy/github-webhook-relay -- node --max-old-space-size=24 -e '+shlex.quote(NODE),json.dumps(payload),60))
    if r['status']!=200:raise RuntimeError('Read-only Jenkins HTTP '+str(r['status']))
    try:x=json.loads(r['body'].split('\n')[0])
    except Exception:raise RuntimeError('Jenkins capability query rejected: '+r['body'][:400])
    save('jenkins-'+phase+'.json',x);return {'version':x['version'],'capabilities':x['apiCapabilities'],'production':x['production']}
HOST=r'''
import datetime,hashlib,json,os,pathlib,subprocess,time,urllib.request
def run(a):return subprocess.check_output(a,text=True,timeout=25)
def k(a):return json.loads(run(['kubectl']+a))
def maybe(a):
 try:return k(a)
 except Exception as e:return {'status':'UNKNOWN','error':type(e).__name__}
node=k(['get','node','devops','-o','json']);cfg=maybe(['get','--raw','/api/v1/nodes/devops/proxy/configz'])
samples=[]
for i in range(3):
 s=k(['get','--raw','/api/v1/nodes/devops/proxy/stats/summary'])['node']
 samples.append({a:s.get(a) for a in ['startTime','cpu','memory','fs','runtime']})
 if i<2:time.sleep(15)
pods=k(['get','pods','-A','--field-selector','spec.nodeName=devops','-o','json'])['items']
# Only metadata, requests/limits and status on the one eligible candidate node.
podrows=[{'name':p['metadata']['name'],'namespace':p['metadata']['namespace'],'uid':p['metadata']['uid'],'phase':p['status'].get('phase'),
 'resources':[c.get('resources',{}) for c in p['spec']['containers']],
 'initResources':[{'restartPolicy':c.get('restartPolicy'),'resources':c.get('resources',{})} for c in p['spec'].get('initContainers',[])],
 'overhead':p['spec'].get('overhead',{})} for p in pods]
controller=next(p for p in pods if p['metadata']['namespace']=='ns-devops' and p['metadata']['name'].startswith('jenkins-') and not p['metadata']['name'].startswith('jenkins-build'))
js=r"const fs=require('fs'),cp=require('child_process'),crypto=require('crypto');const sha=p=>crypto.createHash('sha256').update(fs.readFileSync(p)).digest('hex');const bins=['/usr/bin/node','/usr/bin/git','/opt/java/openjdk/bin/java','/usr/bin/tini','/usr/bin/prlimit','/etc/ssl/certs/ca-certificates.crt'];const files=bins.map(p=>{try{const r=fs.realpathSync(p),s=fs.statSync(r);return {path:p,realpath:r,uid:s.uid,gid:s.gid,mode:(s.mode&511).toString(8),bytes:s.size,sha256:sha(r)}}catch{return {path:p,status:'UNAVAILABLE'}}});const versions={git:cp.spawnSync('/usr/bin/git',['--version'],{encoding:'utf8'}).stdout.trim(),prlimit:cp.spawnSync('/usr/bin/prlimit',['--version'],{encoding:'utf8'}).stdout?.trim(),tini:cp.spawnSync('/usr/bin/tini',['--version'],{encoding:'utf8'}).stdout.trim(),java:cp.spawnSync('/opt/java/openjdk/bin/java',['-version'],{encoding:'utf8'}).stderr.trim(),node:process.version};const licenses=['/usr/share/doc/git/copyright','/usr/share/doc/nodejs/copyright','/usr/share/doc/tini/copyright','/usr/share/doc/util-linux/copyright','/usr/share/doc/ca-certificates/copyright','/opt/java/openjdk/legal/java.base/LICENSE'];const records=licenses.map(p=>{try{return {path:p,sha256:sha(p),bytes:fs.statSync(p).size}}catch{return {path:p,status:'NOT_FOUND'}}});console.log(JSON.stringify({files,versions,licenses:records,uid24001ImageAccounts:fs.readFileSync('/etc/passwd','utf8').split('\n').filter(l=>l.split(':')[2]==='24001').map(l=>l.split(':')[0]),runtimeAs24001Tested:false}))"
tool=json.loads(run(['kubectl','-n','ns-devops','exec',controller['metadata']['name'],'-c','jenkins','--','node','-e',js]))
pet=k(['-n','petclinic','get','deployment','petclinic','-o','json']);petpods=k(['-n','petclinic','get','pods','-l','app=petclinic','-o','json'])['items'];argo=k(['-n','argocd','get','application','petclinic','-o','json'])
ns='devsecops-execution';scope={kind:maybe(['-n',ns,'get',kind,'-o','json']) for kind in ['resourcequota','limitrange','networkpolicy']}
safe=lambda p:{'name':p['metadata']['name'],'uid':p['metadata']['uid'],'node':p['spec'].get('nodeName'),'phase':p['status']['phase'],'containers':[{a:c.get(a) for a in ['name','image','imageID','ready','restartCount']} for c in p['status'].get('containerStatuses',[])]}
trivy=k(['-n','harbor','get','pod','harbor-trivy-0','-o','json'])
db=run(['kubectl','-n','harbor','exec','harbor-trivy-0','-c','trivy','--','sh','-c',"for f in /home/scanner/.cache/trivy/db/metadata.json /home/scanner/.cache/trivy/java-db/metadata.json; do stat -c '%n|%s|%i|%Y' \"$f\"; sha256sum \"$f\"; done"])
dojo=k(['-n','devsecops-system','get','pods','-o','json'])['items'];sock=os.stat('/run/docker.sock')
with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(urllib.request.Request('http://192.168.64.11/',headers={'Host':'petclinic.devops.local'}),timeout=8) as r:http=r.status
try:
 ss=run(['ss','-lnt']);remoteDocker=[l.split()[3] for l in ss.splitlines()[1:] if l.split()[3].endswith((':2375',':2376'))]
except Exception:remoteDocker='UNKNOWN'
c=cfg.get('kubeletconfig',{})
x={'classification':'REAL_READ_ONLY_TARGETED_SNAPSHOT_NOT_AGENT_EXECUTION','at':datetime.datetime.now(datetime.timezone.utc).isoformat(),
 'candidateNode':{'name':'devops','labels':node['metadata']['labels'],'taints':node['spec'].get('taints',[]),'allocatable':node['status']['allocatable'],'conditions':node['status']['conditions'],'samples':samples,'pods':podrows},
 'kubelet':{a:c.get(a) for a in ['podPidsLimit','cgroupDriver','cgroupsPerQOS','containerLogMaxSize','containerLogMaxFiles','evictionHard','evictionSoft']},
 'namespace':{'metadata':k(['get','namespace',ns,'-o','json'])['metadata'],'resources':scope},'tools':tool,
 'controller':safe(controller),'jenkinsService':k(['-n','ns-devops','get','svc','jenkins','-o','json'])['spec'],
 'remoteDockerApiListeners':remoteDocker,
 'production':{'image':[c['image'] for c in pet['spec']['template']['spec']['containers']],'specSha256':hashlib.sha256(json.dumps(pet['spec'],sort_keys=True).encode()).hexdigest(),'ready':pet['status'].get('readyReplicas'),'http':http,'distribution':[safe(p) for p in petpods],'argoSync':argo['status']['sync']['status'],'argoHealth':argo['status']['health']['status'],'argoSource':argo['spec'].get('source'),
 'nodes':[{'name':n['metadata']['name'],'ready':next(c['status'] for c in n['status']['conditions'] if c['type']=='Ready')} for n in k(['get','nodes','-o','json'])['items']],
 'socket':{'mode':format(sock.st_mode&511,'04o'),'uid':sock.st_uid,'gid':sock.st_gid},'trivy':safe(trivy),'dbMetadataObservation':db,'dojo':[safe(p) for p in dojo if 'dojo' in p['metadata']['name'].lower()]},
 'counts':{'podCreate':0,'podDelete':0,'nodeCreate':0,'SAcreate':0,'RBACcreate':0,'networkPolicyCreate':0,'imageBuild':0,'imagePush':0,'jenkinsBuild':0,'release':0,'rollout':0}}
print(json.dumps(x))
'''
def cluster(phase):
    x=json.loads(remote('sudo -n python3 -',HOST,150));save('live-'+phase+'.json',x)
    return {'node':'devops','kubelet':x['kubelet'],'tools':x['tools']['versions'],'production':{k:x['production'][k] for k in ['ready','http','argoSync','argoHealth']}}
if __name__=='__main__':
    phase=sys.argv[1];assert phase in ['before','after']
    if phase=='before':baseline()
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as ex:
        futures={ex.submit(jenkins,phase):'jenkins',ex.submit(cluster,phase):'cluster'}
        for f in concurrent.futures.as_completed(futures):print(json.dumps({futures[f]:f.result()}))
