"""Read-only planning evidence. No cluster writes, credentials export or scanners.

Uses the previously authorized relay identity in place; never prints its secrets.
Every output is new (exclusive create), including errors. Strict host keys remain on.
"""
import concurrent.futures, datetime, hashlib, json, pathlib, shlex, subprocess, sys, urllib.parse
sys.dont_write_bytecode = True
ROOT = pathlib.Path(__file__).resolve().parents[3]
OUT = pathlib.Path(__file__).resolve().parent
SSH = ['ssh','-o','BatchMode=yes','-o','ConnectTimeout=6','-o','ConnectionAttempts=1',
       '-o','StrictHostKeyChecking=yes','-o','HostName=192.168.64.11',
       '-o','HostKeyAlias=192.168.1.58','zhang@192.168.1.58']
def save(name, value):
    with (OUT/name).open('x') as f: json.dump(value,f,indent=2); f.write('\n')
def remote(command, data=None, timeout=100):
    p = subprocess.run(SSH+[command],input=data,text=True,capture_output=True,timeout=timeout)
    if p.returncode: raise RuntimeError('Read-only SSH check failed: '+p.stderr[-500:])
    return p.stdout
def jenkins(phase):
    sys.path.insert(0,'/Users/zhangsir/code/evidence/platform-20261011')
    from jenkins_control import NODE
    script = r'''
import groovy.json.JsonOutput
import java.security.MessageDigest
def j=Jenkins.instance
def hash={s->MessageDigest.getInstance('SHA-256').digest(s.getBytes('UTF-8')).encodeHex().toString()}
def b=j.getItemByFullName('petclinic-ci')?.getBuildByNumber(270)
def summary=b?.artifacts?.find{it.relativePath=='.devsecops/security-summary.json'}
def text=summary?new File(b.artifactsDir,summary.relativePath).getText('UTF-8'):null
def pluginRows=j.pluginManager.plugins.collect{[id:it.shortName,version:it.version,active:it.active]}.sort{it.id}
def ws=null
try {ws=jenkins.websocket.WebSockets.isSupported()} catch(Throwable ignored) {}
def validation=j.getItemByFullName('security-manager-v2-gitleaks-validation')
def x=[classification:'READ_ONLY_LIVE_INVENTORY_NOT_AGENT_EXECUTION',version:Jenkins.VERSION,
 rootUrl:j.rootUrl,controllerInsideKubernetes:true,agentListenerPort:j.slaveAgentPort,
 authorizationStrategy:j.authorizationStrategy.class.name,securityRealm:j.securityRealm.class.name,
 webSocketSupported:ws,plugins:pluginRows,clouds:j.clouds.collect{[name:it.name,type:it.class.name]},
 nodes:j.computers.collect{c->[name:c.name,online:c.online,executors:c.numExecutors,busy:c.countBusy(),
  mode:c.node?.mode?.toString(),labels:c.node?.assignedLabels?.collect{it.name},
  remoteFS:c.name?c.node?.remoteFS:j.rootDir.absolutePath,
  launcher:c.node?.metaClass?.respondsTo(c.node,'getLauncher')?c.node.launcher.class.name:null]},
 queue:j.queue.items.collect{[id:it.id,task:it.task.fullDisplayName]},
 credentialManagement:[credentialsPluginInstalled:j.pluginManager.getPlugin('credentials')!=null,
  secretValuesRead:false,secretValuesExported:false],
 validationJob:[exists:validation!=null,disabled:validation?.disabled,lastBuild:validation?.lastBuild?.number],
 build270:[number:b?.number,result:b?.result?.toString(),building:b?.building,summarySha256:text==null?null:hash(text)],
 productionDefinitionSha256:hash(j.getItemByFullName('petclinic-ci').getConfigFile().asString()),mutations:0]
println(JsonOutput.toJson(x))
'''
    data={'path':'/scriptText','method':'POST','type':'application/x-www-form-urlencoded',
          'body':urllib.parse.urlencode({'script':script}),'timeout':30000}
    r=json.loads(remote('sudo -n kubectl exec -i -n ns-devops deploy/github-webhook-relay -- node --max-old-space-size=24 -e '+shlex.quote(NODE),json.dumps(data),60))
    if r['status']!=200: raise RuntimeError('Jenkins read-only inspection HTTP '+str(r['status']))
    try: x=json.loads(r['body'].split('\n')[0])
    except Exception: raise RuntimeError('Jenkins read-only response not structured JSON: '+r['body'][:600])
    save('jenkins-'+phase+'.json',x)
    return {'version':x['version'],'kubernetesPlugin':next((p for p in x['plugins'] if p['id']=='kubernetes'),None),
            'nodes':x['nodes'],'websocket':x['webSocketSupported'],'build270':x['build270'],'validationJob':x['validationJob']}

HOST = r'''
import concurrent.futures,datetime,decimal,hashlib,json,os,pathlib,re,subprocess,urllib.request
def run(a,timeout=30):return subprocess.check_output(a,text=True,timeout=timeout)
def k(a):return json.loads(run(['kubectl']+a))
def q(x):
 m=re.fullmatch(r'([0-9.]+)([a-zA-Z]*)',str(x or 0));v=decimal.Decimal(m[1]);s=m[2]
 return float(v*decimal.Decimal({'':1,'n':1e-9,'u':1e-6,'m':1e-3,'k':1000,'K':1000,'M':1e6,'G':1e9,'T':1e12,'Ki':1024,'Mi':1024**2,'Gi':1024**3,'Ti':1024**4}[s]))
pods=k(['get','pods','-A','-o','json'])['items'];nodes=k(['get','nodes','-o','json'])['items']
def req(p,kind):
 cs=p['spec'].get('containers',[]);side=0;initmax=0
 for c in p['spec'].get('initContainers',[]):
  n=q(c.get('resources',{}).get('requests',{}).get(kind,0))
  if c.get('restartPolicy')=='Always':side+=n;initmax=max(initmax,side)
  else:initmax=max(initmax,side+n)
 return max(sum(q(c.get('resources',{}).get('requests',{}).get(kind,0)) for c in cs)+side,initmax)+q(p['spec'].get('overhead',{}).get(kind,0))
def stats(n):
 try:
  s=k(['get','--raw','/api/v1/nodes/'+n+'/proxy/stats/summary'])
  return {'node':s['node'],'podUsage':[{'namespace':p['podRef']['namespace'],'name':p['podRef']['name'],'cpu':p.get('cpu'),'memory':p.get('memory'),'ephemeralStorage':p.get('ephemeral-storage')} for p in s.get('pods',[])]}
 except Exception as e:return {'error':type(e).__name__,'status':'UNKNOWN'}
with concurrent.futures.ThreadPoolExecutor(max_workers=3) as ex: st=dict(zip([n['metadata']['name'] for n in nodes],ex.map(stats,[n['metadata']['name'] for n in nodes])))
nr=[]
for n in nodes:
 name=n['metadata']['name'];active=[p for p in pods if p['spec'].get('nodeName')==name and p['status'].get('phase') not in ['Succeeded','Failed']]
 nr.append({'name':name,'uid':n['metadata']['uid'],'labels':n['metadata']['labels'],'taints':n['spec'].get('taints',[]),'unschedulable':n['spec'].get('unschedulable',False),
  'capacity':n['status']['capacity'],'allocatable':n['status']['allocatable'],'conditions':n['status']['conditions'],
  'scheduledRequests':{t:reqs for t,reqs in [(t,sum(req(p,t) for p in active)) for t in ['cpu','memory','ephemeral-storage']]},'stats':st[name]})
ns=k(['get','namespaces','-o','json'])['items']
policies={}
for kind in ['resourcequotas','limitranges','networkpolicies','clusterpolicies.kyverno.io','policies.kyverno.io','policyexceptions.kyverno.io','certificates.cert-manager.io']:
 try:policies[kind]=k(['get',kind,'-A','-o','json']).get('items',[])
 except Exception as e:policies[kind]={'status':'UNKNOWN','error':type(e).__name__}
services=k(['-n','ns-devops','get','svc','-o','json'])['items'];selected=[s for s in services if any(x in s['metadata']['name'] for x in ['jenkins','gitlab'])]
controller=next(p for p in pods if p['metadata']['namespace']=='ns-devops' and p['metadata']['name'].startswith('jenkins-') and not p['metadata']['name'].startswith('jenkins-build'))
identityjs=r"const fs=require('fs'),cp=require('child_process'),path=require('path');const paths=['/usr/bin/node','/usr/bin/git','/usr/bin/java','/opt/java/openjdk/bin/java','/usr/share/jenkins/agent.jar','/usr/share/jenkins/ref','/home/jenkins','/tmp'];const info=paths.map(p=>{try{const s=fs.statSync(p);return {path:p,realpath:fs.realpathSync(p),uid:s.uid,gid:s.gid,mode:(s.mode&511).toString(8),bytes:s.size}}catch{return {path:p,exists:false}}});const s=fs.statSync('/run/docker.sock');console.log(JSON.stringify({uid:process.getuid(),gid:process.getgid(),groups:process.getgroups(),status:fs.readFileSync('/proc/self/status','utf8').split('\n').filter(l=>/^(NoNewPrivs|CapEff):/.test(l)),files:info,javaVersion:cp.spawnSync('java',['-version'],{encoding:'utf8'}).stderr.slice(0,500),nodeVersion:process.version,socket:{uid:s.uid,gid:s.gid,mode:(s.mode&511).toString(8)}}))"
try:identity=json.loads(run(['kubectl','-n','ns-devops','exec',controller['metadata']['name'],'--','node','-e',identityjs]))
except Exception as e:identity={'status':'UNKNOWN','error':type(e).__name__}
uid24001=[]
for p in pathlib.Path('/proc').glob('[0-9]*/status'):
 try:
  text=p.read_text()
  if re.search(r'^Uid:\s+24001\s',text,re.M):uid24001.append({'pid':int(p.parent.name),'name':text.splitlines()[0]})
 except (PermissionError,FileNotFoundError,ProcessLookupError):pass
pet=k(['-n','petclinic','get','deployment','petclinic','-o','json']);argo=k(['-n','argocd','get','application','petclinic','-o','json'])
safe=lambda p:{'namespace':p['metadata']['namespace'],'name':p['metadata']['name'],'uid':p['metadata']['uid'],'node':p['spec'].get('nodeName'),'phase':p['status'].get('phase'),
 'containers':[{a:c.get(a) for a in ['name','ready','restartCount','image','imageID']} for c in p['status'].get('containerStatuses',[])]}
trivy=next(p for p in pods if p['metadata']['namespace']=='harbor' and p['metadata']['name']=='harbor-trivy-0')
dbscript="for f in /home/scanner/.cache/trivy/db/metadata.json /home/scanner/.cache/trivy/java-db/metadata.json; do stat -c '%n|%s|%i|%Y' \"$f\"; sha256sum \"$f\"; done"
db=run(['kubectl','-n','harbor','exec',trivy['metadata']['name'],'-c','trivy','--','sh','-c',dbscript])
sock=os.stat('/run/docker.sock')
with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(urllib.request.Request('http://192.168.64.11/',headers={'Host':'petclinic.devops.local'}),timeout=8) as r:http=r.status
agentCount=sum(p['metadata'].get('labels',{}).get('security.devops.local/purpose')=='gitleaks-validation' for p in pods)
data={'classification':'READ_ONLY_LIVE_PLANNING_NOT_AGENT_PROOF','collectedAt':datetime.datetime.now(datetime.timezone.utc).isoformat(),
 'nodes':nr,'pods':[dict(safe(p),requests={t:req(p,t) for t in ['cpu','memory','ephemeral-storage']}) for p in pods],
 'namespaces':[{'name':n['metadata']['name'],'labels':n['metadata'].get('labels',{})} for n in ns],'policies':policies,
 'controller':{'pod':safe(controller),'spec':controller['spec'],'observedIdentity':identity},'services':selected,
 'controllerEndpointSlices':k(['-n','ns-devops','get','endpointslices','-l','kubernetes.io/service-name=jenkins-service','-o','json']).get('items',[]),
 'uid24001HostProcesses':uid24001,'hostPasswdUid24001':[l.split(':')[0] for l in pathlib.Path('/etc/passwd').read_text().splitlines() if l.split(':')[2]=='24001'],
 'socket':{'mode':format(sock.st_mode&511,'04o'),'uid':sock.st_uid,'gid':sock.st_gid},
 'production':{'petclinicSpecSha256':hashlib.sha256(json.dumps(pet['spec'],sort_keys=True).encode()).hexdigest(),'image':[c['image'] for c in pet['spec']['template']['spec']['containers']],
  'ready':pet['status'].get('readyReplicas'),'httpStatus':http,'argoSync':argo['status']['sync']['status'],'argoHealth':argo['status']['health']['status'],'argoSource':argo['spec'].get('source'),
  'trivyPod':safe(trivy),'trivyDbMetadataObservation':db,'defectdojo':[safe(p) for p in pods if 'dojo' in p['metadata']['name'].lower()]},
 'agentPodCount':agentCount,'agentPodsCreated':0,'agentPodsDeleted':0,'release':0,'rollout':0,'mutations':0}
# Never archive pod env values or credential references in this read-only report.
data['controller']['spec']={a:controller['spec'].get(a) for a in ['serviceAccountName','nodeName','hostNetwork','hostPID','securityContext','volumes']}
print(json.dumps(data))
'''
def cluster(phase):
    x=json.loads(remote('sudo -n python3 -',HOST,150))
    save('cluster-'+phase+'.json',x)
    return {'nodes':[{'name':n['name'],'allocatable':n['allocatable'],'requests':n['scheduledRequests']} for n in x['nodes']],
            'production':{a:x['production'][a] for a in ['ready','httpStatus','argoSync','argoHealth','image']},'socket':x['socket']}
def baseline():
    old=json.loads((ROOT/'evidence/2026-11-04/security-manager-v2-gitleaks-jenkins-ci/baseline.json').read_text())
    paths=set(old['protectedFilesAtStart'])
    prev=ROOT/'evidence/2026-11-04/security-manager-v2-gitleaks-jenkins-ci'
    paths.update(str(p.relative_to(ROOT)) for p in prev.rglob('*') if p.is_file())
    paths.update(json.loads((prev/'code-sha256.json').read_text()))
    hashes={p:hashlib.sha256((ROOT/p).read_bytes()).hexdigest() for p in sorted(paths)}
    save('protected-before.json',{'head':subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip(),'files':hashes})
    return {'protectedFiles':len(hashes)}
if __name__=='__main__':
    phase=sys.argv[1];assert phase in ['before','after']
    if phase=='before':print(json.dumps(baseline()))
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as ex:
        fs={ex.submit(jenkins,phase):'jenkins',ex.submit(cluster,phase):'cluster'}
        for f in concurrent.futures.as_completed(fs):print(json.dumps({fs[f]:f.result()}))
