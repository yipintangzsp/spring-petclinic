"""Read-only health checks; no agent audit, secrets, scanner or production writes."""
from pathlib import Path
import subprocess,json,shlex,sys,urllib.parse,concurrent.futures
sys.dont_write_bytecode=True
OUT=Path(__file__).resolve().parent
SSH=['ssh','-o','BatchMode=yes','-o','ConnectTimeout=6','-o','ConnectionAttempts=1','-o','StrictHostKeyChecking=yes','-o','HostName=192.168.64.11','-o','HostKeyAlias=192.168.1.58','zhang@192.168.1.58']
def save(name,x):
 with (OUT/name).open('x') as f:json.dump(x,f,indent=2);f.write('\n')
def remote(cmd,data=None,timeout=120):
 p=subprocess.run(SSH+[cmd],input=data,text=True,capture_output=True,timeout=timeout)
 if p.returncode:raise RuntimeError('SSH operation failed: '+p.stderr[-1200:])
 return p.stdout
def jenkins():
 sys.path.insert(0,'/Users/zhangsir/code/evidence/platform-20261011');from jenkins_control import NODE
 groovy='''import groovy.json.JsonOutput
import java.security.MessageDigest
def j=Jenkins.instance.getItemByFullName('petclinic-ci'), b=j.getBuildByNumber(270)
def hash={s->MessageDigest.getInstance('SHA-256').digest(s.getBytes('UTF-8')).encodeHex().toString()}
def a=b.artifacts.find{it.relativePath=='.devsecops/security-summary.json'}
println(JsonOutput.toJson([build:270,result:b.result.toString(),building:b.building,summarySha256:hash(new File(b.artifactsDir,a.relativePath).text),jobDefinitionSha256:hash(j.configFile.asString()),lastBuild:j.lastBuild.number,queueSize:Jenkins.instance.queue.items.size(),mutations:0]))'''
 r=json.loads(remote('sudo -n kubectl exec -i -n ns-devops deploy/github-webhook-relay -- node --max-old-space-size=24 -e '+shlex.quote(NODE),json.dumps({'path':'/scriptText','method':'POST','type':'application/x-www-form-urlencoded','body':urllib.parse.urlencode({'script':groovy}),'timeout':30000}),60));assert r['status']==200
 return json.loads(r['body'].split('\n')[0])
HOST=r'''
import json,subprocess,os,hashlib,urllib.request,urllib.error,datetime,shutil,pathlib
k=lambda a:json.loads(subprocess.check_output(['kubectl']+a,text=True,timeout=25))
p=k(['-n','petclinic','get','deploy','petclinic','-o','json']);a=k(['-n','argocd','get','application','petclinic','-o','json']);sock=os.stat('/run/docker.sock')
try:
 with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(urllib.request.Request('http://192.168.64.11/',headers={'Host':'petclinic.devops.local'}),timeout=8) as r:status=r.status
except urllib.error.HTTPError as e:status=e.code
except (urllib.error.URLError,TimeoutError):status='UNREACHABLE'
safe=lambda p:{'name':p['metadata']['name'],'uid':p['metadata']['uid'],'node':p['spec'].get('nodeName'),'containers':[{a:c.get(a) for a in ['imageID','ready','restartCount']} for c in p['status'].get('containerStatuses',[])]}
trivy=k(['-n','harbor','get','pod','harbor-trivy-0','-o','json']);db=subprocess.check_output(['kubectl','-n','harbor','exec','harbor-trivy-0','-c','trivy','--','sh','-c','for f in /home/scanner/.cache/trivy/db/metadata.json /home/scanner/.cache/trivy/java-db/metadata.json; do stat -c "%n|%s|%i|%Y" "$f"; sha256sum "$f"; done'],text=True,timeout=25)
print(json.dumps({'classification':'REAL_READ_ONLY_PRODUCTION_SNAPSHOT','at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'production':{'ready':p['status'].get('readyReplicas'),'deploymentUid':p['metadata']['uid'],'generation':p['metadata']['generation'],'specSha256':hashlib.sha256(json.dumps(p['spec'],sort_keys=True).encode()).hexdigest(),'image':[c['image'] for c in p['spec']['template']['spec']['containers']],'pods':[safe(q) for q in k(['-n','petclinic','get','pods','-l','app=petclinic','-o','json'])['items']],'argoSync':a['status']['sync']['status'],'argoHealth':a['status']['health']['status'],'argoRevision':a['status']['sync']['revision'],'nodes':[{'name':n['metadata']['name'],'ready':next(c['status'] for c in n['status']['conditions'] if c['type']=='Ready')} for n in k(['get','nodes','-o','json'])['items']],'http':status,'socket':{'mode':format(sock.st_mode&511,'04o'),'uid':sock.st_uid,'gid':sock.st_gid},'trivy':safe(trivy),'trivyDbMetadata':db,'dockerDaemon':{'pid':subprocess.check_output(['systemctl','show','docker','-p','MainPID','--value'],text=True).strip(),'activeEnter':subprocess.check_output(['systemctl','show','docker','-p','ActiveEnterTimestampMonotonic','--value'],text=True).strip(),'restarts':subprocess.check_output(['systemctl','show','docker','-p','NRestarts','--value'],text=True).strip()},'dojo':[safe(q) for q in k(['-n','devsecops-system','get','pods','-o','json'])['items'] if 'dojo'in q['metadata']['name']]},'fixtureCapacity':{'freeTmpBytes':shutil.disk_usage('/var/tmp').free,'memAvailableKiB':next(l.split()[1] for l in pathlib.Path('/proc/meminfo').read_text().splitlines() if l.startswith('MemAvailable:'))},'mutations':0}))
'''
if __name__=='__main__':
 phase=sys.argv[1];assert phase in ['before','after','final']
 with concurrent.futures.ThreadPoolExecutor(max_workers=2) as ex:
  j=ex.submit(jenkins);h=ex.submit(remote,'sudo -n python3 -',HOST)
  x={'jenkins':j.result(),'host':json.loads(h.result())};save('production-'+phase+'.json',x);print(json.dumps({'phase':phase,'jenkins':x['jenkins'],'health':{k:x['host']['production'][k] for k in ['ready','argoSync','argoHealth','http','socket']}}))
