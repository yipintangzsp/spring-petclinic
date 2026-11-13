"""Read-only local capability inspection. No Kubernetes API, cluster creation or secrets.
Only filtered kubeconfig context metadata is persisted; no auth fields are archived.
"""
import json,os,platform,shutil,subprocess
from pathlib import Path
OUT=Path(__file__).resolve().parent
def run(args,env=None):
 try:
  p=subprocess.run(args,capture_output=True,text=True,timeout=10,env=env)
  return {'command':args,'exit':p.returncode,'stdout':p.stdout[:14000],'stderr':p.stderr[:1800]}
 except subprocess.TimeoutExpired:return {'command':args,'timeout':True}
def save(n,d): (OUT/n).write_text(json.dumps(d,ensure_ascii=False,indent=2)+'\n')
tools={n:shutil.which(n) for n in ['docker','orb','kind','k3d','k3s','kubectl','sops','age','age-keygen','podman','colima','nerdctl','lima','limactl']}
apps={p:Path(p).is_dir() for p in ['/Applications/OrbStack.app','/Applications/Docker.app',str(Path.home()/'Applications/OrbStack.app'),str(Path.home()/'Applications/Docker.app')]}
sockets=[]
for p in ['/var/run/docker.sock',str(Path.home()/'.docker/run/docker.sock'),str(Path.home()/'.orbstack/run/docker.sock'),str(Path.home()/'.colima/default/docker.sock')]:
 sockets.append({'path':p,'lexists':os.path.lexists(p),'exists':os.path.exists(p),'symlinkTarget':os.readlink(p) if os.path.islink(p) else None})
commands=[]
for args in [['docker','--version'],['docker','context','ls','--format','{{json .}}'],['docker','context','show'],['kind','version'],['colima','list','--json'],['limactl','list','--json']]:
 if tools.get(args[0]):commands.append(run(args))
# Force a previously inspected local UNIX endpoint. Never use remote Docker contexts.
env=os.environ.copy();env.pop('DOCKER_CONTEXT',None);env['DOCKER_HOST']='unix:///var/run/docker.sock'
if tools['docker']:commands.append(run(['docker','--host','unix:///var/run/docker.sock','info','--format','{{json .ServerVersion}}'],env))
if tools['kind']:commands.append(run(['kind','get','clusters'],env))
listeners=[]
if shutil.which('lsof'):
 for port in [63731,26443]:listeners.append(run(['lsof','-nP','-iTCP:'+str(port),'-sTCP:LISTEN','-Fpcn']))
frozen_root=Path('/var/jenkins_home/platform-security/20261027')
save('capability-inventory.json',{'host':{'system':platform.system(),'machine':platform.machine(),'release':platform.release()},'toolPaths':tools,'applicationsAtCommonLocations':apps,'sockets':sockets,'commands':commands,'listenerMetadataOnly':listeners,'frozenBinaryPaths':{str(frozen_root/n):{'exists':(frozen_root/n).is_file()} for n in ['sops','age','age-keygen']},'actions':'Read-only inspection; no start/install/create; remote Docker endpoints not contacted'})
# config view reads local metadata only; omit users and every credential field.
p=subprocess.run(['kubectl','config','view','-o','json'],capture_output=True,text=True,timeout=10)
if p.returncode:
 save('context-metadata.json',{'localConfigReadExit':p.returncode,'stderr':p.stderr[:1200],'kubernetesApiRequests':0})
else:
 d=json.loads(p.stdout);clusters={x['name']:x.get('cluster',{}) for x in d.get('clusters',[])};rows=[]
 for x in d.get('contexts',[]):
  c=x['context'];k=clusters.get(c.get('cluster'),{})
  rows.append({'name':x['name'],'cluster':c.get('cluster'),'server':k.get('server'),'namespace':c.get('namespace'),'tlsServerName':k.get('tls-server-name'),'skipTLSVerify':k.get('insecure-skip-tls-verify',False),'caConfigured':bool(k.get('certificate-authority-data') or k.get('certificate-authority')),'credentialFieldsExcluded':True})
 save('context-metadata.json',{'sourceCommand':['kubectl','config','view','-o','json'],'scope':'Local context/server metadata only; no --raw, no API request, no auth-plugin execution, no use-context','currentContext':d.get('current-context'),'contexts':rows,'kubernetesApiRequests':0,'freshNamespaceUIDQueries':0,'freshIsolatedClusterIdentity':'NOT_PROVEN'})
print('Read-only capability and sanitized local context metadata saved; Kubernetes API requests: 0')
