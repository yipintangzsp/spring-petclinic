from pathlib import Path
import json,subprocess,shlex
O=Path(__file__).resolve().parent;g=json.loads((O.parent/'trivy-infra-repair/image-reference-graph.json').read_text());unknown=[r for r in g['records'] if r['classification']=='D'];needles={}
for r in unknown:
 n=set([r['id'],*r['repoTags'],*r['repoDigests']])
 for v in list(n):
  if '/' in v:n.add(v.split('/',1)[1])
  if '@sha256:' in v:n.add(v.split('@')[-1])
 needles[r['id']]=sorted(n)
code=r'''
from pathlib import Path
import json,hashlib,subprocess
needles=NEEDLES;roots=[Path('/home/zhang/k8s-infra'),Path('/home/zhang/k8s-manifests'),Path('/home/zhang/devops-stack/ops-managed/manifests'),Path('/etc/systemd/system')];out={k:[] for k in needles};seen=0
for root in roots:
 if not root.exists():continue
 for p in root.rglob('*'):
  if not p.is_file() or p.is_symlink() or '.git' in p.parts or p.suffix not in ['.yml','.yaml','.json','.service','.md','.sh']:continue
  if any(s in str(p).lower() for s in ['secret','credential','password','.kube','private-key']):continue
  if p.stat().st_size>2*1024*1024:continue
  try:b=p.read_bytes();text=b.decode()
  except:continue
  seen+=1
  for image,ns in needles.items():
   matches=[v for v in ns if v in text]
   if matches:out[image].append({'path':str(p),'sha256':hashlib.sha256(b).hexdigest(),'matchingKnownImageIdentities':matches})
# Current sandbox image is a hidden dependency that container-list alone misses.
p=subprocess.run(['sudo','-n','k3s','crictl','info'],capture_output=True,text=True,timeout=20);sandbox=[]
if p.returncode==0:
 def walk(x,key=''):
  if isinstance(x,dict):
   for k,v in x.items():
    if 'sandbox' in k.lower() and isinstance(v,str):sandbox.append({'key':k,'image':v})
    else:walk(v,k)
 walk(json.loads(p.stdout))
print(json.dumps({'knownImageReferences':out,'filesExamined':seen,'noAbsenceProofFromTextSearch':True,'currentSandboxImages':sandbox,'mutations':0}))
'''.replace('NEEDLES',repr(needles))
S=['ssh','-o','BatchMode=yes','-o','ConnectTimeout=6','-o','StrictHostKeyChecking=yes','-o','HostName=192.168.64.11','-o','HostKeyAlias=192.168.1.58','zhang@192.168.1.58'];p=subprocess.run(S+['python3 -c '+shlex.quote(code)],capture_output=True,text=True,timeout=45);assert p.returncode==0;x=json.loads(p.stdout);(O/'remote-reference-proof.json').write_text(json.dumps(x,indent=2)+'\n');print(json.dumps({'filesExamined':x['filesExamined'],'imagesWithConfigReferences':sum(bool(v) for v in x['knownImageReferences'].values()),'sandboxImages':x['currentSandboxImages'],'mutations':0}))
