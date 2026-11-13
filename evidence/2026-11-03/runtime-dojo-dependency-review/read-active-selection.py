from pathlib import Path
import subprocess,shlex,json,hashlib
O=Path(__file__).resolve().parent
S=['ssh','-o','BatchMode=yes','-o','ConnectTimeout=6','-o','StrictHostKeyChecking=yes','-o','HostName=192.168.64.11','-o','HostKeyAlias=192.168.1.58','zhang@192.168.1.58']
paths=['vars/securityManager.groovy','resources/security-manager/petclinic-adapter.json','infra/security/governance/defectdojo.mjs','infra/security/manager/tool.mjs']
code="const fs=require('fs'),root='/var/jenkins_home/workspace/petclinic-ci/',paths="+json.dumps(paths)+";console.log(JSON.stringify({files:Object.fromEntries(paths.map(p=>[p,fs.readFileSync(root+p,'utf8')])),readOnly:true}));"
p=subprocess.run(S+['sudo -n kubectl exec -i -n ns-devops deploy/jenkins -c jenkins -- node -e '+shlex.quote(code)],capture_output=True,text=True,timeout=30);assert p.returncode==0,'ACTIVE_PUBLIC_SOURCE_READ_FAILED';x=json.loads(p.stdout);meta={}
for f,t in x['files'].items():
 h=hashlib.sha256(t.encode()).hexdigest();local=hashlib.sha256(Path(f).read_bytes()).hexdigest();dest=O/'active-v1-selection'/f;dest.parent.mkdir(parents=True,exist_ok=True);dest.write_text(t);meta[f]={'liveSha256':h,'localSha256':local,'equal':h==local,'snapshot':str(dest.relative_to(O))}
assert meta['vars/securityManager.groovy']['liveSha256']=='6854436a43b347fc94e895eada0b2048be238668817a4af33a228396f1c57c32'
for f in ['resources/security-manager/petclinic-adapter.json','infra/security/governance/defectdojo.mjs']:assert meta[f]['equal']
assert "if(cfg.adapter=='petclinic') plan=readJSON" in x['files']['vars/securityManager.groovy']
(O/'active-v1-selection-identity.json').write_text(json.dumps({'classification':'REAL_READ_ONLY_ACTIVE_CODE_SNAPSHOT','workspace':'/var/jenkins_home/workspace/petclinic-ci','productionBuild':270,'files':meta,'writesToRemote':0,'localManagerDiffersButCanonicalBranchAndDojoParentIdentical':True},indent=2)+'\n');print(json.dumps({p:{'sha256':r['liveSha256'],'matchesLocal':r['equal']} for p,r in meta.items()}))
