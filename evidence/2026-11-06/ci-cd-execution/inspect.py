"""Bounded read-only prerequisites for the approved three changes."""
import json,runpy
from pathlib import Path
OUT=Path(__file__).resolve().parent
prior=OUT.parents[1]/'2026-11-05'
p=runpy.run_path(str(prior/'gitlab-push-demo/preflight.py'))
code=p['PREFIX']+r'''
import com.cloudbees.plugins.credentials.SystemCredentialsProvider
def user=api('/user')
println(JsonOutput.toJson([gitlabVersion:api('/version').version,
 project:api('/projects/12').findAll{k,v->k in ['id','path_with_namespace','visibility','namespace']},
 existingTokens:api('/projects/12/access_tokens').collect{[id:it.id,name:it.name,active:it.active,revoked:it.revoked,scopes:it.scopes,accessLevel:it.access_level]},
 mainProtection:api('/projects/12/protected_branches/main').push_access_levels.collect{[level:it.access_level]},
 writerCredentialAbsent:!SystemCredentialsProvider.instance.credentials.any{it.id=='security-gitops-demo-ssh'},
 branch:api('/projects/12/repository/branches/security-demo%2Fgitops-20261105').commit.id,
 trigger:api('/projects/12/repository/branches/security-demo%2Fgitlab-push-20261105').commit.id,
 demoBuild:Jenkins.instance.getItemByFullName('security-gitlab-push-demo').lastBuild.number]))
'''
j=p['script'](code)
host=r'''
import json,pathlib,subprocess,pwd,grp,os,hashlib
def absent(db,s):return subprocess.run(['getent',db,s],capture_output=True,text=True,timeout=3).returncode==2
root=pathlib.Path('/var/tmp/security-manager-gitleaks-v2-linux-20261105')
entry=(root/'ssh-entry.py').read_text()
out=root/'outputs'
items=[{'name':q.name,'mode':oct(q.stat().st_mode&511),'uid':q.stat().st_uid} for q in list(out.iterdir())[:6]]
print(json.dumps({'writerAccountAbsent':absent('passwd','security-gitops-demo'),'uid24022Free':absent('passwd','24022'),'gid24022Free':absent('group','24022'),
 'homeAbsent':not pathlib.Path('/var/lib/security-gitops-demo').exists(),
 'entry':entry,'outputsMode':oct(out.stat().st_mode&511),'outputExamples':items,
 'git':subprocess.check_output(['/usr/bin/git','--version'],text=True).strip(),
 'hostPublicKey':pathlib.Path('/etc/ssh/ssh_host_ed25519_key.pub').read_text().split()[:2]}))
'''
h=json.loads(p['m']['remote']('sudo -n python3 -',host,30))
assert j['writerCredentialAbsent'] and all(h[k] for k in ['writerAccountAbsent','uid24022Free','gid24022Free','homeAbsent'])
with (OUT/'inspection.json').open('x') as f:json.dump({'jenkins':j,'host':h},f,indent=2)
print(json.dumps({'jenkins':j,'host':{k:v for k,v in h.items() if k not in ['entry','hostPublicKey']}}))
