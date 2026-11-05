"""Prepare three real, tiny Git commits. No remote push or executable checkout."""
import hashlib
import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path
OUT=Path(__file__).resolve().parent
BRANCH='security-demo/gitops-20261105'
FILE='infra/devops-lab/gitops-demo/configmap.yaml'
directory=Path(tempfile.mkdtemp(prefix='petclinic-gitops-demo-',dir='/tmp'))
env={**os.environ,'HOME':str(directory),'GIT_CONFIG_GLOBAL':'/dev/null','GIT_CONFIG_SYSTEM':'/dev/null',
 'GIT_AUTHOR_NAME':'DevSecOps GitOps Demo','GIT_AUTHOR_EMAIL':'gitops-demo@localhost',
 'GIT_COMMITTER_NAME':'DevSecOps GitOps Demo','GIT_COMMITTER_EMAIL':'gitops-demo@localhost'}
def git(args):
 return subprocess.check_output(['/opt/homebrew/bin/git','-c','core.hooksPath=/dev/null','-c','commit.gpgsign=false',*args],cwd=directory,env=env,text=True,timeout=10).strip()
cm={'apiVersion':'v1','kind':'ConfigMap','metadata':{'name':'petclinic-gitops-demo','namespace':'devsecops-test','labels':{'petclinic.devops.local/scope':'non-production-gitops-demo'}},'data':{'demo-stage':'baseline'}}
commits={}
try:
 git(['init','-q','--template=','-b',BRANCH])
 target=directory/FILE;target.parent.mkdir(parents=True)
 for stage,value in [('baseline','baseline'),('updated','updated')]:
  cm['data']['demo-stage']=value;target.write_text(json.dumps(cm,indent=2)+'\n')
  git(['add',FILE]);git(['commit','-qm','demo: GitOps '+stage+' [skip ci]'])
  sha=git(['rev-parse','HEAD']);tree=git(['rev-parse','HEAD^{tree}'])
  assert git(['ls-tree','-r','--name-only','HEAD'])==FILE
  bundle=OUT/(stage+'.bundle');git(['bundle','create',str(bundle),'refs/heads/'+BRANCH])
  raw=bundle.read_bytes();assert len(raw)<16384
  commits[stage]={'commit':sha,'tree':tree,'bundle':bundle.name,'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),'value':value}
 git(['revert','--no-edit',commits['updated']['commit']])
 assert git(['rev-parse','HEAD^{tree}'])==commits['baseline']['tree']
 assert json.loads(target.read_text())['data']['demo-stage']=='baseline'
 bundle=OUT/'restored.bundle';git(['bundle','create',str(bundle),'refs/heads/'+BRANCH]);raw=bundle.read_bytes()
 commits['restored']={'commit':git(['rev-parse','HEAD']),'tree':git(['rev-parse','HEAD^{tree}']),'bundle':bundle.name,'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),'value':'baseline','reverts':commits['updated']['commit']}
finally:
 assert directory.name.startswith('petclinic-gitops-demo-') and directory.parent==Path('/tmp')
 shutil.rmtree(directory)
app={'apiVersion':'argoproj.io/v1alpha1','kind':'Application',
 'metadata':{'name':'petclinic-gitops-demo','namespace':'argocd','labels':{'petclinic.devops.local/scope':'non-production-gitops-demo'}},
 'spec':{'project':'default','source':{'repoURL':'http://gitlab-service.ns-devops.svc.cluster.local/root/petclinic-platform.git','targetRevision':BRANCH,'path':'infra/devops-lab/gitops-demo','directory':{'recurse':False,'include':'configmap.yaml'}},
 'destination':{'server':'https://kubernetes.default.svc','namespace':'devsecops-test'},
 'syncPolicy':{'automated':{'prune':False,'selfHeal':True,'allowEmpty':False},'syncOptions':['CreateNamespace=false']}}}
with (OUT/'application.json').open('x') as f:json.dump(app,f,indent=2)
plan={'branch':BRANCH,'file':FILE,'commits':commits,'localFixtureCleaned':True,'remotePushes':0}
with (OUT/'prepared.json').open('x') as f:json.dump(plan,f,indent=2)
print(json.dumps(plan))
