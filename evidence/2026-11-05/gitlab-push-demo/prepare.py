"""Create only a disposable local Git documentation commit and tiny incremental bundle. No push."""
import hashlib,json,os,subprocess,tempfile
from pathlib import Path
ROOT=Path(__file__).resolve().parents[3]
OUT=Path(__file__).resolve().parent
BASE='9a78cc89f22fa98fb1ffcc43e2ae279299471793'
BRANCH='security-demo/gitlab-push-20261105'
DOC='docs/security-demo-gitlab-push.md'
env={**os.environ,'GIT_CONFIG_GLOBAL':'/dev/null','GIT_CONFIG_SYSTEM':'/dev/null',
     'GIT_AUTHOR_NAME':'DevSecOps Demo','GIT_AUTHOR_EMAIL':'devsecops-demo@localhost',
     'GIT_COMMITTER_NAME':'DevSecOps Demo','GIT_COMMITTER_EMAIL':'devsecops-demo@localhost'}
def git(args,cwd=ROOT,input=None):
 return subprocess.check_output(['/opt/homebrew/bin/git','-c','core.hooksPath=/dev/null',*args],
 input=input,text=True,cwd=cwd,env=env,timeout=15).strip()
objects=git(['rev-parse','--git-path','objects'])
directory=Path(tempfile.mkdtemp(prefix='gitlab-push-demo-',dir='/tmp'))
git(['init','-q','--template='],directory)
(directory/'.git/objects/info/alternates').write_text(str(Path(objects).resolve())+'\n')
git(['read-tree',BASE],directory)
content='# Isolated GitLab Push demonstration\n\nProject 12; fixed non-production branch; documentation only.\nNo production release, image publication or rollout.\n'
blob=git(['hash-object','-w','--stdin'],directory,content)
git(['update-index','--add','--cacheinfo','100644',blob,DOC],directory)
tree=git(['write-tree'],directory)
commit=git(['commit-tree',tree,'-p',BASE],directory,'demo: verify isolated GitLab push webhook\n')
git(['update-ref','refs/heads/'+BRANCH,commit],directory)
assert git(['diff-tree','--no-commit-id','--name-only','-r',commit],directory)==DOC
git(['bundle','create',str(directory/'demo.bundle'),'refs/heads/'+BRANCH,'^'+BASE],directory)
bundle=(directory/'demo.bundle').read_bytes()
assert len(bundle)<64*1024
r={'base':BASE,'branch':BRANCH,'commit':commit,'onlyChangedPath':DOC,'bundleBytes':len(bundle),
   'bundleSha256':hashlib.sha256(bundle).hexdigest(),'localTemporaryDirectory':str(directory),'pushExecuted':False}
with (OUT/'prepared.json').open('x') as f:json.dump(r,f,indent=2)
print(json.dumps(r))
