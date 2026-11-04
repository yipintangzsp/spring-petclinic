"""Execute original parent/Groovy oracles in disposable copies, never old evidence."""
from pathlib import Path
import argparse,shutil,tempfile,subprocess,json,hashlib
R=Path(__file__).resolve().parents[3]
def run(output,mode):
 out=Path(output)/mode;out.mkdir(exist_ok=False)
 with tempfile.TemporaryDirectory(prefix='gitleaks-frozen-') as t:
  root=Path(t)
  for prefix in ['infra/security','infra/observability','vars','resources']:shutil.copytree(R/prefix,root/prefix,ignore=shutil.ignore_patterns('__pycache__','*.pyc'))
  for p in R.glob('Jenkinsfile*'):
   if p.is_file():shutil.copyfile(p,root/p.name)
  source=R/'evidence/2026-11-01/policy-engine/gitleaks-differential.json';dest=root/source.relative_to(R);dest.parent.mkdir(parents=True);shutil.copyfile(source,dest)
  (root/'evidence/2026-11-01/gitleaks-parent/fixtures').mkdir(parents=True)
  if mode=='original-v1':
   shutil.copyfile(R/'infra/security/policy/versions/gitleaks-parent.frozen-v1.mjs',root/'infra/security/policy/gitleaks-parent.mjs')
   old=subprocess.check_output(['git','show','ee6df0c285b57600e8c09e8ffaad08fccb79f497:Jenkinsfile.security-audit'],cwd=R)
   (root/'Jenkinsfile.security-audit').write_bytes(old)
  command=['node','--test','--test-concurrency=1','infra/security/policy/gitleaks-evidence.test.mjs','infra/security/policy/gitleaks-parent.test.mjs','infra/security/policy/gitleaks-parent-workflow.test.mjs']
  with (out/'tests.log').open('w') as f:r=subprocess.run(command,cwd=root,stdout=f,stderr=subprocess.STDOUT)
  generated=root/'evidence/2026-11-01/gitleaks-parent'
  if generated.exists():shutil.copytree(generated,out/'generated-evidence')
  (out/'execution.json').write_text(json.dumps({'mode':mode,'command':command,'exit':r.returncode,'realScannerExecutions':0,'evidenceClass':'CONTROLLED_ORIGINAL_PARENT_AND_GROOVY_EXECUTION','privateCopyRemoved':True},indent=2)+'\n')
 print(json.dumps({'mode':mode,'exit':r.returncode}));return r.returncode
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('mode',choices=['original-v1','current']);p.add_argument('--output',required=True);a=p.parse_args();raise SystemExit(run(a.output,a.mode))
