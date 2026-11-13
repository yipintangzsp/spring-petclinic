"""Run unchanged Trivy differential suites in a disposable source tree, never historical evidence paths."""
from pathlib import Path
import subprocess,shutil,tempfile,json,hashlib,sys
O=Path(__file__).resolve().parent;R=O.parents[2];mode=sys.argv[1]
assert mode in ['original-v1','current-lock-failure','helm-versioned']
out=O/mode;out.mkdir(exist_ok=False)
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
historical=json.loads((O/'baseline.json').read_text())['historicalArtifactsAtStart']
lock=json.loads((R/'infra/security/policy/versions/trivy-parent-baseline-v1.json').read_text())
with tempfile.TemporaryDirectory(prefix='trivy-compatibility-replay-') as d:
 root=Path(d)
 for prefix in ['infra/security','infra/observability','vars','resources','infra/helm','charts/petclinic']:
  shutil.copytree(R/prefix,root/prefix,ignore=shutil.ignore_patterns('__pycache__','*.pyc'))
 for p in set(lock['sourceHashes'])|{'Jenkinsfile.helm-shadow','Jenkinsfile.candidate-build','infra/argocd/petclinic-helm-candidate.yaml'}:
  if (R/p).is_file():(root/p).parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(R/p,root/p)
 p=Path('evidence/2026-11-01/policy-engine/gate-decision-before.json');(root/p).parent.mkdir(parents=True);shutil.copyfile(R/p,root/p)
 if mode!='helm-versioned':shutil.copyfile(O/'trivy-parent.v1.mjs',root/'infra/security/policy/trivy-parent.mjs')
 if mode=='original-v1':
  old=subprocess.check_output(['git','show','741ea28:Jenkinsfile.security-audit'],cwd=R)
  (root/'Jenkinsfile.security-audit').write_bytes(old)
  assert all(sha(root/p)==h for p,h in lock['sourceHashes'].items())
 # The unchanged suites write only into this copied tree, then those outputs are copied to the new round.
 (root/'evidence/2026-11-01/trivy-parent/fixtures').mkdir(parents=True)
 cmd=['node','--test','--test-concurrency=1','infra/security/policy/trivy-db.test.mjs','infra/security/policy/trivy-parent.test.mjs','infra/security/policy/trivy-parent-workflow.test.mjs']
 with (out/'tests.log').open('w') as log:p=subprocess.run(cmd,cwd=root,stdout=log,stderr=subprocess.STDOUT)
 shutil.copytree(root/'evidence/2026-11-01/trivy-parent',out/'generated-evidence')
 files={str(p.relative_to(root)):sha(p) for p in root.rglob('*') if p.is_file() and 'evidence' not in p.relative_to(root).parts}
 (out/'execution.json').write_text(json.dumps({'mode':mode,'command':cmd,'exit':p.returncode,'sourceHashes':files,'realScannerExecutions':0,'originalTestsModified':False},indent=2)+'\n')
for name,h in historical.items():assert sha(R/name)==h,'Historical evidence was modified: '+name
print(json.dumps({'mode':mode,'exit':p.returncode,'historicalFilesUnchanged':len(historical),'temporarySourceTreeRemoved':True}))
if mode!='current-lock-failure':assert p.returncode==0,'Replay failed; see new-round test log'
