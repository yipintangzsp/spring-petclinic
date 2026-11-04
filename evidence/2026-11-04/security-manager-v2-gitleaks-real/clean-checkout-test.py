"""Rebuild HEAD plus exactly the reviewed commit inputs; no unrelated untracked code."""
from pathlib import Path
import tempfile,subprocess,tarfile,io,json,shutil,sys
O=Path(__file__).resolve().parent;R=O.parents[2]
scope=json.loads((O/'commit-scope.json').read_text())
attempt=sys.argv[1] if len(sys.argv)>1 else 'first'
assert attempt in ['first','full-head']
archive=subprocess.check_output(['git','archive','HEAD']+(['infra/security','infra/observability','vars','resources','Jenkinsfile','Jenkinsfile.security-audit'] if attempt=='first' else []),cwd=R)
with tempfile.TemporaryDirectory(prefix='gitleaks-candidate-clean-') as t:
 root=Path(t)
 with tarfile.open(fileobj=io.BytesIO(archive)) as tar:
  for m in tar.getmembers():
   rel=Path(m.name);assert not rel.is_absolute() and '..' not in rel.parts
   if m.isdir():(root/rel).mkdir(parents=True,exist_ok=True)
   else:
    assert m.isfile();p=root/rel;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(tar.extractfile(m).read())
 for name in scope['modified']+scope['new']+scope['unchangedExistingTestDependenciesToTrack']:
  p=root/name;p.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(R/name,p)
 (root/'evidence/2026-11-01/gitleaks-parent/fixtures').mkdir(parents=True)
 tests=[str(p.relative_to(root)) for p in sorted((root/'infra/security/manager-v2').glob('*.test.mjs'))]
 tests+=['infra/security/policy/gitleaks-source-lock.test.mjs','infra/security/policy/gitleaks-evidence.test.mjs','infra/security/policy/gitleaks-parent.test.mjs','infra/security/policy/gitleaks-parent-workflow.test.mjs']
 command=['node','--test','--test-concurrency=1',*tests]
 logName='clean-checkout-tests.tap' if attempt=='first' else 'clean-checkout-full-head-tests.tap'
 with (O/logName).open('x') as log:p=subprocess.run(command,cwd=root,stdout=log,stderr=subprocess.STDOUT)
 receipt={'baseline':'0457b1e','reviewedInputPaths':scope['modified']+scope['new']+scope['unchangedExistingTestDependenciesToTrack'],'command':command,'exit':p.returncode,'unrelatedUntrackedFilesUsed':False,'realScannerExecutions':0,'privateCopyRemoved':True}
 (O/('clean-checkout-execution.json' if attempt=='first' else 'clean-checkout-full-head-execution.json')).write_text(json.dumps(receipt,indent=2)+'\n')
 print(json.dumps({'exit':p.returncode,'privateCopyRemoved':True}));raise SystemExit(p.returncode)
