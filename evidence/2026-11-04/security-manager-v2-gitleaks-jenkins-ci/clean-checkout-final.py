"""Reproduce only the new CI contract + unchanged Candidate, without live CI."""
from pathlib import Path
import subprocess,tarfile,io,tempfile,shutil,json
R=Path(__file__).resolve().parents[3];O=Path(__file__).resolve().parent
blob=subprocess.check_output(['git','archive','2ca60f7'],cwd=R)
with tempfile.TemporaryDirectory(prefix='gitleaks-ci-final-clean-') as t:
 root=Path(t)
 with tarfile.open(fileobj=io.BytesIO(blob)) as tar:
  for m in tar.getmembers():
   p=Path(m.name);assert not p.is_absolute() and '..' not in p.parts
   if m.isdir():(root/p).mkdir(parents=True,exist_ok=True)
   else:
    assert m.isfile();dest=root/p;dest.parent.mkdir(parents=True,exist_ok=True);dest.write_bytes(tar.extractfile(m).read())
 for name in ['infra/security/manager-v2/ci','infra/jenkins/gitleaks-validation']:shutil.copytree(R/name,root/name)
 tests=sorted(str(p.relative_to(root)) for p in (root/'infra/security/manager-v2').glob('*.test.mjs'))+['infra/security/manager-v2/ci/contract.test.mjs','infra/security/policy/gitleaks-source-lock.test.mjs']
 command=['node','--test',*tests]
 with (O/'clean-checkout-final-tests.tap').open('x') as f:p=subprocess.run(command,cwd=root,stdout=f,stderr=subprocess.STDOUT)
 (O/'clean-checkout-final-execution.json').write_text(json.dumps({'base':'2ca60f7','command':command,'exit':p.returncode,'scope':'OFFLINE_ONLY_NOT_JENKINS_CI','unrelatedInputsUsed':False,'privateCopyRemoved':True,'realScans':0,'jenkinsBuilds':0},indent=2)+'\n')
 assert p.returncode==0
print('Final clean checkout passed; no CI build or real scan.')
