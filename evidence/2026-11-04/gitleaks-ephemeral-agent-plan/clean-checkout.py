"""Reproduce offline tests from HEAD plus ONLY this round's candidate directory."""
from pathlib import Path
import io,json,re,shutil,subprocess,tarfile,tempfile
ROOT=Path(__file__).resolve().parents[3];OUT=Path(__file__).resolve().parent
scope='infra/jenkins/gitleaks-validation/ephemeral-agent'
head=subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip()
blob=subprocess.check_output(['git','archive',head],cwd=ROOT)
removed=False
with tempfile.TemporaryDirectory(prefix='gitleaks-agent-plan-clean-') as t:
    root=Path(t)
    with tarfile.open(fileobj=io.BytesIO(blob)) as tar:tar.extractall(root,filter='data')
    assert not (root/scope).exists(),'Use the recorded pre-change parent for this reproduction'
    shutil.copytree(ROOT/scope,root/scope)
    tests=sorted(str(p.relative_to(root)) for p in (root/'infra/security/manager-v2').glob('*.test.mjs'))+[
        'infra/security/manager-v2/ci/contract.test.mjs','infra/security/policy/gitleaks-source-lock.test.mjs',scope+'/plan.test.mjs']
    r=subprocess.run(['node','--test','--test-reporter=tap',*tests],cwd=root,text=True,capture_output=True)
    with (OUT/'clean-checkout.tap').open('x') as f:f.write(r.stdout+r.stderr)
    counts={k:int(m.group(1)) if (m:=re.search(r'^# '+k+r' (\d+)$',r.stdout,re.M)) else None for k in ['tests','pass','fail','skipped']}
removed=not Path(t).exists()
result={'base':head,'candidateScopeOnly':scope,'exit':r.returncode,**counts,'temporaryCheckoutRemoved':removed,
        'classification':'CLEAN_CHECKOUT_OFFLINE_CONTRACT_NOT_POD_OR_CI','realScans':0,'jenkinsBuilds':0}
with (OUT/'clean-checkout.json').open('x') as f:json.dump(result,f,indent=2);f.write('\n')
print(json.dumps(result))
assert r.returncode==0 and removed
