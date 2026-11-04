"""Reproduce only offline tests: trusted Git baseline + approved candidate overlay."""
from pathlib import Path
import io,json,re,shutil,subprocess,tarfile,tempfile
OUT=Path(__file__).resolve().parent;ROOT=OUT.parents[2]
scope='infra/jenkins/gitleaks-validation/ephemeral-agent'
base=json.loads((OUT/'baseline.json').read_text())['head']
paths=['infra','vars','resources','Jenkinsfile','Jenkinsfile.security-audit','evidence/2026-11-04/security-manager-v2-gitleaks-real/linux-package-retry.json']
blob=subprocess.check_output(['git','archive',base,*paths],cwd=ROOT)
with tempfile.TemporaryDirectory(prefix='gitleaks-readiness-clean-') as t:
 root=Path(t)
 with tarfile.open(fileobj=io.BytesIO(blob)) as tar:tar.extractall(root,filter='data')
 shutil.rmtree(root/scope);shutil.copytree(ROOT/scope,root/scope)
 tests=sorted(str(p.relative_to(root)) for p in (root/'infra/security/manager-v2').glob('*.test.mjs'))+['infra/security/manager-v2/ci/contract.test.mjs','infra/security/policy/gitleaks-source-lock.test.mjs']+sorted(str(p.relative_to(root)) for p in (root/scope).glob('*.test.mjs'))
 r=subprocess.run(['node','--test','--test-reporter=tap',*tests],cwd=root,text=True,capture_output=True)
 with (OUT/'clean-checkout.tap').open('x') as f:f.write(r.stdout+r.stderr)
 counts={k:int(m.group(1)) if (m:=re.search(r'^# '+k+r' (\d+)$',r.stdout,re.M)) else None for k in ['tests','pass','fail','skipped']}
x={'classification':'CLEAN_CHECKOUT_STATIC_FIXTURE_NOT_REAL_AGENT_OR_CI','base':base,'archiveScopes':paths,'overlayOnly':scope,'exit':r.returncode,**counts,'temporaryCheckoutRemoved':not Path(t).exists(),'realScans':0,'jenkinsBuilds':0}
with (OUT/'clean-checkout.json').open('x') as f:json.dump(x,f,indent=2);f.write('\n')
print(json.dumps(x));assert r.returncode==0 and counts['pass']==241 and x['temporaryCheckoutRemoved']
