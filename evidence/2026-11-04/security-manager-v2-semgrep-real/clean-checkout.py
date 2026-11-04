"""Run legacy writers ONLY in a disposable Git baseline, never in repository evidence."""
from pathlib import Path
import io,json,re,shutil,subprocess,tarfile,tempfile,hashlib
OUT=Path(__file__).resolve().parent;ROOT=OUT.parents[2];baseline=json.loads((OUT/'protected-before.json').read_text());base=baseline['base']
blob=subprocess.check_output(['git','archive',base,'infra','vars','resources','Jenkinsfile','Jenkinsfile.security-audit'],cwd=ROOT)
changes=list(baseline['approvedExistingFileChanges'])+['infra/security/manager-v2/semgrep-real.mjs','infra/security/manager-v2/semgrep-real.test.mjs','infra/security/testing/semgrep-real-suite.mjs']
with tempfile.TemporaryDirectory(prefix='semgrep-manager-v2-clean-') as t:
 root=Path(t)
 with tarfile.open(fileobj=io.BytesIO(blob)) as tar:tar.extractall(root,filter='data')
 for n in changes:
  p=root/n;p.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(ROOT/n,p)
 deps=json.loads((OUT/'offline-test-dependencies.json').read_text())['files']
 for n,h in deps.items():
  source=OUT/'offline-test-dependencies'/n;assert hashlib.sha256(source.read_bytes()).hexdigest()==h;dest=root/n;dest.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(source,dest)
 (root/'evidence/2026-11-01/command-parent/fixtures').mkdir(parents=True,exist_ok=True)
 (root/'evidence/2026-11-01/remaining-policy').mkdir(parents=True,exist_ok=True)
 tests=sorted(str(p.relative_to(root)) for p in (root/'infra/security/manager-v2').glob('*.test.mjs'))+['infra/security/semgrep-policy.test.mjs','infra/security/policy/gitleaks-source-lock.test.mjs','infra/security/policy/engine.test.mjs','infra/security/policy/command-parent.test.mjs','infra/security/policy/command-evidence.test.mjs']
 assert all((root/n).is_file() for n in tests),'Missing explicit test file'
 p=subprocess.run(['node','--test','--test-reporter=tap',*tests],cwd=root,text=True,capture_output=True,timeout=90)
 with (OUT/'clean-checkout-attempt3.tap').open('x') as f:f.write(p.stdout+p.stderr)
 counts={k:int(m.group(1))if(m:=re.search(r'^# '+k+r' (\d+)$',p.stdout,re.M))else None for k in ['tests','pass','fail','skipped']}
result={'classification':'ISOLATED_STATIC_FIXTURE_REPLAY_NOT_REAL_SCANNER','base':base,'currentOverlay':changes,'legacyHistoricalInputCopied':True,'legacyGeneratedOutputOnlyInTemporaryTree':True,'temporaryTreeRemoved':not Path(t).exists(),'exit':p.returncode,**counts,'productionOperations':0,'realScans':0}
with (OUT/'clean-checkout-attempt3.json').open('x') as f:json.dump(result,f,indent=2);f.write('\n')
print(json.dumps(result));assert p.returncode==0 and counts['pass']==230 and result['temporaryTreeRemoved']
# Hash check must include the previously restored history, after the isolated run.
assert all(hashlib.sha256((ROOT/n).read_bytes()).hexdigest()==h for n,h in baseline['protected'].items())
