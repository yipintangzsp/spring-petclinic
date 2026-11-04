"""All Node tests execute in one disposable tree under kernel write restrictions."""
from pathlib import Path
import importlib.util,sys,io,tarfile,subprocess,tempfile,json,shutil,re,hashlib
sys.dont_write_bytecode=True
OUT=Path(__file__).resolve().parent;ROOT=OUT.parents[2]
spec=importlib.util.spec_from_file_location('boundary',ROOT/'infra/security/testing/evidence-boundary.py');b=importlib.util.module_from_spec(spec);spec.loader.exec_module(b)
base=json.loads((OUT/'protected-before.json').read_text());assert json.loads((OUT/'write-boundary-preflight.json').read_text())['canaryContentAndMtimeModeUnchanged']
attempt=int(sys.argv[1])if len(sys.argv)>1 else 1;assert 1<=attempt<=5
allfiles=list(base['protected']);before=b.snapshot(allfiles)
assert before==base['protected'],'Protected content or metadata changed before tests'
scopes=['infra','vars','resources','Jenkinsfile','Jenkinsfile.security-audit'];archive=subprocess.check_output(['git','archive',base['head'],*scopes],cwd=ROOT)
changes=list(base['approvedExistingChanges'])+['infra/security/testing/cosign-real-suite.mjs']+['infra/security/manager-v2/cosign-real.mjs','infra/security/manager-v2/cosign-real.test.mjs','infra/security/policy/cosign-blob-evidence.mjs','infra/security/policy/versions/cosign-blob-candidate-v1.json','infra/security/testing/evidence-boundary.py']
with tempfile.TemporaryDirectory(prefix='security-cosign-boundary-') as d:
 tree=Path(d).resolve()
 with tarfile.open(fileobj=io.BytesIO(archive)) as tar:tar.extractall(tree,filter='data')
 for n in changes:
  if (ROOT/n).is_file():dest=tree/n;dest.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(ROOT/n,dest)
 # Copy unchanged untracked old tests/inputs explicitly, never run them at ROOT.
 dependencies=['infra/security/policy/cosign-parent.test.mjs','infra/security/policy/engine.test.mjs','infra/security/cosign-verification.test.mjs','evidence/2026-11-01/policy-engine/gate-decision-before.json','evidence/2026-11-01/remaining-policy/archived-270.json']
 for n in dependencies:
  source=OUT/'offline-inputs'/n;assert not source.is_symlink() and hashlib.sha256(source.read_bytes()).hexdigest()==base['protected'][n]['sha256'];dest=tree/n;dest.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(source,dest)
 (tree/'evidence/2026-11-01/cosign-parent/fixtures').mkdir(parents=True)
 tests=sorted(str(p.relative_to(tree)) for p in (tree/'infra/security/manager-v2').glob('*.test.mjs'))+['infra/security/cosign-verification.test.mjs','infra/security/semgrep-policy.test.mjs','infra/security/policy/gitleaks-source-lock.test.mjs','infra/security/policy/engine.test.mjs','infra/security/policy/cosign-parent.test.mjs']
 assert all((tree/n).is_file() for n in tests)
 result=b.guarded(tree,[shutil.which('node'),'--test','--test-reporter=tap',*tests],timeout=120)
 legacy=json.loads((tree/'evidence/2026-11-01/cosign-parent/differential.json').read_text())
 with (OUT/f'legacy-cosign-differential-attempt{attempt}.json').open('x') as f:json.dump(legacy,f,indent=2);f.write('\n')
 with (OUT/f'offline-attempt{attempt}.tap').open('x') as f:f.write(result.stdout+result.stderr)
 counts={k:int(m.group(1))if(m:=re.search(r'^# '+k+r' (\d+)$',result.stdout,re.M))else None for k in ['tests','pass','fail','skipped']}
after=b.snapshot(allfiles);content=[n for n in before if after[n]['sha256']!=before[n]['sha256']];metadata=[n for n in before if after[n]!=before[n] and after[n]['sha256']==before[n]['sha256']]
receipt={'classification':'STATIC_FIXTURE_REPLAY_IN_OS_WRITE_SANDBOX_NOT_REAL_TOOLS','attempt':attempt,'exit':result.returncode,**counts,'testFiles':tests,'sandbox':'macOS deny network + deny writes outside unique disposable tree','testCwdOutsideRepository':True,'protectedFiles':len(before),'contentChanges':content,'metadataChanges':metadata,'temporaryTreeRemoved':not Path(d).exists()}
with (OUT/f'offline-attempt{attempt}.json').open('x') as f:json.dump(receipt,f,indent=2);f.write('\n')
print(json.dumps(receipt));assert result.returncode==0 and not content and not metadata and receipt['temporaryTreeRemoved']
