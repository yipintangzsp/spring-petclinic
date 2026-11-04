"""Candidate tests + replayed real artifacts in the existing OS write sandbox."""
from pathlib import Path
import sys,importlib.util,json,subprocess,io,tarfile,tempfile,shutil,re,hashlib
sys.dont_write_bytecode=True
O=Path(__file__).resolve().parent;R=O.parents[2];spec=importlib.util.spec_from_file_location('b',R/'infra/security/testing/evidence-boundary.py');b=importlib.util.module_from_spec(spec);spec.loader.exec_module(b)
base=json.loads((O/'protected-before.json').read_text());assert b.snapshot(base['protected'])==base['protected'];assert json.loads((O/'write-boundary-preflight.json').read_text())['canaryContentMtimeModeUnchanged']
attempt=int(sys.argv[1]);assert 1<=attempt<=5
blob=subprocess.check_output(['git','archive',base['head'],'infra','vars','resources','Jenkinsfile','Jenkinsfile.security-audit'],cwd=R)
with tempfile.TemporaryDirectory(prefix='security-cosign-boundary-') as d:
 tree=Path(d).resolve()
 with tarfile.open(fileobj=io.BytesIO(blob)) as tar:tar.extractall(tree,filter='data')
 for n in base['approvedExistingChanges']:
  p=tree/n;p.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(R/n,p)
 shutil.copytree(R/'infra/security/manager-v2/consumers',tree/'infra/security/manager-v2/consumers')
 # Historical reports are immutable input copies, explicitly REPLAY, not new scans.
 prefix='evidence/2026-11-05/security-manager-v2-cosign-real/real-linux/outputs';cases=['A-three-valid','H-gitleaks-fail','G-semgrep-fail','F-cosign-tampered','D-gitleaks-disabled','C-semgrep-disabled','I-cosign-timeout','Q-cross-project-identity-rejected','P-service-project','E-all-disabled']
 for name in cases:shutil.copytree(R/prefix/('attempt2-'+name),tree/prefix/('attempt2-'+name))
 shutil.copytree(R/prefix/'H-gitleaks-fail',tree/prefix/'H-gitleaks-fail')
 for n in ['infra/security/policy/engine.test.mjs','evidence/2026-11-01/policy-engine/gate-decision-before.json']:
  assert hashlib.sha256((R/n).read_bytes()).hexdigest()==base['protected'][n]['sha256'];p=tree/n;p.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(R/n,p)
 tests=sorted(str(p.relative_to(tree)) for p in (tree/'infra/security/manager-v2').glob('*.test.mjs'))+['infra/security/manager-v2/consumers/defectdojo.test.mjs','infra/security/policy/gitleaks-source-lock.test.mjs','infra/security/policy/engine.test.mjs','infra/security/semgrep-policy.test.mjs']
 assert all((tree/n).is_file() for n in tests)
 result=b.guarded(tree,[shutil.which('node'),'--test','--test-reporter=tap',*tests],timeout=90)
 with (O/f'tests-attempt{attempt}.tap').open('x') as f:f.write(result.stdout+result.stderr)
 counts={k:int(m.group(1))if(m:=re.search(r'^# '+k+r' (\d+)$',result.stdout,re.M))else None for k in ['tests','pass','fail','skipped']}
receipt={'classification':'STATIC_FIXTURE_AND_PRIOR_REAL_ARTIFACT_REPLAY_NOT_SCANS_OR_HTTP','attempt':attempt,'testFiles':tests,'exit':result.returncode,**counts,'temporaryTreeRemoved':not Path(d).exists(),'writeProtection':'REAL_OS_SANDBOX','scannersStarted':0,'policyEvaluationsByConsumer':0,'httpWrites':0,'remoteDelivery':'NOT_TESTED','contentAndMetadataUnchanged':b.snapshot(base['protected'])==base['protected']}
with (O/f'tests-attempt{attempt}.json').open('x') as f:json.dump(receipt,f,indent=2);f.write('\n')
print(json.dumps(receipt));assert result.returncode==0 and receipt['contentAndMetadataUnchanged'] and receipt['temporaryTreeRemoved']
