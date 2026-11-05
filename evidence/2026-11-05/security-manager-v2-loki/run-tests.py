"""No test runs in the repository. Export only new evidence, never old archives."""
from pathlib import Path
import sys,runpy,tempfile,subprocess,tarfile,io,json,shutil,re
sys.dont_write_bytecode=True
O=Path(__file__).resolve().parent;R=O.parents[2];b=runpy.run_path(str(O/'http-boundary.py'));base=json.loads((O/'protected-before.json').read_text());boundary=b['boundary']
assert boundary.snapshot(base['protected'])==base['protected'],'Protected metadata drift before tests'
assert json.loads((O/'http-boundary-preflight.json').read_text())['checks']['external']=='DENIED'
attempt=int(sys.argv[1]);assert 1<=attempt<=9;only='--loki-only'in sys.argv
blob=subprocess.check_output(['git','archive',base['head'],'infra','vars','resources','Jenkinsfile','Jenkinsfile.security-audit'],cwd=R)
with tempfile.TemporaryDirectory(prefix='security-cosign-boundary-')as d:
 t=Path(d).resolve()
 with tarfile.open(fileobj=io.BytesIO(blob))as tar:tar.extractall(t,filter='data')
 for n in base['approvedExistingChanges']:
  p=t/n;p.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(R/n,p)
 for p in (R/'infra/security/manager-v2/consumers').glob('*'):
  if p.is_file():shutil.copyfile(p,t/'infra/security/manager-v2/consumers'/p.name)
 ob=R/'infra/security/manager-v2/observability'
 if ob.exists():shutil.copytree(ob,t/'infra/security/manager-v2/observability')
 prefix='evidence/2026-11-05/security-manager-v2-cosign-real/real-linux/outputs'
 for name in ['A-three-valid','H-gitleaks-fail','G-semgrep-fail','F-cosign-tampered','D-gitleaks-disabled','C-semgrep-disabled','I-cosign-timeout','Q-cross-project-identity-rejected','P-service-project','E-all-disabled']:
  shutil.copytree(R/prefix/('attempt2-'+name),t/prefix/('attempt2-'+name))
 shutil.copytree(R/prefix/'H-gitleaks-fail',t/prefix/'H-gitleaks-fail')
 for n in ['infra/security/policy/engine.test.mjs','evidence/2026-11-01/policy-engine/gate-decision-before.json']:
  p=t/n;p.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(R/n,p)
 tests=sorted(str(p.relative_to(t))for p in (t/'infra/security/manager-v2').glob('*.test.mjs'))+sorted(str(p.relative_to(t))for p in (t/'infra/security/manager-v2/consumers').glob('*.test.mjs'))+['infra/security/policy/gitleaks-source-lock.test.mjs','infra/security/policy/engine.test.mjs','infra/security/semgrep-policy.test.mjs']
 if only:tests=['infra/security/manager-v2/consumers/loki.test.mjs']
 tests+=sorted(str(p.relative_to(t))for p in (t/'infra/security/manager-v2/observability').glob('*.test.mjs'))
 r=b['guarded'](t,[shutil.which('node'),'--test','--test-concurrency=1','--test-reporter=tap',*tests],timeout=180)
 with(O/f'tests-attempt{attempt}.tap').open('x')as f:f.write(r.stdout+r.stderr)
 for name in ['loki-protocol-samples','logql-contract-samples']:
  p=t/name
  if p.exists():shutil.copytree(p,O/f'{name}-attempt{attempt}')
 counts={k:int(m.group(1))if(m:=re.search(r'^# '+k+r' (\d+)$',r.stdout,re.M))else None for k in ['tests','pass','fail','skipped']}
receipt={'classification':'REAL_LOOPBACK_HTTP_AND_OFFLINE_QUERY_CONTRACT_PRIOR_FACTS_REPLAY','attempt':attempt,'scope':'LOKI_ONLY'if only else'RELATED_REGRESSION_AND_LOKI','exit':r.returncode,**counts,'testFiles':tests,'temporaryTreeRemoved':not Path(d).exists(),'historicalContentMetadataUnchanged':boundary.snapshot(base['protected'])==base['protected'],'productionLokiPush':0,'realDojoWrites':0,'scannersStarted':0,'consumerPolicyEvaluations':0,'allowedNetwork':'localhost:32185,32187 ONLY','grafanaRealQuery':'NOT_TESTED'}
with(O/f'tests-attempt{attempt}.json').open('x')as f:json.dump(receipt,f,indent=2);f.write('\n')
print(json.dumps(receipt));assert r.returncode==0 and receipt['historicalContentMetadataUnchanged'] and receipt['temporaryTreeRemoved']
