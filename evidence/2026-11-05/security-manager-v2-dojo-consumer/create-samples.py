from pathlib import Path
import sys,importlib.util,io,tarfile,tempfile,json,subprocess,shutil,hashlib
sys.dont_write_bytecode=True
O=Path(__file__).resolve().parent;R=O.parents[2];spec=importlib.util.spec_from_file_location('b',R/'infra/security/testing/evidence-boundary.py');b=importlib.util.module_from_spec(spec);spec.loader.exec_module(b);base=json.loads((O/'protected-before.json').read_text());assert b.snapshot(base['protected'])==base['protected']
archive=subprocess.check_output(['git','archive',base['head'],'infra','vars','resources','Jenkinsfile','Jenkinsfile.security-audit'],cwd=R)
with tempfile.TemporaryDirectory(prefix='security-cosign-boundary-') as d:
 tree=Path(d).resolve()
 with tarfile.open(fileobj=io.BytesIO(archive)) as t:t.extractall(tree,filter='data')
 shutil.copyfile(R/'infra/security/manager-v2/router.mjs',tree/'infra/security/manager-v2/router.mjs');shutil.copytree(R/'infra/security/manager-v2/consumers',tree/'infra/security/manager-v2/consumers')
 prefix=Path('evidence/2026-11-05/security-manager-v2-cosign-real/real-linux/outputs')
 for name in ['A-three-valid','H-gitleaks-fail','G-semgrep-fail','F-cosign-tampered','D-gitleaks-disabled','C-semgrep-disabled','I-cosign-timeout','P-service-project','Q-cross-project-identity-rejected']:
  shutil.copytree(R/prefix/('attempt2-'+name),tree/prefix/('attempt2-'+name))
 rel=O.relative_to(R)/'samples.mjs';(tree/rel).parent.mkdir(parents=True);shutil.copyfile(O/'samples.mjs',tree/rel)
 target=tree/'prepared-samples';p=b.guarded(tree,[shutil.which('node'),str(rel),str(target)],timeout=30)
 with(O/'sample-generation.log').open('x') as f:f.write(p.stdout+p.stderr)
 assert p.returncode==0,p.stderr
 dest=O/'samples';dest.mkdir();manifest={}
 for source in target.rglob('*'):
  if source.is_file():
   assert not source.is_symlink();data=source.read_bytes();assert b'PRIVATE KEY-----'not in data;relative=source.relative_to(target);out=dest/relative;out.parent.mkdir(parents=True,exist_ok=True)
   with out.open('xb') as f:f.write(data)
   out.chmod(0o444);manifest[str(relative)]={'sha256':hashlib.sha256(data).hexdigest(),'bytes':len(data)}
assert b.snapshot(base['protected'])==base['protected']
with(O/'sample-generation.json').open('x') as f:json.dump({'classification':'ACTUAL_ADAPTER_ON_REPLAYED_REAL_ARTIFACTS','files':manifest,'sampleCases':9,'temporaryTreeRemoved':not Path(d).exists(),'protectedContentAndMetadataUnchanged':True,'newScans':0,'consumerPolicyEvaluations':0,'httpRequests':0,'remoteDelivery':'NOT_TESTED'},f,indent=2);f.write('\n')
print(json.dumps({'sampleCases':9,'files':len(manifest),'temporaryTreeRemoved':not Path(d).exists(),'httpRequests':0}))
