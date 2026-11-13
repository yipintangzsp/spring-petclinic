"""Disposable non-root Linux executor. Receives ONLY synthetic keys and MIN_RBAC token."""
from pathlib import Path
import os,sys,json,hashlib,shutil,subprocess
os.umask(0o077)
sys.path.insert(0,'/fixture/python')
import yaml
import isolated_sops_executor as g
root=Path('/fixture');case=json.loads((root/'case.json').read_text())
for name in ['boundary','results','control','home','work']:(root/name).mkdir(mode=0o700,exist_ok=True)
cfg=yaml.safe_load((root/'input.kubeconfig').read_bytes())
assert set(cfg['users'][0]['user'])=={'token'}
cfg['clusters'][0]['cluster']['server']='https://security-test-sops-control-plane:6443'
config=root/'executor.kubeconfig';g.write_private(config,yaml.safe_dump(cfg).encode(),0o600)
doc=json.loads((root/'input-profile.json').read_text())
doc['binding'].update(path=str(config),server=cfg['clusters'][0]['cluster']['server'],config_sha=hashlib.sha256(config.read_bytes()).hexdigest())
doc.update(real_kubectl='/fixture/tools/kubectl',kubectl_sha=hashlib.sha256((root/'tools/kubectl').read_bytes()).hexdigest(),temp_parent='/fixture/boundary',allowed_cwds=['/fixture/work'],fixture_input_root='/fixture/keys',fixture_age_file='/fixture/keys/'+('negative-wrong-key.agekey' if case['scenario']=='WRONG_AGE_KEY' else 'baseline.agekey'),heavy_holder='sm-sops-20261102-02',read_only=False)
profile=g.profile_from_document(doc)
tools=Path('/var/jenkins_home/platform-security/20261027')
if case['scenario']!='TOOL_MISSING':shutil.copyfile(root/'tools/sops',tools/'sops');(tools/'sops').chmod(0o500)
if case['scenario']=='REPORT_WRITE_FAILURE':(root/'work/.devsecops/secrets-gate.json').mkdir(parents=True,mode=0o700)
try:
 result=g.execute(str(config),{'KUBECONFIG':str(config)},profile=profile,mode='child',child_command=['/usr/bin/python3','/fixture/collector.py'],child_cwd=root/'work')
 (root/'results/guard.json').write_text(json.dumps(result))
except Exception as exc:
 (root/'results/guard.json').write_text(json.dumps({'status':'EXECUTOR_BLOCKED','errorClass':type(exc).__name__,'reason':str(exc) if isinstance(exc,g.BoundaryError) else 'details suppressed'}))
result={p.stem:json.loads(p.read_text()) for p in (root/'results').glob('*.json')}
print(json.dumps(result),flush=True)
