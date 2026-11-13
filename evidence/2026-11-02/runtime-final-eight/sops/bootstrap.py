"""Ephemeral non-root runtime; raw envelope crosses stdout pipe only, never file."""
from pathlib import Path
import sys,os,json,hashlib,shutil,subprocess
os.umask(0o077);sys.path.insert(0,'/fixture/python');import yaml;import isolated_sops_executor as g
root=Path('/fixture');case=json.loads((root/'case.json').read_text())
for name in ['boundary','home','work']:(root/name).mkdir(mode=0o700,exist_ok=True)
cfg=yaml.safe_load((root/'input-executor.kubeconfig').read_bytes());assert set(cfg['users'][0]['user'])=={'token'}
cfg['clusters'][0]['cluster']['server']='https://security-test-sops-control-plane:6443'
config=root/'executor.kubeconfig';g.write_private(config,yaml.safe_dump(cfg).encode(),0o600)
doc=json.loads((root/'input-executor-profile.json').read_text());doc['binding'].update(path=str(config),server=cfg['clusters'][0]['cluster']['server'],config_sha=hashlib.sha256(config.read_bytes()).hexdigest())
doc.update(real_kubectl='/fixture/tools/kubectl',kubectl_sha=hashlib.sha256((root/'tools/kubectl').read_bytes()).hexdigest(),temp_parent='/fixture/boundary',allowed_cwds=['/fixture/work'],fixture_input_root='/fixture/keys',fixture_age_file='/fixture/keys/'+('negative-wrong-key.agekey' if case['scenario']=='WRONG_KEY' else 'baseline.agekey'),heavy_holder=case['holder'],read_only=True)
profile=g.profile_from_document(doc)
assert hashlib.sha256((root/'node/bin/node').read_bytes()).hexdigest()=='d09e299258c24f7cdf6f5d5ec185e3a56512b27a697113735dac909f1cac7b8d'
tools=Path('/var/jenkins_home/platform-security/20261027')
if case['scenario']!='TOOL_MISSING':shutil.copyfile(root/'tools/sops',tools/'sops');(tools/'sops').chmod(0o500)
command=['/fixture/node/bin/node','/fixture/collector.mjs'];run=subprocess.run;observed={}
def observe_run(args,*a,**kw):
 result=run(args,*a,**kw)
 if args==command:observed['result']=result
 return result
# Passive capture of the unchanged guard's exact trusted child completion.
# Guard still validates config, CA, UID, real SA identity and token before run.
subprocess.run=observe_run
guard=g.execute(str(config),{'KUBECONFIG':str(config)},profile=profile,mode='child',child_command=command,child_cwd=root/'work')
child=observed['result'];assert child.returncode==0
packet=json.loads(child.stdout);packet['guard']=guard;packet['executionScope']='CONTROLLED_ISOLATED_RUNTIME';packet['scenario']=case['scenario']
sys.stdout.write(json.dumps(packet));sys.stdout.flush()
