from pathlib import Path
import sys,os,json
repo=Path(__file__).resolve().parents[3];sys.path.insert(0,str(repo/'infra/security/testing'))
import sops_observation as observer
cmd=['/opt/homebrew/bin/docker','--host','unix:///Users/zhangsir/.colima/security-test/docker.sock','run','--rm','--pull=never','--network','none','--read-only','--cap-drop','ALL','--security-opt','no-new-privileges','--user','65532:65532','--entrypoint','/bin/sh','452d707d4862','-c','exec node --version']
r=observer.observe_child(cmd,env=dict(os.environ),cwd=Path.cwd(),identity='system:serviceaccount:devsecops-system:security-fixture-executor',evidence_ref='startup-node-prerequisite.json',timeout=30)
Path('evidence/startup-node-prerequisite.json').write_text(json.dumps(r,indent=2))
assert r['exit']['code']==127
