"""Existing filesystem sandbox; only the two Candidate Mock HTTP ports allowed."""
from pathlib import Path
import sys,importlib.util,subprocess,os
sys.dont_write_bytecode=True
R=Path(__file__).resolve().parents[3]
spec=importlib.util.spec_from_file_location('boundary',R/'infra/security/testing/evidence-boundary.py');boundary=importlib.util.module_from_spec(spec);spec.loader.exec_module(boundary)
def guarded(tree,args,timeout=180):
 tree=boundary.validate_tree(tree);command=boundary.sandbox_command(tree,args)
 rule='(deny network*)'+''.join('(allow network-bind (local ip "localhost:%d"))(allow network-inbound (local ip "localhost:%d"))(allow network-outbound (remote ip "localhost:%d"))'%(p,p,p) for p in [32185,32187])
 command[2]=command[2].replace('(deny network*)',rule);tmp=tree/'tmp';tmp.mkdir(exist_ok=True)
 env={'PATH':os.environ['PATH'],'HOME':str(tree),'TMPDIR':str(tmp),'PYTHONDONTWRITEBYTECODE':'1','LANG':'C'}
 return subprocess.run(command,cwd=tree,env=env,text=True,capture_output=True,timeout=timeout)
