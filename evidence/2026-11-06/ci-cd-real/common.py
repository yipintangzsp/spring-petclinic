import json,runpy,sys,os
from pathlib import Path
BASE=Path(__file__).resolve().parent
OUT=BASE
if os.environ.get('CI_CD_ATTEMPT')=='2':
 OUT=BASE/'attempt2';OUT.mkdir(exist_ok=True)
ROOT=BASE.parents[2]
PRIOR=BASE.parents[1]/'2026-11-05'
p=runpy.run_path(str(PRIOR/'gitlab-push-demo/preflight.py'))
def save(name,v):
 with (OUT/name).open('x') as f:json.dump(v,f,indent=2)
def remote(code,timeout=55):return json.loads(p['m']['remote']('sudo -n python3 -',code,timeout))
def script(code):return p['script'](code)
