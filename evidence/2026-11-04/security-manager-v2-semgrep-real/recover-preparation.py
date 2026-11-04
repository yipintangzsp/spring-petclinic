"""Identify and remove only this failed pre-scan temporary fixture, never glob delete."""
import runpy,json
from pathlib import Path
p=Path(__file__).resolve().parent;api=runpy.run_path(str(p/'inspect-production.py'))
s=r'''
from pathlib import Path
import time,json,hashlib,shutil
rows=[]
for d in Path('/var/tmp').glob('security-manager-gitleaks-*'):
 if d.is_dir() and d.stat().st_uid==0 and time.time()-d.stat().st_ctime<1200:
  files=sorted(x.name for x in d.iterdir())
  if files==['gitleaks'] and hashlib.sha256((d/'gitleaks').read_bytes()).hexdigest()=='db4d43dd4ab54f047a2d18d210a8d2294e2e5cc26d1e26a299a9675916f5647d':rows.append(d)
assert len(rows)==1,[str(p) for p in rows]
d=rows[0];receipt={'failedAttempt':'native file count assertion expected28 actual27','workspace':str(d),'observedFiles':['gitleaks'],'scannerStarted':False,'policyEvaluations':0}
shutil.rmtree(d);receipt['removed']=not d.exists();print(json.dumps(receipt))
'''
x=json.loads(api['remote']('sudo -n python3 -',s));api['save']('preparation-attempt1-failure-cleanup.json',x);print(json.dumps(x))
