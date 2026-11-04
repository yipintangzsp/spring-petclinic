"""Read-only feasibility check. Do not reuse the host's shared nobody identity."""
from pathlib import Path
import subprocess,json
O=Path(__file__).resolve().parent
S=['ssh','-o','BatchMode=yes','-o','ConnectTimeout=6','-o','StrictHostKeyChecking=yes','-o','HostName=192.168.64.11','-o','HostKeyAlias=192.168.1.58','zhang@192.168.1.58']
script=r'''
import shutil,json,pathlib
processes=[]
for p in pathlib.Path('/proc').glob('[0-9]*/status'):
 try:
  lines=p.read_text().splitlines();uid=next((x.split()[1] for x in lines if x.startswith('Uid:')),None)
  if uid=='65534':processes.append({'pid':int(p.parent.name),'name':lines[0].split(':',1)[1].strip(),'cgroup':(p.parent/'cgroup').read_text().strip()})
 except (PermissionError,FileNotFoundError,ProcessLookupError):pass
print(json.dumps({'java':shutil.which('java'),'setpriv':shutil.which('setpriv'),'node':shutil.which('node'),'existingUid65534Processes':processes,'readOnly':True,'provisioningPerformed':False}))
'''
p=subprocess.run(S+['python3 -'],input=script,text=True,capture_output=True,timeout=30);assert p.returncode==0,p.stderr[-300:]
x=json.loads(p.stdout)
with (O/'agent-resource-observation.json').open('x') as f:json.dump(x,f,indent=2);f.write('\n')
print(json.dumps({'javaAvailable':bool(x['java']),'sharedUid65534ProcessCount':len(x['existingUid65534Processes']),'names':sorted({z['name'] for z in x['existingUid65534Processes']}),'readOnly':True,'provisioningPerformed':False}))
