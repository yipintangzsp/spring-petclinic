"""Keep controller and build JVMs within a practical combined memory budget."""
import json,subprocess,os
from pathlib import Path
root=Path('/opt/petclinic-observability/backup');root.mkdir(parents=True,exist_ok=True)
backup=root/'jenkins-before-resource-fix.json'
if not backup.exists():
 data=subprocess.check_output(['kubectl','get','deploy','jenkins','-n','ns-devops','-o','json'],timeout=45)
 fd=os.open(backup,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
 with os.fdopen(fd,'wb') as f:f.write(data)
patch={'spec':{'template':{'spec':{'containers':[{'name':'jenkins','resources':{'limits':{'cpu':'2','memory':'3Gi'}},'livenessProbe':{'timeoutSeconds':10,'failureThreshold':6},'readinessProbe':{'timeoutSeconds':10}}]}}}}
subprocess.run(['kubectl','patch','deploy','jenkins','-n','ns-devops','--type=strategic','-p',json.dumps(patch)],check=True,timeout=45)
print('Jenkins memory limit 3Gi; liveness tolerates bounded temporary build contention. Backup stored root-only.')
