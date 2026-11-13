from pathlib import Path
import subprocess,json
O=Path(__file__).resolve().parent;S=['ssh','-o','BatchMode=yes','-o','ConnectTimeout=6','-o','StrictHostKeyChecking=yes','-o','HostName=192.168.64.11','-o','HostKeyAlias=192.168.1.58','zhang@192.168.1.58'];cmd='sudo -n timeout 50s ionice -c3 nice -n19 du -x -B1 --max-depth=2 /home/zhang/devops-stack/ops-managed'
p=subprocess.run(S+[cmd],capture_output=True,text=True,timeout=60);(O/'managed-usage.stdout').write_text(p.stdout);(O/'managed-usage-execution.json').write_text(json.dumps({'command':cmd,'exit':p.returncode,'stderr':p.stderr[-1000:]},indent=2));print(json.dumps({'exit':p.returncode,'bytes':len(p.stdout)}))
