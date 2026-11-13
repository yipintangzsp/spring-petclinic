from pathlib import Path
import subprocess,json
O=Path(__file__).resolve().parent;rows=[]
for proxy in ['http://127.0.0.1:10808','http://192.168.1.238:10808']:
 p=subprocess.run(['curl','--proxy',proxy,'--connect-timeout','4','--max-time','10','-sS','-o','/dev/null','-w','%{http_code}','https://ghcr.io/v2/'],capture_output=True,text=True,timeout=13);rows.append({'origin':'Mac','proxy':proxy,'endpoint':'https://ghcr.io/v2/','exit':p.returncode,'httpStatus':p.stdout,'error':p.stderr[-450:]})
S=['ssh','-o','BatchMode=yes','-o','ConnectTimeout=6','-o','StrictHostKeyChecking=yes','-o','HostName=192.168.64.11','-o','HostKeyAlias=192.168.1.58','zhang@192.168.1.58'];cmd='sudo -n kubectl exec -n harbor harbor-trivy-0 -- env http_proxy=http://192.168.1.238:10808 https_proxy=http://192.168.1.238:10808 wget -S -T 8 -O /dev/null https://ghcr.io/v2/'
p=subprocess.run(S+[cmd],capture_output=True,text=True,timeout=18);rows.append({'origin':'Harbor Trivy container','proxy':'http://192.168.1.238:10808','endpoint':'https://ghcr.io/v2/','exit':p.returncode,'diagnostic':(p.stdout+p.stderr)[-1500:]});(O/'proxy-before.json').write_text(json.dumps({'probes':rows,'configurationChanges':0,'TLSVerificationDisabled':False},indent=2)+'\n');print(json.dumps(rows))
