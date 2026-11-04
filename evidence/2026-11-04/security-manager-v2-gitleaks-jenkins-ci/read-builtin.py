"""Read actual built-in process identity only; no Docker API call or credential read."""
from pathlib import Path
import subprocess,json,shlex
O=Path(__file__).resolve().parent
S=['ssh','-o','BatchMode=yes','-o','ConnectTimeout=6','-o','StrictHostKeyChecking=yes','-o','HostName=192.168.64.11','-o','HostKeyAlias=192.168.1.58','zhang@192.168.1.58']
script=r'''const fs=require('fs');const s=fs.statSync('/run/docker.sock');let readable=false;try{fs.accessSync('/run/docker.sock',fs.constants.R_OK);readable=true}catch{}const p=fs.readFileSync('/proc/self/status','utf8');console.log(JSON.stringify({uid:process.getuid(),gid:process.getgid(),groups:process.getgroups(),dockerSocket:{uid:s.uid,gid:s.gid,mode:(s.mode&511).toString(8),readable},noNewPrivs:/^NoNewPrivs:\s+1$/m.test(p),capEff:(p.match(/^CapEff:\s+(\S+)/m)||[])[1],platform:process.platform,readOnly:true,dockerAPICalled:false,credentialsRead:false}));'''
command='sudo -n kubectl exec -n ns-devops deploy/jenkins -- node -e '+shlex.quote(script)
p=subprocess.run(S+[command],capture_output=True,text=True,timeout=30);assert p.returncode==0,p.stderr[-300:]
x=json.loads(p.stdout)
with (O/'builtin-identity.json').open('x') as f:json.dump(x,f,indent=2);f.write('\n')
print(json.dumps(x))
