"""No uploads, remote files or mutations: SSH sends Python source to stdin only."""
from pathlib import Path
import subprocess,json,datetime,sys
O=Path(__file__).resolve().parent
SSH=['ssh','-o','BatchMode=yes','-o','ConnectTimeout=8','-o','ServerAliveInterval=15','-o','ServerAliveCountMax=2','-o','StrictHostKeyChecking=yes','-o','HostName=192.168.64.11','-o','HostKeyAlias=192.168.1.58','zhang@192.168.1.58']
def execute(payload,output,timeout=150):
 start=datetime.datetime.now(datetime.timezone.utc).isoformat();p=subprocess.run(SSH+['sudo -n python3 -'],input=(O/payload).read_text(),capture_output=True,text=True,timeout=timeout)
 if p.returncode:x={'classification':'READ_ONLY_PROBE_FAILED','startedAt':start,'exit':p.returncode,'stderr':p.stderr[-2000:]}
 else:x=json.loads(p.stdout)
 with(O/output).open('x')as f:json.dump(x,f,indent=2);f.write('\n')
 print(json.dumps({'file':output,'exit':p.returncode,'startedAt':start,'completedAt':datetime.datetime.now(datetime.timezone.utc).isoformat(),'remoteFilesCreated':0,'productionMutations':0}));return x
if __name__=='__main__':execute(sys.argv[1],sys.argv[2],int(sys.argv[3])if len(sys.argv)>3 else 150)
