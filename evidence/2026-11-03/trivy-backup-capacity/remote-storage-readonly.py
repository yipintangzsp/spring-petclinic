from pathlib import Path
import subprocess,json
O=Path(__file__).resolve().parent
S=['ssh','-o','BatchMode=yes','-o','ConnectTimeout=6','-o','StrictHostKeyChecking=yes','-o','HostName=192.168.64.11','-o','HostKeyAlias=192.168.1.58','zhang@192.168.1.58']
script='''import subprocess,json
rows=[]
for node in ['devops','aliyun-worker','ucloud-worker']:
 p=subprocess.run(['sudo','-n','kubectl','get','--raw','/api/v1/nodes/'+node+'/proxy/stats/summary'],capture_output=True,text=True,timeout=25)
 row={'node':node,'exit':p.returncode,'storagePermissionExpanded':False}
 if p.returncode==0:
  d=json.loads(p.stdout)['node'];row['rootFs']=d.get('fs');row['imageFs']=d.get('runtime',{}).get('imageFs')
 else:row['reason']='Read-only node storage stats unavailable; cannot accept as backup destination'
 rows.append(row)
print(json.dumps({'source':'AUTHORIZED_KUBERNETES_NODE_STATS_ONLY_NOT_REMOTE_HOST_WRITE_OR_MOUNT','nodes':rows}))
'''
z=subprocess.run(S+['python3 -'],input=script,text=True,capture_output=True,timeout=90)
if z.returncode:raise SystemExit('Trusted read-only management query failed; no alternate auth attempted')
d=json.loads(z.stdout);(O/'remote-storage-readonly.json').write_text(json.dumps(d,indent=2)+'\n')
print(json.dumps([{'node':x['node'],'exit':x['exit'],'freeGiB':x.get('rootFs',{}).get('availableBytes',0)/1024**3} for x in d['nodes']]))
