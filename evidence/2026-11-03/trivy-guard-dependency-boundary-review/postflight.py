"""Read-only node and lease postflight. Never fetches any Secret."""
from pathlib import Path
import json,subprocess,shlex
O=Path(__file__).resolve().parent
ssh=['ssh','-o','BatchMode=yes','-o','ConnectTimeout=6','-o','StrictHostKeyChecking=yes','-o','HostName=192.168.64.11','-o','HostKeyAlias=192.168.1.58','zhang@192.168.1.58']
rows={}
for name,args in [('nodes',['get','nodes','-o','json']),('lease',['-n','data-infra','get','lease','platform-heavy','--ignore-not-found','-o','json'])]:
    p=subprocess.run(ssh+['sudo -n kubectl '+shlex.join(args)],capture_output=True,text=True,timeout=25)
    if p.returncode:raise SystemExit('Read-only postflight failed for '+name+': '+p.stderr[-300:])
    if name=='lease' and not p.stdout.strip():
        rows[name]={'name':'platform-heavy','absent':True,'validationHolderReleased':True,'evidence':'Successful get --ignore-not-found returned no object after original release command'}
        continue
    x=json.loads(p.stdout)
    if name=='nodes':rows[name]=[{'name':n['metadata']['name'],'conditions':[{k:c.get(k) for k in ['type','status','reason','lastTransitionTime']} for c in n['status']['conditions']]} for n in x['items']]
    else:rows[name]={'name':x['metadata']['name'],'resourceVersion':x['metadata']['resourceVersion'],'spec':x['spec'],'validationHolderReleased':not str(x['spec'].get('holderIdentity','')).startswith('runtime-facts-')}
(O/'node-lease-postflight.json').write_text(json.dumps(rows,indent=2)+'\n')
print(json.dumps({'nodes':[(n['name'],next(c['status'] for c in n['conditions'] if c['type']=='Ready')) for n in rows['nodes']],'validationLeaseReleased':rows['lease']['validationHolderReleased']}))
