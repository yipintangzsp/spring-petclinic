"""Strict-host-key, read-only production checks; no Secret or environment reads."""
from pathlib import Path
import subprocess,json,shlex,sys
O=Path(__file__).resolve().parent
phase=sys.argv[1];assert phase in ['before','after']
S=['ssh','-o','BatchMode=yes','-o','ConnectTimeout=6','-o','StrictHostKeyChecking=yes','-o','HostName=192.168.64.11','-o','HostKeyAlias=192.168.1.58','zhang@192.168.1.58']
script=r'''
import subprocess,json,os,hashlib,datetime,urllib.request
run=lambda a:subprocess.check_output(a,text=True,timeout=30)
s=os.stat('/run/docker.sock');sock={'mode':format(s.st_mode&0o777,'04o'),'uid':s.st_uid,'gid':s.st_gid,'inode':s.st_ino}
service=run(['systemctl','show','docker.service','-p','MainPID','-p','NRestarts','-p','ExecMainStartTimestampMonotonic','-p','ActiveState'])
ids=run(['docker','ps','-aq']).split();fmt='{"id":{{json .Id}},"name":{{json .Name}},"state":{{json .State}},"restartCount":{{json .RestartCount}}}'
containers=[json.loads(x) for x in run(['docker','inspect','--format',fmt,*ids]).splitlines()]
nodes=json.loads(run(['kubectl','get','nodes','-o','json']))
ns=[{'name':n['metadata']['name'],'ready':next(c['status'] for c in n['status']['conditions'] if c['type']=='Ready')} for n in nodes['items']]
pods=json.loads(run(['kubectl','get','pods','-A','-o','json']))
dojo=[{'name':p['metadata']['name'],'namespace':p['metadata']['namespace'],'uid':p['metadata']['uid'],'node':p['spec'].get('nodeName'),'phase':p['status']['phase'],'containers':[{k:c.get(k) for k in ['name','ready','restartCount','image','imageID']} for c in p['status'].get('containerStatuses',[])]} for p in pods['items'] if 'dojo' in p['metadata']['name'].lower()]
with urllib.request.urlopen('http://127.0.0.1:9000/api/status',timeout=5) as r:portainer=r.status
x={'checkedAt':datetime.datetime.now(datetime.timezone.utc).isoformat(),'socket':sock,'dockerService':service,'containers':containers,'nodes':ns,'defectdojoPods':dojo,'portainerHTTP':portainer,'productionMutation':0}
print(json.dumps(x));assert sock['mode']=='0660' and 'ActiveState=active' in service and all(n['ready']=='True' for n in ns) and portainer==200
'''
p=subprocess.run(S+['sudo -n python3 -'],input=script,capture_output=True,text=True,timeout=120)
if p.returncode:raise SystemExit('Host pre/postflight failed: '+p.stderr[-500:])
x=json.loads(p.stdout);target=O/('host-'+phase+'.json')
with target.open('x') as f:json.dump(x,f,indent=2);f.write('\n')
print(json.dumps({'phase':phase,'socket':x['socket'],'nodes':x['nodes'],'containerCount':len(x['containers']),'dojoPods':len(x['defectdojoPods']),'portainerHTTP':x['portainerHTTP']}))
