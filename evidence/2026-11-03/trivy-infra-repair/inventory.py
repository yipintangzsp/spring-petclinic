from pathlib import Path
import json,subprocess,concurrent.futures,hashlib,datetime
O=Path(__file__).resolve().parent;R=O.parents[2];S=['ssh','-o','BatchMode=yes','-o','ConnectTimeout=6','-o','StrictHostKeyChecking=yes','-o','HostName=192.168.64.11','-o','HostKeyAlias=192.168.1.58','zhang@192.168.1.58']
commands={
'filesystem':'df -B1 -T /; df -i /; findmnt -J -T /; sudo -n docker info --format \'{{json .DockerRootDir}}\'; sudo -n docker system df -v',
'usage':'sudo -n timeout 50s ionice -c3 nice -n19 du -x -B1 --max-depth=1 /tmp /var/tmp /var/log /opt /var/lib/docker /var/lib/rancher/k3s/storage',
'images':'sudo -n k3s crictl images -o json',
'containers':'sudo -n k3s crictl ps -a -o json',
'workloads':'sudo -n kubectl get pods,deployments,statefulsets,daemonsets,replicasets,jobs,cronjobs -A -o json',
'nodes':'sudo -n kubectl get nodes -o json',
'pvc':'sudo -n kubectl get pv,pvc -A -o json',
'docker':'sudo -n docker ps -a --format \'{{json .}}\'',
'services':'systemctl list-units --type=service --state=running --no-pager --no-legend; sudo -n docker buildx ls',
'metadata':'sudo -n kubectl exec -n harbor harbor-trivy-0 -- sh -c \'cat /home/scanner/.cache/trivy/db/metadata.json; cat /home/scanner/.cache/trivy/java-db/metadata.json; ps -o comm\''}
def one(k,c):
 p=subprocess.run(S+[c],capture_output=True,text=True,timeout=65);meta={'command':c,'exitStatus':p.returncode,'stderr':p.stderr[-2000:],'collectedAt':datetime.datetime.now(datetime.timezone.utc).isoformat()}
 if k=='workloads':
  x=json.loads(p.stdout);rows=[]
  def walk(v,path=''):
   if isinstance(v,dict):
    for a,b in v.items():
     if a=='image' and isinstance(b,str):yield path+'/'+a,b
     else:yield from walk(b,path+'/'+a)
   elif isinstance(v,list):
    for i,b in enumerate(v):yield from walk(b,path+'/'+str(i))
  for v in x['items']:rows.append({'kind':v['kind'],'namespace':v['metadata'].get('namespace'),'name':v['metadata']['name'],'uid':v['metadata']['uid'],'images':[{'path':a,'image':b} for a,b in walk(v['spec'])],'imageIDs':[c.get('imageID') for c in v.get('status',{}).get('containerStatuses',[])],'deletionTimestamp':v['metadata'].get('deletionTimestamp')})
  payload=json.dumps(rows,indent=2)
 elif k=='nodes':
  x=json.loads(p.stdout);payload=json.dumps([{'name':v['metadata']['name'],'arch':v['status']['nodeInfo']['architecture'],'conditions':v['status']['conditions'],'capacity':v['status']['capacity'],'allocatable':v['status']['allocatable']} for v in x['items']],indent=2)
 else:payload=p.stdout
 (O/(k+'.stdout')).write_text(payload);(O/(k+'-execution.json')).write_text(json.dumps(meta,indent=2)+'\n');return {'name':k,'exit':p.returncode,'bytes':len(payload)}
with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
 for result in pool.map(lambda item:one(*item),commands.items()):print(json.dumps(result),flush=True)
