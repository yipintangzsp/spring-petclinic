from pathlib import Path
import subprocess,shlex,json,sys,hashlib,datetime
O=Path(__file__).resolve().parent;phase=sys.argv[1];assert phase in ['before','after']
S=['ssh','-o','BatchMode=yes','-o','ConnectTimeout=6','-o','StrictHostKeyChecking=yes','-o','HostName=192.168.64.11','-o','HostKeyAlias=192.168.1.58','zhang@192.168.1.58']
def r(command,timeout=45):
 p=subprocess.run(S+[command],capture_output=True,text=True,timeout=timeout);assert p.returncode==0,p.stderr[-350:];return p.stdout
k=lambda args:json.loads(r('sudo -n kubectl '+shlex.join(args)))
p=k(['-n','harbor','get','pod','harbor-trivy-0','-o','json']);c=next(c for c in p['spec']['containers'] if c['name']=='trivy');sts=k(['-n','harbor','get','statefulset','harbor-trivy','-o','json']);vols=p['spec'].get('volumes',[])
pvcs=[]
for v in vols:
 if 'persistentVolumeClaim' not in v:continue
 pvc=k(['-n','harbor','get','pvc',v['persistentVolumeClaim']['claimName'],'-o','json']);pv=k(['get','pv',pvc['spec']['volumeName'],'-o','json']);pvcs.append({'name':pvc['metadata']['name'],'uid':pvc['metadata']['uid'],'capacity':pvc['status'].get('capacity'),'pv':pv['metadata']['name'],'hostPath':pv['spec'].get('hostPath'),'local':pv['spec'].get('local'),'csi':pv['spec'].get('csi'),'nodeAffinity':pv['spec'].get('nodeAffinity')})
# Explicit DB/cache and mount metadata only; no environment dump, auth file or Secret.
script="""set -eu
for d in /home/scanner/.cache/trivy /home/scanner/.cache/trivy/db /home/scanner/.cache/trivy/java-db /tmp; do
 if [ -d "$d" ]; then du -sk "$d"; fi
done
for d in /home/scanner/.cache/trivy /home/scanner/.cache/trivy/db /home/scanner/.cache/trivy/java-db; do
 if [ -d "$d" ]; then find "$d" -maxdepth 2 -type f -exec stat -c '%n|%s|%b|%B|%d|%i|%Y' {} \;; fi
done
for f in /home/scanner/.cache/trivy/db/metadata.json /home/scanner/.cache/trivy/java-db/metadata.json; do
 printf 'METADATA:%s\\n' "$f"; cat "$f"; printf '\\n'; sha256sum "$f"
done
printf 'MOUNTS\\n'; cat /proc/self/mountinfo
printf 'FS\\n'; df -Pk /home/scanner/.cache/trivy /tmp
printf 'TEMP_NAMES\\n'; find /tmp -maxdepth 1 \\( -name '*trivy*' -o -name '*javadb*' -o -name 'petclinic-db-*' \\) -exec stat -c '%n|%s|%b|%B|%d|%i|%Y' {} \;
printf 'PROCESSES\\n'; ps -o comm
"""
text=r('sudo -n kubectl exec -n harbor harbor-trivy-0 -c trivy -- sh -c '+shlex.quote(script));(O/('trivy-filesystem-'+phase+'.stdout')).write_text(text)
node=k(['get','--raw','/api/v1/nodes/devops/proxy/stats/summary'])['node'];safe={'sampledAt':datetime.datetime.now(datetime.timezone.utc).isoformat(),'classification':'READ_ONLY_FILE_SIZE_METADATA_AND_MOUNTS_NOT_REFRESH','pod':{'name':p['metadata']['name'],'uid':p['metadata']['uid'],'node':p['spec']['nodeName'],'containers':[{'name':x['name'],'image':x['image'],'volumeMounts':x.get('volumeMounts',[])} for x in p['spec']['containers']]},'volumes':vols,'statefulsetSpecSha256':hashlib.sha256(json.dumps(sts['spec'],sort_keys=True).encode()).hexdigest(),'environmentConfigurationSha256':hashlib.sha256(json.dumps(c.get('env',[]),sort_keys=True).encode()).hexdigest(),'environmentValuesArchived':False,'pvcs':pvcs,'nodeFs':node['fs'],'imageFs':node['runtime']['imageFs'],'proxyOrStorageChanges':0,'refreshes':0,'dbContentsRead':False,'dbMetadataRead':True}
(O/('trivy-storage-'+phase+'.json')).write_text(json.dumps(safe,indent=2)+'\n');print(json.dumps({'phase':phase,'node':p['spec']['nodeName'],'podUid':p['metadata']['uid'],'volumeMounts':c.get('volumeMounts',[]),'pvcs':pvcs,'nodeFsCapacity':node['fs']['capacityBytes'],'availableBytes':node['fs']['availableBytes'],'refreshes':0}))
