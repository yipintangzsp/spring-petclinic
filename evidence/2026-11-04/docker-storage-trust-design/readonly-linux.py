import json,subprocess,pathlib,os,stat
rows=[]
def run(c):
 try:r=subprocess.run(c,capture_output=True,text=True,timeout=15);d={'command':c,'exit':r.returncode,'stdout':r.stdout[:16000],'stderr':r.stderr[:1500]}
 except Exception as e:d={'command':c,'error':type(e).__name__}
 rows.append(d);return d
r=run(['docker','info','--format','{{json .}}']);raw=json.loads(r.pop('stdout'));keys=['ID','Name','ServerVersion','DockerRootDir','Driver','DriverStatus','CgroupDriver','CgroupVersion','SecurityOptions','LiveRestoreEnabled','MemTotal','NCPU'];r['selectedFields']={k:raw.get(k) for k in keys}
for path in ['/var/lib/docker','/var/lib/containerd','/tmp','/var/run/docker.sock']:
 try:
  s=os.stat(path);v=os.statvfs(path);rows.append({'path':path,'uid':s.st_uid,'gid':s.st_gid,'mode':oct(stat.S_IMODE(s.st_mode)),'device':s.st_dev,'capacity':v.f_blocks*v.f_frsize,'available':v.f_bavail*v.f_frsize,'inodesFree':v.f_favail})
 except OSError as e:rows.append({'path':path,'error':str(e)})
run(['findmnt','-T','/var/lib/docker','-o','TARGET,SOURCE,FSTYPE,OPTIONS,MAJ:MIN']);run(['findmnt','-T','/var/lib/containerd','-o','TARGET,SOURCE,FSTYPE,OPTIONS,MAJ:MIN'])
r=run(['sudo','-n','tune2fs','-l','/dev/vda2'])
if r.get('exit')==0:r['selectedMetadata']='\n'.join(x for x in r.pop('stdout').splitlines() if x.startswith(('Filesystem features:','Default mount options:','Project quota inode:','User quota inode:','Group quota inode:','Filesystem state:','Block size:')))
r=run(['sudo','-n','cat','/etc/docker/daemon.json'])
if r.get('exit')==0:
 d=json.loads(r.pop('stdout'));r['selectedFields']={k:d.get(k) for k in ['data-root','storage-driver','storage-opts','live-restore','userns-remap','authorization-plugins','features']}
run(['free','-b']);run(['cat','/proc/swaps'])
r=run(['sudo','-n','kubectl','get','deployment','jenkins','-n','ns-devops','-o','json'])
if r.get('exit')==0:
 d=json.loads(r.pop('stdout'))['spec']['template']['spec'];r['selectedFields']={'serviceAccountName':d.get('serviceAccountName'),'securityContext':d.get('securityContext'),'volumes':d.get('volumes'),'containers':[{'name':c['name'],'securityContext':c.get('securityContext'),'volumeMounts':c.get('volumeMounts')} for c in d['containers']]}
r=run(['sudo','-n','kubectl','get','pvc','jenkins-pvc','-n','ns-devops','-o','json'])
if r.get('exit')==0:
 d=json.loads(r.pop('stdout'));r['selectedFields']={'volumeName':d['spec'].get('volumeName'),'storageClass':d['spec'].get('storageClassName')};pv=d['spec'].get('volumeName')
 r=run(['sudo','-n','kubectl','get','pv',pv,'-o','json'])
 if r.get('exit')==0:
  d=json.loads(r.pop('stdout'))['spec'];r['selectedFields']={k:d.get(k) for k in ['hostPath','local','csi','capacity','nodeAffinity']}
run(['sudo','-n','kubectl','exec','-n','ns-devops','deploy/jenkins','--','sh','-c','id; docker info --format "{{.ID}} {{.Name}} {{json .SecurityOptions}}"; stat -c "%u %g %a %n" /var/run/docker.sock'])
print(json.dumps(rows,indent=2))
