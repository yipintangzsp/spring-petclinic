import pathlib,subprocess,json,os,stat,hashlib,urllib.request
rows=[]
def run(c):
 try:r=subprocess.run(c,capture_output=True,text=True,timeout=18);d={'command':c,'exit':r.returncode,'stdout':r.stdout,'stderr':r.stderr[:1200]}
 except Exception as e:d={'command':c,'error':type(e).__name__}
 rows.append(d);return d
s=os.stat('/run/docker.sock');rows.append({'socket':{'uid':s.st_uid,'gid':s.st_gid,'mode':oct(stat.S_IMODE(s.st_mode)),'ino':s.st_ino}})
run(['systemctl','show','docker.service','-p','MainPID','-p','ExecMainStartTimestampMonotonic','-p','NRestarts','-p','ActiveState','-p','ExecStartPost']);run(['systemctl','show','docker.socket','-p','SocketMode','-p','SocketUser','-p','SocketGroup','-p','ActiveState'])
run(['getfacl','-cp','/run/docker.sock'])
for n in ['/etc/systemd/system/docker.service.d/override.conf','/etc/systemd/system/docker.service.d/limits.conf']:
 r=run(['sudo','-n','cat',n]);r['sha256']=hashlib.sha256(r.get('stdout','').encode()).hexdigest()
run(['sudo','-n','kubectl','exec','-n','ns-devops','deploy/jenkins','--','sh','-c','id; docker info --format "{{.ID}}"'])
r=run(['sudo','-n','kubectl','get','deployment','jenkins','-n','ns-devops','-o','json']);d=json.loads(r.pop('stdout'));sp=d['spec'];r['selected']={'uid':d['metadata']['uid'],'resourceVersion':d['metadata']['resourceVersion'],'generation':d['metadata']['generation'],'managers':[m['manager'] for m in d['metadata'].get('managedFields',[])],'annotationKeys':list(d['metadata'].get('annotations',{})),'securityContext':sp['template']['spec'].get('securityContext'),'strategy':sp.get('strategy'),'replicas':sp['replicas'],'status':d['status'],'specSha256':hashlib.sha256(json.dumps(sp,sort_keys=True).encode()).hexdigest()}
r=run(['docker','ps','-aq']);ids=r.pop('stdout').split();r['ids']=ids
r=run(['docker','inspect',*ids]);ds=json.loads(r.pop('stdout'));r['containers']=[{'id':d['Id'],'name':d['Name'],'running':d['State']['Running'],'pid':d['State']['Pid'],'startedAt':d['State']['StartedAt'],'restartCount':d['RestartCount'],'health':d['State'].get('Health',{}).get('Status'),'socketMounts':[m for m in d['Mounts'] if 'docker.sock'in m.get('Source','')]} for d in ds]
run(['sudo','-n','systemctl','show','gitlab-runner','-p','ActiveState','-p','MainPID']);run(['sudo','-n','-u','gitlab-runner','id']);run(['sudo','-n','-u','gitlab-runner','docker','info','--format','{{.ID}}'])
r=run(['docker','inspect','portainer','--format','{{json .NetworkSettings.Ports}}']);r['ports']=json.loads(r.pop('stdout'))
for bindings in r['ports'].values():
 for bind in bindings or []:
  if bind['HostPort']=='9000':
   try:
    with urllib.request.urlopen('http://127.0.0.1:9000/api/status',timeout=5) as resp:rows.append({'portainerStatus':resp.status})
   except Exception as e:rows.append({'portainerError':type(e).__name__})
print(json.dumps(rows,indent=2))
