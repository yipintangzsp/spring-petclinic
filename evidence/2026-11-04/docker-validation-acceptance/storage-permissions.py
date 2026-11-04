import subprocess,json,os,pathlib,uuid
rows=[]
def run(c):
 try:r=subprocess.run(c,capture_output=True,text=True,timeout=20);d={'command':c,'exit':r.returncode,'stdout':r.stdout[:18000],'stderr':r.stderr[:2000]}
 except Exception as e:d={'command':c,'error':type(e).__name__}
 rows.append(d);return d
info=run(['docker','info','--format','{{json .}}']);d=json.loads(info['stdout']);paths=[d['DockerRootDir'],'/var/lib/containerd','/tmp']
for n in paths:
 try:
  v=os.statvfs(n);st=os.stat(n);rows.append({'hostPath':n,'device':st.st_dev,'capacity':v.f_blocks*v.f_frsize,'available':v.f_bavail*v.f_frsize,'inodesFree':v.f_favail})
 except OSError as e:rows.append({'hostPath':n,'error':str(e)})
run(['findmnt','-T',d['DockerRootDir'],'-o','TARGET,SOURCE,FSTYPE,OPTIONS,MAJ:MIN'])
run(['findmnt','-T','/var/lib/containerd','-o','TARGET,SOURCE,FSTYPE,OPTIONS,MAJ:MIN'])
r=run(['docker','create','--pull=never','--name','trivy-quota-probe-'+uuid.uuid4().hex[:10],'--label','purpose=trivy-docker-acceptance','--storage-opt','size=4m','--network=none','--read-only','--cap-drop=ALL','--security-opt=no-new-privileges','--user=65534:65534','--log-driver=none','python:3.14.8-slim-trixie','true'])
if r.get('exit')==0:run(['docker','rm',r['stdout'].strip()])
run(['sudo','-n','kubectl','get','deployment','jenkins','-n','ns-devops','-o','jsonpath={.spec.template.spec.volumes}{"\n"}{.spec.template.spec.containers[*].volumeMounts}{"\n"}'])
run(['sudo','-n','kubectl','exec','-n','ns-devops','deploy/jenkins','--','sh','-c','id; docker info --format "{{.ID}} {{.Name}} {{.DockerRootDir}} {{json .SecurityOptions}}"'])
print(json.dumps(rows,indent=2))
