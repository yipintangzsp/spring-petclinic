import subprocess,json,hashlib
rows=[]
for c in [['sudo','-n','cat','/etc/systemd/system/docker.service.d/override.conf'],['sudo','-n','cat','/etc/systemd/system/docker.service.d/limits.conf'],['getent','passwd','zhang','gitlab-runner'],['getent','group','docker'],['sudo','-n','systemctl','show','docker.socket','-p','Requires','-p','PartOf','-p','BindsTo'],['sudo','-n','kubectl','exec','-n','ns-devops','deploy/jenkins','--','id'],['docker','inspect','portainer','--format','{{.Config.User}} {{json .HostConfig.GroupAdd}} {{json .HostConfig.SecurityOpt}}']]:
 r=subprocess.run(c,capture_output=True,text=True,timeout=15);rows.append({'command':c,'exit':r.returncode,'stdout':r.stdout,'stderr':r.stderr[:1000],'stdoutSha256':hashlib.sha256(r.stdout.encode()).hexdigest()})
print(json.dumps(rows,indent=2))
