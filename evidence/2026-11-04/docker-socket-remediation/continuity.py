import subprocess,json,os,socket,urllib.request,time
rows=[]
for i in range(3):
 s=os.stat('/run/docker.sock');service=subprocess.check_output(['systemctl','show','docker.service','-p','MainPID','-p','NRestarts','-p','ExecMainStartTimestampMonotonic'],text=True);rows.append({'sample':i,'time':time.time(),'mode':oct(s.st_mode&0o777),'inode':s.st_ino,'service':service});assert (s.st_mode&0o777)==0o660 and s.st_ino==1405
 if i<2:time.sleep(5)
ids=subprocess.check_output(['docker','ps','-aq'],text=True).split();data=json.loads(subprocess.check_output(['docker','inspect',*ids],text=True));containers=[{'id':d['Id'],'name':d['Name'],'running':d['State']['Running'],'pid':d['State']['Pid'],'startedAt':d['State']['StartedAt'],'restartCount':d['RestartCount']} for d in data]
port=next(d for d in data if d['Name']=='/portainer');pid=port['State']['Pid'];status=open('/proc/'+str(pid)+'/status').read();identity='\n'.join(x for x in status.splitlines() if x.startswith(('Uid:','Gid:','Groups:')))
path='/proc/'+str(pid)+'/root/var/run/docker.sock';st=os.stat(path);assert st.st_ino==1405
s=socket.socket(socket.AF_UNIX);s.settimeout(3);s.connect(path);s.sendall(b'GET /_ping HTTP/1.0\r\nHost: localhost\r\n\r\n');resp=s.recv(2048).decode();s.close();assert '200 OK'in resp
with urllib.request.urlopen('http://127.0.0.1:9000/api/status',timeout=5) as r:ui=r.status;assert ui==200
print(json.dumps({'samples':rows,'containers':containers,'portainer':{'pid':pid,'identity':identity,'socketMountInode':st.st_ino,'socketReadOnlyPingViaExistingMount':'200 OK','apiStatus':ui,'scope':'host root performs GET on existing Portainer socket mount; authenticated Portainer endpoint workflow NOT_TESTED; no credentials read'}},indent=2))
