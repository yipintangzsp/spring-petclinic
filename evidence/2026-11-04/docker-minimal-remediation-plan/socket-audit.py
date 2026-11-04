import os,pathlib,json,subprocess,re,stat,hashlib,grp,pwd
rows=[]
def run(c):
 try:r=subprocess.run(c,capture_output=True,text=True,timeout=18);d={'command':c,'exit':r.returncode,'stdout':r.stdout,'stderr':r.stderr[:1500]}
 except Exception as e:d={'command':c,'error':type(e).__name__}
 rows.append(d);return d
s=os.stat('/var/run/docker.sock');rows.append({'realPath':os.path.realpath('/var/run/docker.sock'),'uid':s.st_uid,'gid':s.st_gid,'mode':oct(stat.S_IMODE(s.st_mode)),'inode':s.st_ino,'ctime':s.st_ctime,'dockerGroup':grp.getgrgid(s.st_gid).gr_name,'groupExplicitMembers':grp.getgrgid(s.st_gid).gr_mem})
run(['systemctl','cat','docker.socket']);run(['systemctl','show','docker.socket','-p','FragmentPath','-p','DropInPaths','-p','ActiveState','-p','SocketMode','-p','SocketUser','-p','SocketGroup','-p','Listen']);run(['systemctl','show','docker.service','-p','FragmentPath','-p','DropInPaths','-p','ExecStart','-p','ExecStartPost','-p','ActiveState'])
# Inspect only known configuration locations for socket permission writers, not shell history.
r=run(['sudo','-n','rg','-n','--no-heading','docker\\.sock|SocketMode|chmod.*(666|0666)','/etc/systemd/system','/etc/tmpfiles.d','/usr/local/bin','/usr/local/sbin','/etc/rc.local','/etc/cron.d'])
if 'stdout'in r:
 lines=[]
 for line in r['stdout'].splitlines():
  if 'docker.sock'in line or 'SocketMode'in line or re.search('chmod.*0?666',line):
   parts=line.split(':',2);text=parts[-1];m=re.search(r'(?:chmod|SocketMode|SocketGroup|SocketUser)[^;\n]{0,140}',text)
   lines.append({'file':parts[0],'line':parts[1] if len(parts)>2 else None,'relevantCommand':m.group(0) if m else 'docker.sock reference (content omitted)'})
 r['matches']=lines;r.pop('stdout')
r=run(['sudo','-n','kubectl','get','pods','-A','-o','json'])
if r.get('exit')==0:
 pods=json.loads(r.pop('stdout'))['items'];out=[]
 for pod in pods:
  spec=pod['spec'];names={v['name'] for v in spec.get('volumes',[]) if 'docker.sock'in v.get('hostPath',{}).get('path','')}
  if not names:continue
  out.append({'namespace':pod['metadata']['namespace'],'name':pod['metadata']['name'],'node':spec.get('nodeName'),'sa':spec.get('serviceAccountName'),'volumes':[v for v in spec['volumes'] if v['name']in names],'containers':[{'name':c['name'],'securityContext':c.get('securityContext'),'mounts':[m for m in c.get('volumeMounts',[]) if m['name']in names],'socketCommands':[x[:700] for x in c.get('command',[])+c.get('args',[]) if 'docker.sock'in x]} for c in spec.get('containers',[])+spec.get('initContainers',[])]})
 r['socketConsumers']=out
r=run(['docker','ps','-aq']);ids=r.get('stdout','').split();r.pop('stdout',None);r['containerCount']=len(ids)
if ids:
 r=run(['docker','inspect',*ids]);data=json.loads(r.pop('stdout'));r['socketConsumers']=[{'name':d['Name'],'id':d['Id'],'running':d['State']['Running'],'user':d['Config']['User'],'mounts':[m for m in d['Mounts'] if 'docker.sock'in m.get('Source','') or 'docker.sock'in m.get('Destination','')]} for d in data if any('docker.sock'in m.get('Source','') or 'docker.sock'in m.get('Destination','') for m in d['Mounts'])]
r=run(['sudo','-n','ss','-ltnp']);r['dockerListeners']=[l for l in r.pop('stdout','').splitlines() if 'dockerd'in l or ':2375 'in l or ':2376 'in l]
r=run(['sudo','-n','ss','-xapn']);r['socketConnections']=[l[:900] for l in r.pop('stdout','').splitlines() if 'docker.sock'in l or 'dockerd'in l][:70]
r=run(['sudo','-n','lsof','-n','-a','-U','/var/run/docker.sock'])
print(json.dumps(rows,indent=2))
