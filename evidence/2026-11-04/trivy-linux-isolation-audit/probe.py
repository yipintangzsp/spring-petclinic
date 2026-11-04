import os,pathlib,subprocess,json,platform,shutil

def run(args):
 try:
  r=subprocess.run(args,capture_output=True,text=True,timeout=12);return {'command':args,'exit':r.returncode,'stdout':r.stdout[:6000],'stderr':r.stderr[:1500]}
 except Exception as e:return {'command':args,'error':type(e).__name__}
def read(p):
 try:return pathlib.Path(p).read_text()[:18000]
 except Exception as e:return type(e).__name__
cg=read('/proc/self/cgroup');line=next((x[3:] for x in cg.splitlines() if x.startswith('0::')),None)
p=pathlib.Path('/sys/fs/cgroup')/(line or '').lstrip('/')
r={'kernel':platform.release(),'arch':platform.machine(),'uid':os.getuid(),'groups':os.getgroups(),'cgroup':cg,'controllers':read('/sys/fs/cgroup/cgroup.controllers'),'selfCgroup':str(p),'selfWritable':os.access(p,os.W_OK),'killWritable':os.access(p/'cgroup.kill',os.W_OK),'mountinfo':read('/proc/self/mountinfo'),'status': '\n'.join(x for x in read('/proc/self/status').splitlines() if x.startswith(('Cap','Seccomp','NoNewPrivs','Uid','Gid'))),'sysctls':{n:read('/proc/sys/'+n) for n in ['kernel/unprivileged_userns_clone','user/max_user_namespaces','kernel/apparmor_restrict_unprivileged_userns']},'tools':{n:shutil.which(n) for n in ['systemd-run','unshare','bwrap','docker','podman','nerdctl','ctr','runc']},'namespaces':{n:os.readlink('/proc/self/ns/'+n) for n in ['user','mnt','pid','net']},'sockets':{n:{'exists':pathlib.Path(n).exists(),'read':os.access(n,os.R_OK),'write':os.access(n,os.W_OK)} for n in ['/run/user/'+str(os.getuid())+'/bus','/var/run/docker.sock','/run/k3s/containerd/containerd.sock']}}
r['readOnlyChecks']=[run(x) for x in [['systemctl','--user','show','-p','Version'],['systemctl','show','-p','Version'],['docker','info','--format','{{json .SecurityOptions}}'],['podman','info','--format','json']]]
print(json.dumps(r,indent=2))
