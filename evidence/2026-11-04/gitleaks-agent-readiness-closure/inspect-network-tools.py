"""Read-only supplemental evidence, never read a Secret or Node connection key."""
import runpy,json
from pathlib import Path
p=Path(__file__).resolve().parent
api=runpy.run_path(str(p/'inspect.py'))
code=r'''
import subprocess,json,urllib.request,hashlib,zipfile,io,os,pathlib
k=lambda a:json.loads(subprocess.check_output(['kubectl']+a,text=True,timeout=30))
p=next(p for p in k(['-n','ns-devops','get','pod','-l','app=jenkins','-o','json'])['items'] if p['status']['phase']=='Running')
js=r"const fs=require('fs'),cp=require('child_process');const paths=['/usr/share/doc/git/copyright','/usr/share/doc/nodejs/copyright','/usr/share/doc/tini/copyright','/usr/share/doc/util-linux/copyright','/usr/share/doc/ca-certificates/copyright','/opt/java/openjdk/legal/java.base/LICENSE'];const licenses=paths.map(p=>{const s=fs.readFileSync(p,'utf8');return {path:p,licenseMentions:[...new Set(s.split('\n').filter(l=>/^(License:|License-Reference:)|GNU General Public License|Classpath|MIT License/.test(l)))].slice(0,16)}});const q=cp.spawnSync('/usr/bin/dpkg-query',['-W','-f=${Package} ${Version} ${Architecture}\\n','nodejs','git','tini','util-linux','ca-certificates','libc6','libstdc++6','zlib1g','libssl3t64'],{encoding:'utf8'});console.log(JSON.stringify({licenses,packages:q.stdout,queryExit:q.status,architecture:process.arch,uid:process.getuid(),gid:process.getgid(),groups:process.getgroups()}));"
tools=json.loads(subprocess.check_output(['kubectl','-n','ns-devops','exec',p['metadata']['name'],'-c','jenkins','--','node','-e',js],text=True,timeout=30))
url='http://10.43.47.83:8080/'
with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(url+'jnlpJars/agent.jar',timeout=15) as r:jar=r.read()
z=zipfile.ZipFile(io.BytesIO(jar));mf=z.read('META-INF/MANIFEST.MF').decode();agent={'sha256':hashlib.sha256(jar).hexdigest(),'bytes':len(jar),'manifest':[l for l in mf.splitlines() if any(k in l for k in ['Version:','Jdk','Java','Url:','Title:'])],'licenseFiles':[n for n in z.namelist() if n.upper().endswith(('LICENSE','LICENSE.TXT','NOTICE','NOTICE.TXT'))][:20]}
try:
 with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(url+'wsagents/',timeout=10) as r:ws=r.status
except urllib.error.HTTPError as e:ws=e.code
# Only the existing Jenkins ingress and CNI implementation metadata; no full platform scan.
ing=k(['-n','ns-devops','get','ingress','-o','json'])['items'];ing=[{'name':i['metadata']['name'],'tls':i['spec'].get('tls',[]),'rules':i['spec'].get('rules',[])} for i in ing if any('jenkins' in str(r) for r in i['spec'].get('rules',[]))]
args=pathlib.Path('/proc/'+subprocess.check_output(['pidof','k3s-server'],text=True).strip().split()[0]+'/cmdline').read_bytes().replace(b'\0',b' ').decode() if subprocess.run(['pidof','k3s-server'],stdout=subprocess.DEVNULL).returncode==0 else ''
chains=subprocess.run(['iptables-save','-t','filter'],capture_output=True,text=True,timeout=20)
print(json.dumps({'classification':'REAL_READ_ONLY_NOT_AGENT_RUNTIME','tools':tools,'agentJar':agent,'webSocketUnauthenticatedProbe':{'status':ws,'actualHandshake':False},'jenkinsIngress':ing,'networkPolicyImplementation':{'KUBE_NWPLCY_chainCount':sum(l.startswith(':KUBE-NWPLCY') for l in chains.stdout.splitlines()),'disableNetworkPolicyFlagPresent':'--disable-network-policy' in args,'argumentInspectionComplete':bool(args)},'hostUid24001Accounts':[l.split(':')[0] for l in pathlib.Path('/etc/passwd').read_text().splitlines() if l.split(':')[2]=='24001'],'mutations':0}))
'''
x=json.loads(api['remote']('sudo -n python3 -',code,120));api['save']('network-tools.json',x);print(json.dumps({'jar':x['agentJar'],'websocket':x['webSocketUnauthenticatedProbe'],'cni':x['networkPolicyImplementation']}))
