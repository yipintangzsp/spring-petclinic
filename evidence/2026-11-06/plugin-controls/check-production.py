import pathlib,runpy,json,sys
HERE=pathlib.Path(__file__).resolve().parent;REPO=HERE.parents[2]
api=runpy.run_path(str(REPO/'evidence/2026-11-05/security-manager-v2-loki/inspect-production.py'))
code=r'''
import subprocess,json,os,hashlib,pathlib,datetime
k=lambda *a:json.loads(subprocess.check_output(['kubectl',*a,'-o','json'],timeout=15))
d=k('get','deployment','petclinic','-n','petclinic');a=k('get','application','petclinic','-n','argocd');pods=k('get','pods','-n','petclinic','-l','app=petclinic')['items'];nodes=k('get','nodes')['items']
p=lambda x:hashlib.sha256(json.dumps(x,sort_keys=True).encode()).hexdigest()
h=subprocess.run(['curl','--noproxy','*','-sS','-o','/dev/null','-w','%{http_code}','--max-time','8','-H','Host: petclinic.devops.local','http://192.168.64.11/'],capture_output=True,text=True,timeout=10)
files={}
for name in ['/var/lib/security-gitleaks/.ssh/authorized_keys','/var/tmp/security-manager-gitleaks-v2-linux-20261105/ssh-entry.py','/var/tmp/security-manager-gitleaks-v2-linux-20261105/jenkins-ssh-entry.py','/var/lib/security-cosign/.ssh/authorized_keys','/var/lib/security-semgrep/.ssh/authorized_keys','/var/tmp/security-manager-gitleaks-semgrep-web-20261106/ssh-entry.py']:
 f=pathlib.Path(name)
 if f.is_file():files[name]=hashlib.sha256(f.read_bytes()).hexdigest()
print(json.dumps({'observedAt':datetime.datetime.now(datetime.timezone.utc).isoformat(),'deploymentSpecSha256':p(d['spec']),'generation':d['metadata']['generation'],'ready':d.get('status',{}).get('readyReplicas',0),'desired':d['spec']['replicas'],'image':d['spec']['template']['spec']['containers'][0]['image'],'argoSpecSha256':p(a['spec']),'argoSync':a['status']['sync']['status'],'argoHealth':a['status']['health']['status'],'argoRevision':a['status']['sync']['revision'],'nodes':{n['metadata']['name']:next(c['status'] for c in n['status']['conditions'] if c['type']=='Ready') for n in nodes},'http':h.stdout,'dockerMode':oct(os.stat('/run/docker.sock').st_mode&0o777),'gitleaksHashes':files,'pods':[{'name':p['metadata']['name'],'ready':[c['ready'] for c in p.get('status',{}).get('containerStatuses',[])],'restarts':[c['restartCount'] for c in p.get('status',{}).get('containerStatuses',[])]}for p in pods]}))
'''
x=json.loads(api['remote']('sudo -n python3 -',code,timeout=80))
with (HERE/('production-'+sys.argv[1]+'.json')).open('x') as f:json.dump(x,f,indent=2)
print(json.dumps(x))
