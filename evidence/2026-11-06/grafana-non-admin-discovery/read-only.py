import runpy,json,shlex,sys,urllib.parse,pathlib,datetime
sys.dont_write_bytecode=True
api=runpy.run_path('evidence/2026-11-05/security-manager-v2-loki/inspect-production.py')
code=r'''
import subprocess,json,urllib.request,urllib.error,re,datetime,pathlib
k=lambda a:json.loads(subprocess.check_output(['kubectl']+a,text=True,timeout=25))
out={'at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'credentialValuesRead':0,'grafanaWrites':0}
deps=[]
for ns,name in [('monitoring','kube-stack-grafana'),('ns-devops','jenkins'),('ns-devops','github-webhook-relay')]:
 try:d=k(['-n',ns,'get','deployment',name,'-o','json'])
 except subprocess.CalledProcessError:continue
 containers=[]
 for c in d['spec']['template']['spec']['containers']:
  env=[]
  for e in c.get('env',[]):
   item={'name':e['name']}
   if 'valueFrom'in e:item['valueFrom']=e['valueFrom']
   elif re.search('GRAFANA|^GF_AUTH|^GF_SECURITY|^GF_PATHS',e['name']):item['literalValue']='NOT_EXPORTED'
   env.append(item)
  containers.append({'name':c['name'],'env':env,'envFrom':c.get('envFrom',[]),'volumeMounts':c.get('volumeMounts',[])})
 deps.append({'namespace':ns,'name':name,'containers':containers,'volumes':[{key:v[key]for key in ['name','secret','configMap']if key in v}for v in d['spec']['template']['spec'].get('volumes',[])]})
out['deploymentReferences']=deps
out['configReferences']=[]
for cm in k(['-n','monitoring','get','cm','-o','json'])['items']:
 if 'grafana'not in cm['metadata']['name']:continue
 for key,val in cm.get('data',{}).items():
  sections=re.findall(r'^\[([^\]]+)\]',val,re.M)
  authkeys=[]
  for line in val.splitlines():
   if re.search('token|credential|password|secret|service.?account|basic.?auth',line,re.I):
    m=re.match(r'\s*([\w.]+)\s*[:=]',line)
    if m:authkeys.append(m[1])
  out['configReferences'].append({'namespace':'monitoring','configMap':cm['metadata']['name'],'key':key,'iniSections':sections,'credentialFieldNamesOnly':authkeys})
out['hostCredentialPathMetadata']=[]
for p in ['/etc/grafana','/etc/default/grafana-server','/home/zhang/.config/grafana','/home/zhang/.grafana','/home/zhang/.config/security-manager']:
 q=pathlib.Path(p)
 if q.exists():out['hostCredentialPathMetadata'].append({'path':p,'type':'dir'if q.is_dir()else'file','mode':oct(q.stat().st_mode&511)})
http=urllib.request.build_opener(urllib.request.ProxyHandler({}));out['anonymousGrafana']={}
for path in ['/api/health','/api/user','/api/access-control/user/permissions']:
 try:
  with http.open('http://10.43.55.143'+path,timeout=8)as r:status=r.status
 except urllib.error.HTTPError as e:status=e.code
 out['anonymousGrafana'][path]=status
print(json.dumps(out))
'''
result={'monitoring':json.loads(api['remote']('sudo -n python3 -',code,90))}
sys.path.insert(0,'/Users/zhangsir/code/evidence/platform-20261011');from jenkins_control import NODE
groovy='''import groovy.json.JsonOutput
import com.cloudbees.plugins.credentials.SystemCredentialsProvider
def provider=SystemCredentialsProvider.getInstance()
def rows=[]
provider.getDomainCredentialsMap().each{domain,credentials->credentials.each{c->rows.add([id:c.id,type:c.getClass().name,scope:c.scope?.toString(),domain:domain.name?:'GLOBAL',valuesRead:false])}}
println(JsonOutput.toJson([credentials:rows,credentialValuesRead:0,mutations:0]))'''
payload={'path':'/scriptText','method':'POST','type':'application/x-www-form-urlencoded','body':urllib.parse.urlencode({'script':groovy}),'timeout':25000}
r=json.loads(api['remote']('sudo -n kubectl exec -i -n ns-devops deploy/github-webhook-relay -- node --max-old-space-size=24 -e '+shlex.quote(NODE),json.dumps(payload),50))
assert r['status']==200,'Jenkins metadata query HTTP '+str(r['status'])
result['jenkinsCredentialMetadata']=json.loads(r['body'].split('\n')[0])
with pathlib.Path('evidence/2026-11-06/grafana-non-admin-discovery/references.json').open('x')as f:json.dump(result,f,indent=2)
print(json.dumps(result))
