import subprocess,json,hashlib,datetime,re,urllib.request,urllib.error
r={'classification':'READ_ONLY_COLLECTION_COVERAGE_AND_CURRENT_NETWORK','at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'productionMutations':0}
b=subprocess.check_output(['kubectl','--request-timeout=8s','get','--raw','/api/v1/namespaces/monitoring/configmaps/alloy'],text=True,timeout=12);d=json.loads(b);text=d.get('data',{}).get('config.alloy','');rules=[]
for block in re.findall(r'rule\s*\{([^{}]*)\}',text,re.S):
 if '__meta_kubernetes_namespace'in block:rules.append({'sourceLabels':re.findall(r'source_labels\s*=\s*\[([^\]]*)\]',block),'regex':re.findall(r'regex\s*=\s*"([^"\n]+)"',block),'action':re.findall(r'action\s*=\s*"([^"\n]+)"',block)})
r['alloy']={'configmapUid':d['metadata']['uid'],'configSha256':hashlib.sha256(text.encode()).hexdigest(),'namespaceRules':rules,'namespaceBlocks':re.findall(r'namespaces\s*\{([^{}]*)\}',text,re.S),'note':'Only namespace filter configuration projected; no credentials/config changes'}
r['network']={}
for name,cmd in [('links',['ip','-j','-s','link','show']),('routes',['ip','-j','route','show']),('tcpSummary',['ss','-s'])]:
 p=subprocess.run(cmd,capture_output=True,text=True,timeout=5);r['network'][name]={'exit':p.returncode,'stdout':p.stdout,'stderr':p.stderr[:500],'historicalInterpretation':'CURRENT_ONLY_NOT_INCIDENT_PACKET_TRACE'}
q=urllib.request.Request('http://192.168.64.11/',headers={'Host':'petclinic.devops.local'})
try:
 res=urllib.request.build_opener(urllib.request.ProxyHandler({})).open(q,timeout=6);body=res.read(262144);r['http']={'status':res.status,'headers':{k:res.headers.get(k)for k in ['Server','Via','Content-Type','Location','X-Request-ID']},'bodySha256':hashlib.sha256(body).hexdigest(),'bodyBytes':len(body),'observedAt':datetime.datetime.now(datetime.timezone.utc).isoformat()}
except Exception as e:r['http']={'errorClass':type(e).__name__,'status':getattr(e,'code',None)}
print(json.dumps(r))
