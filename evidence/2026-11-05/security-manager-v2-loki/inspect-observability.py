"""Read-only existing monitoring inventory, safe configuration projections and GETs."""
from pathlib import Path
import runpy,json,sys
O=Path(__file__).resolve().parent;api=runpy.run_path(str(O/'inspect-production.py'))
code=r'''
import subprocess,json,hashlib,re,urllib.request,urllib.error,datetime
k=lambda a:json.loads(subprocess.check_output(['kubectl']+a,text=True,timeout=30))
sha=lambda b:hashlib.sha256(b).hexdigest()
pods=k(['-n','monitoring','get','pods','-o','json'])['items'];svcs=k(['-n','monitoring','get','svc','-o','json'])['items'];cms=k(['-n','monitoring','get','cm','-o','json'])['items']
relevant=[{'name':p['metadata']['name'],'uid':p['metadata']['uid'],'images':[c['image'] for c in p['spec']['containers']],'ready':[s.get('ready') for s in p['status'].get('containerStatuses',[])],'restarts':[s.get('restartCount') for s in p['status'].get('containerStatuses',[])]} for p in pods if any(x in p['metadata']['name'] for x in ['loki','alloy','grafana'])]
configs=[];datasources=[];dashboards=[];alloy=[]
for cm in cms:
 name=cm['metadata']['name']
 if not any(s in name for s in ['loki','alloy','grafana','devsecops']):continue
 entries={n:sha(v.encode()) for n,v in cm.get('data',{}).items()};configs.append({'name':name,'dataSha256':entries})
 for n,v in cm.get('data',{}).items():
  if 'datasource' in n.lower() or ('datasources:' in v and 'loki' in v):
   # Only project non-secret public connection fields; never export credentials.
   lines=[l.strip() for l in v.splitlines() if re.match(r'^\s*-?\s*(name|uid|type|url|access|isDefault|basicAuth):',l)]
   datasources.append({'configmap':name,'key':n,'connectionFields':lines})
  if 'loki' in name and any(w in v for w in ['limits_config','auth_enabled']):
   # Known operational limits only, never storage credentials/server tokens.
   fields={key:re.findall(r'^\s*'+key+r':\s*([^\n]+)',v,re.M) for key in ['auth_enabled','max_line_size','max_push_size','max_label_names_per_series','reject_old_samples','reject_old_samples_max_age','creation_grace_period','retention_period','max_streams_per_user']}
   configs[-1].setdefault('safeLimits',{})[n]=fields
  if 'alloy' in name:
   alloy.append({'configmap':name,'key':n,'sha256':sha(v.encode()),'lokiWriteEndpoints':re.findall(r'url\s*=\s*"(http[s]?://[^"\s]+/loki/api/v1/push)"',v),'labelKeysObserved':sorted(set(re.findall(r'(?:target_label|source_labels)\s*=\s*"([^"\n]+)"',v)))[:40],'securityPipelinePresent':'devsecops-security' in v})
  try:d=json.loads(v)
  except (ValueError,TypeError):continue
  if isinstance(d,dict) and ('devsecops' in str(d.get('title','')).lower() or d.get('uid')=='devsecops-control'):
   dashboards.append({'configmap':name,'key':n,'uid':d.get('uid'),'title':d.get('title'),'version':d.get('version'),'sha256':sha(v.encode()),'panels':[{'id':p.get('id'),'title':p.get('title'),'queries':[t.get('expr') for t in p.get('targets',[]) if t.get('expr')]} for p in d.get('panels',[])]})
loki=next(s for s in svcs if s['metadata']['name']=='loki');port=next(p['port'] for p in loki['spec']['ports'] if p['port']==3100);origin='http://'+loki['spec']['clusterIP']+':'+str(port)
opener=urllib.request.build_opener(urllib.request.ProxyHandler({}));gets=[]
for endpoint in ['/ready','/loki/api/v1/status/buildinfo','/loki/api/v1/labels']:
 try:
  r=opener.open(origin+endpoint,timeout=10);body=r.read(65536);status=r.status
 except urllib.error.HTTPError as e:status=e.code;body=e.read(4096)
 except Exception as e:gets.append({'path':endpoint,'status':'UNREACHABLE','errorClass':type(e).__name__});continue
 try:data=json.loads(body)
 except ValueError:data={'bodySha256':sha(body)}
 gets.append({'path':endpoint,'status':status,'body':data})
print(json.dumps({'classification':'REAL_READ_ONLY_MONITORING_NO_PUSH_NO_DASHBOARD_WRITE','at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'pods':relevant,'configurationHashes':configs,'grafanaProvisionedDatasource':datasources,'alloyProjection':alloy,'existingSecurityDashboards':dashboards,'lokiService':{'name':'loki','clusterIP':loki['spec']['clusterIP'],'port':port},'getProbes':gets,'credentialReads':0,'lokiPushRequests':0,'grafanaWrites':0}))
'''
x=json.loads(api['remote']('sudo -n python3 -',code,120));phase=sys.argv[1] if len(sys.argv)>1 else 'before';assert phase in ['before','final','recovery'];api['save']('observability-'+phase+'.json',x)
print(json.dumps({'pods':x['pods'],'datasources':x['grafanaProvisionedDatasource'],'LokiGETs':x['getProbes'],'existingSecurityDashboards':[{k:d[k] for k in ['uid','title','version']} for d in x['existingSecurityDashboards']],'alloy':x['alloyProjection'],'writes':0}))
