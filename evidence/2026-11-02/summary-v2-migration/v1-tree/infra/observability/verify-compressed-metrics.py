"""Verify decoded business gauges and actual gzip transfer, then live scrape targets."""
import importlib.util,json,subprocess,time,sys
from pathlib import Path
s=importlib.util.spec_from_file_location('a',Path(__file__).with_name('audit-production.py'));a=importlib.util.module_from_spec(s);s.loader.exec_module(a)
deadline=time.monotonic()+180
while True:
 pods=a.kube('-n petclinic get pods -l app=petclinic')['items'];active=[p for p in pods if not p['metadata'].get('deletionTimestamp')]
 if len(active)==3 and all(any(c['type']=='Ready'and c['status']=='True'for c in p['status'].get('conditions',[]))for p in active):break
 if time.monotonic()>deadline:raise RuntimeError('Three Ready replicas not restored')
 time.sleep(5)
urls=[{'pod':p['metadata']['name'],'node':p['spec']['nodeName'],'url':'http://'+p['status']['podIP']+':8080/actuator/prometheus'}for p in active]
script="""import urllib.request,time,gzip,json,re
op=urllib.request.build_opener(urllib.request.ProxyHandler({}));result=[]
for item in URLS:
 t=time.monotonic()
 with op.open(urllib.request.Request(item['url'],headers={'Accept-Encoding':'gzip'}),timeout=10) as r:
  ttfb=time.monotonic()-t;raw=r.read();encoding=r.headers.get('Content-Encoding');status=r.status
 decoded=gzip.decompress(raw) if encoding=='gzip' else raw
 counts=dict(re.findall(r'petclinic_business_records\\{[^}]*entity="(owners|pets|vets|visits)"[^}]*\\} ([0-9.]+)',decoded.decode()))
 result.append({**item,'status':status,'encoding':encoding,'ttfb':ttfb,'seconds':time.monotonic()-t,'wire_bytes':len(raw),'decoded_bytes':len(decoded),'counts':counts})
print(json.dumps(result))
""".replace('URLS',repr(urls))
transfer=json.loads(subprocess.check_output(['ssh','-o','BatchMode=yes','192.168.1.58','python3 -'],input=script,text=True,timeout=60))
for r in transfer:
 assert r['status']==200 and r['encoding']=='gzip' and r['wire_bytes']<r['decoded_bytes']/2,r
 assert {k:int(float(v))for k,v in r['counts'].items()}=={'owners':200,'pets':350,'vets':20,'visits':1200},r
samples=[]
for i in range(4):
 targets=[t for t in a.query('http://10.43.111.46:9090','/api/v1/targets')['data']['activeTargets']if t['labels'].get('job')=='petclinic'];samples.append({'time':time.time(),'targets':[{'pod':t['labels'].get('pod'),'health':t['health'],'duration':t['lastScrapeDuration'],'error':t['lastError']}for t in targets]})
 if i!=3:time.sleep(15)
record={'transfer':transfer,'scrapes':samples};Path(sys.argv[1]).write_text(json.dumps(record,indent=2));assert all(len(s['targets'])==3 and all(t['health']=='up'for t in s['targets'])for s in samples[-2:]),record
print(json.dumps(record,indent=2))
