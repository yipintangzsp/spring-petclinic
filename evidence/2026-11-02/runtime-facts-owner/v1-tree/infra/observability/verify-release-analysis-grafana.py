"""Run on server as root; credentials stay in memory, evidence contains query results only."""
import base64,json,pathlib,ssl,time,urllib.request
ctx=ssl.create_default_context(cafile='/var/lib/rancher/k3s/server/tls/server-ca.crt')
ctx.load_cert_chain('/var/lib/rancher/k3s/server/tls/client-admin.crt',
    '/var/lib/rancher/k3s/server/tls/client-admin.key')
api=urllib.request.build_opener(urllib.request.ProxyHandler({}),urllib.request.HTTPSHandler(context=ctx))
def kube(path):
    with api.open('https://127.0.0.1:6443'+path,timeout=15) as response:return json.load(response)
secret=kube('/api/v1/namespaces/monitoring/secrets/kube-stack-grafana')['data']
authorization='Basic '+base64.b64encode(base64.b64decode(secret['admin-user'])+b':'+base64.b64decode(secret['admin-password'])).decode()
base='http://'+kube('/api/v1/namespaces/monitoring/services/kube-stack-grafana')['spec']['clusterIP']
http=urllib.request.build_opener(urllib.request.ProxyHandler({}))
def query(path, body=None):
    request=urllib.request.Request(base+path,data=None if body is None else json.dumps(body).encode(),
        headers={'Authorization':authorization,'Content-Type':'application/json'})
    with http.open(request,timeout=25) as response:return json.load(response)
dashboard=query('/api/dashboards/uid/petclinic-release-analysis')
panels=dashboard['dashboard']['panels']
queries=[{'refId':str(i),'datasource':p['datasource'],'expr':p['targets'][0]['expr'],'range':True,'instant':False,'intervalMs':15000,'maxDataPoints':60} for i,p in enumerate(panels)]
result=query('/api/ds/query',{'from':str(int((time.time()-900)*1000)),'to':str(int(time.time()*1000)),'queries':queries})
checks=[]
for i,p in enumerate(panels):
 r=result['results'][str(i)]
 values=[v for f in r.get('frames',[]) for field,v in zip(f.get('schema',{}).get('fields',[]),f.get('data',{}).get('values',[])) if field.get('type')=='number']
 real=any(any(x is not None for x in series) for series in values)
 checks.append({'panel':p['title'],'realSamples':real,'error':r.get('error')})
record={'uid':dashboard['dashboard']['uid'],'provisioned':dashboard['meta'].get('provisioned'),'panels':checks,'query_count':len(queries),'response':result}
pathlib.Path('/tmp/petclinic-release-analysis-grafana.json').write_text(json.dumps(record,indent=2));print(json.dumps({k:v for k,v in record.items() if k!='response'},ensure_ascii=False))
assert all(c['realSamples'] and not c['error'] for c in checks),checks
