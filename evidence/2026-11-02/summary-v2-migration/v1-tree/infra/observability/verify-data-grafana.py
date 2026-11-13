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
dashboard=query('/api/dashboards/uid/petclinic-app-metrics')
panels=[next(p for p in dashboard['dashboard']['panels']if p['title']==title)for title in ['Pod Ready (1=ready)','Hikari connection pool']]
queries=[{'refId':str(i),'datasource':p['datasource'],'expr':t['expr'],'range':True,'instant':False,'intervalMs':15000,'maxDataPoints':1000}for i,(p,t)in enumerate([(p,t)for p in panels for t in p['targets']])]
result=query('/api/ds/query',{'from':str(int((time.time()-600)*1000)),'to':str(int(time.time()*1000)),'queries':queries})
assert all(not r.get('error')and r.get('frames')for r in result['results'].values())
record={'uid':dashboard['dashboard']['uid'],'provisioned':dashboard['meta'].get('provisioned'),'panels':[p['title']for p in panels],'query_count':len(queries),'response':result}
pathlib.Path('/tmp/petclinic-data-grafana.json').write_text(json.dumps(record,indent=2));print(json.dumps({k:v for k,v in record.items()if k!='response'}))
