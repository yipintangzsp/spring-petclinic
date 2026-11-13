"""Run on devops as root; verify existing Grafana panel against maintenance range.

Credentials are read only in memory, never printed or written to evidence.
"""
import base64
import json
import pathlib
import ssl
import time
import urllib.request

root=pathlib.Path('/opt/petclinic-observability/evidence/ha-20261006')
maintenance=json.loads((root/'maintenance.json').read_text())
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
panel=next(p for p in dashboard['dashboard']['panels'] if p['title']=='Pod Ready (1=ready)')
target=panel['targets'][0]
queries=[{'refId':'A','datasource':panel['datasource'],'expr':target['expr'],
    'range':True,'instant':False,'intervalMs':5000,'maxDataPoints':1000},
    {'refId':'B','datasource':panel['datasource'],
    'expr':'sum(kube_pod_status_ready{namespace="petclinic",condition="true"})',
    'range':True,'instant':False,'intervalMs':5000,'maxDataPoints':1000}]
result=query('/api/ds/query',{'from':str(int((maintenance['start']-30)*1000)),
    'to':str(int(time.time()*1000)),'queries':queries})
assert all(not r.get('error') and r.get('frames') for r in result['results'].values())
frame=result['results']['B']['frames'][0]
values=frame['data']['values'][1]
numeric=[v for v in values if isinstance(v,(int,float))]
assert min(numeric)==2 and max(numeric)>=3, 'Grafana did not observe maintenance ready-count change'
record={'uid':dashboard['dashboard']['uid'],'title':dashboard['dashboard']['title'],
    'provisioned':dashboard['meta'].get('provisioned'),'panel':panel['title'],
    'minimum_ready':min(numeric),'maximum_ready':max(numeric),'range_result':result}
(root/'grafana.json').write_text(json.dumps(record,indent=2))
print(json.dumps({k:v for k,v in record.items() if k!='range_result'}))
