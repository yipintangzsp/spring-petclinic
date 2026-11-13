"""Existing host-local management context. Never exports administrator material."""
import subprocess,json,base64,urllib.request,urllib.error
k=lambda args:json.loads(subprocess.check_output(['kubectl']+args,text=True,timeout=20))
s=k(['-n','monitoring','get','secret','kube-stack-grafana','-o','json'])['data']
admin_auth='Basic '+base64.b64encode(base64.b64decode(s['admin-user'])+b':'+base64.b64decode(s['admin-password'])).decode();del s
base='http://'+k(['-n','monitoring','get','svc','kube-stack-grafana','-o','json'])['spec']['clusterIP']
op=urllib.request.build_opener(urllib.request.ProxyHandler({}))
def request(path,method='GET',body=None,authorization=None):
 req=urllib.request.Request(base+path,data=None if body is None else json.dumps(body).encode(),method=method,headers={'Authorization':authorization or admin_auth,'Content-Type':'application/json'})
 try:
  with op.open(req,timeout=20)as r:
   raw=r.read();return r.status,json.loads(raw)if raw else {}
 except urllib.error.HTTPError as e:return e.code,{}
def must(path,method='GET',body=None,authorization=None,expected=(200,)):
 status,data=request(path,method,body,authorization)
 if status not in expected:raise RuntimeError('GRAFANA_HTTP_'+str(status)+' '+method+' '+path)
 return data
