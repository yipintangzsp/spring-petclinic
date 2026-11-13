import urllib.request,ssl,json,pathlib,re
ctx=ssl.create_default_context(cafile='/var/lib/rancher/k3s/server/tls/server-ca.crt');ctx.load_cert_chain('/var/lib/rancher/k3s/server/tls/client-admin.crt','/var/lib/rancher/k3s/server/tls/client-admin.key')
base='https://127.0.0.1:6443'
def call(route,method='GET',body=None):
 h={'Content-Type':'application/merge-patch+json'} if body is not None else {}
 r=urllib.request.Request(base+route,method=method,headers=h,data=None if body is None else json.dumps(body).encode())
 with urllib.request.urlopen(r,context=ctx,timeout=25) as p:return json.load(p)
r='/apis/apps/v1/namespaces/data-infra/deployments/trino-worker';cr='/api/v1/namespaces/data-infra/configmaps/trino-worker'
d=call(r);c=call(cr);root=pathlib.Path('/opt/petclinic-observability/backup')
for name,obj in [('trino-worker-before-cloud-offload-20261003.json',d),('trino-worker-config-before-cloud-offload-20261003.json',c)]:
 p=root/name;p.write_text(json.dumps(obj));p.chmod(0o600)
s=c['data']['jvm.config'];s,n=re.subn(r'(?m)^-Xmx2G$', '-Xmx1536M',s);assert n==1
call(cr,'PATCH',{'data':{'jvm.config':s}})
containers=d['spec']['template']['spec']['containers']
assert len(containers)==1 and containers[0]['name']=='trino-worker'
containers[0]['image']='trinodb/trino:483@sha256:fca43d1fdfdcd45f36b791f7117a47f8ce69c58232e5398bfdb8539cd28e778b'
containers[0]['resources']['requests'].update(cpu='250m',memory='1Gi')
p={'spec':{'template':{'metadata':{'annotations':{'petclinic.devops.local/memory-relief':'2026-10-03'}},'spec':{'nodeSelector':{'kubernetes.io/hostname':'ucloud-worker'},'tolerations':[{'key':'cloud','operator':'Equal','value':'true','effect':'NoSchedule'}],'containers':containers}}}}
call(r,'PATCH',p)
print('Cloud worker rollout requested; old instance retained until new readiness passes',flush=True)
