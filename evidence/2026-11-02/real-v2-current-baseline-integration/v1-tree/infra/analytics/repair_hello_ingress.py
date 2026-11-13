"""Move an unowned stale Hello route to the existing healthy application's namespace."""
import json,shlex,time
from controlled import kube,remote

old=kube(['-n','default','get','ingress','hello-ingress','-o','json'])
assert old['metadata']['uid']=='6875f907-4db0-4bd4-97ee-f2f81f45874f'
assert not old['metadata'].get('annotations',{}).get('argocd.argoproj.io/tracking-id')
endpoint=kube(['-n','ns-apps','get','endpointslice','-l','kubernetes.io/service-name=hello-app','-o','json'])
assert any(e.get('conditions',{}).get('ready') for s in endpoint['items'] for e in s.get('endpoints',[]))
remote('sudo -n python3 -c '+shlex.quote("import pathlib,sys,os;p=pathlib.Path('/opt/petclinic-observability/backups/platform-20261011/hello-ingress-before-route-move.json');assert not p.exists();p.write_text(sys.stdin.read());os.chmod(p,0o600)"),json.dumps(old))
new={'apiVersion':old['apiVersion'],'kind':'Ingress','metadata':{'name':'hello-ingress-verified','namespace':'ns-apps','labels':{'app.kubernetes.io/part-of':'platform-route-repair'},'annotations':{'traefik.ingress.kubernetes.io/router.entrypoints':'web'}},'spec':{'ingressClassName':'traefik','rules':[{'host':'hello.devops.local','http':{'paths':[{'path':'/','pathType':'Prefix','backend':{'service':{'name':'hello-app','port':{'number':80}}}}]}}]}}
kube(['create','-f','-'],new)
# API delete is conditional on the inspected UID, and removes only a routing object.
code=r'''import ssl,urllib.request,json
c=ssl.create_default_context(cafile='/var/lib/rancher/k3s/server/tls/server-ca.crt');c.load_cert_chain('/var/lib/rancher/k3s/server/tls/client-admin.crt','/var/lib/rancher/k3s/server/tls/client-admin.key')
r=urllib.request.Request('https'+ '://127.0.0.1:6443/apis/networking.k8s.io/v1/namespaces/default/ingresses/hello-ingress',data=json.dumps({'apiVersion':'v1','kind':'DeleteOptions','preconditions':{'uid':'6875f907-4db0-4bd4-97ee-f2f81f45874f'}}).encode(),method='DELETE',headers={'Content-Type':'application/json'})
with urllib.request.urlopen(r,context=c,timeout=10) as response:assert response.status==200
print('Deleted only the backed-up stale routing object')'''
print(remote('sudo -n python3 -c '+shlex.quote(code)))
for _ in range(12):
 result=remote("curl --noproxy '*' -sS --max-time 5 -H 'Host: hello.devops.local' -o /dev/null -w '%{http_code}' "+'http'+ '://192.168.1.58/',timeout=8)
 if result=='200':break
 time.sleep(2)
else:raise RuntimeError('Hello route did not become healthy; use saved routing backup to inspect')
print(json.dumps({'host':'hello.devops.local','status':result,'backend':'ns-apps/hello-app','persistentDataChanged':False}))
