from pathlib import Path
import subprocess,json,shlex,datetime
O=Path(__file__).resolve().parent
S=['ssh','-o','BatchMode=yes','-o','ConnectTimeout=6','-o','StrictHostKeyChecking=yes','-o','HostName=192.168.64.11','-o','HostKeyAlias=192.168.1.58','zhang@192.168.1.58']
def k(a):
 z=subprocess.run(S+['sudo -n kubectl '+shlex.join(a)],capture_output=True,text=True,timeout=30)
 if z.returncode:raise RuntimeError('READ_ONLY_KUBE_FAILED '+a[0])
 return json.loads(z.stdout)
web=[]
for kind in ['validatingwebhookconfigurations','mutatingwebhookconfigurations']:
 for x in k(['get',kind,'-o','json'])['items']:
  if 'kyverno' in x['metadata']['name']:
   web.append({'kind':kind,'name':x['metadata']['name'],'uid':x['metadata']['uid'],'webhooks':[{'name':w['name'],'namespaceSelector':w.get('namespaceSelector'),'objectSelector':w.get('objectSelector'),'failurePolicy':w.get('failurePolicy'),'rules':w.get('rules'),'clientService':w.get('clientConfig',{}).get('service')} for w in x['webhooks']]})
policy=k(['get','clusterpolicy','devsecops-signed-images','-o','json'])
ns=[{'name':n['metadata']['name'],'labels':n['metadata'].get('labels',{})} for n in k(['get','namespaces','-o','json'])['items'] if any(v in n['metadata']['name'] for v in ('devsecops','scanner','rf3','signature'))]
r={'time':datetime.datetime.now(datetime.timezone.utc).isoformat(),'webhooks':web,'productionSignaturePolicy':policy,'relevantNamespaces':ns,'privateKeyAccess':0,'writes':0}
(O/'cosign-admission-discovery.json').write_text(json.dumps(r,indent=2)+'\n')
print(json.dumps({'webhooks':web,'policyMatch':policy['spec']['rules'][0]['match'],'namespaces':ns},ensure_ascii=False))
