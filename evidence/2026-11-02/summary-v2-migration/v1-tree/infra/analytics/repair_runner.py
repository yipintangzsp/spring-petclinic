"""Use a digest-verified native helper and bound the existing Runner controller.

Before running, stage the official 19.2.0 ARM64 manifest and verified blobs at
/tmp/petclinic-runner-helper-manifest-20261012.json and
/tmp/petclinic-runner-helper-blobs-20261012. Credentials remain in the server backup.
"""
import base64,json,re,shlex
from controlled import HeavyRun,kube,remote

UPLOAD=r'''import json,urllib.request,urllib.parse,pathlib,hashlib
base='http'+ '://127.0.0.1:30050';repo='platform-upgrade/gitlab-runner-helper';root=pathlib.Path('/tmp/petclinic-runner-helper-blobs-20261012');raw=pathlib.Path('/tmp/petclinic-runner-helper-manifest-20261012.json').read_bytes();m=json.loads(raw)
expected='sha256:e5fbc428f53a3fec19fb685d81e81e86cd6c054458887f8f8235c95f8390d743'
assert 'sha256:'+hashlib.sha256(raw).hexdigest()==expected
config=json.loads((root/m['config']['digest'].replace(':','-')).read_bytes());assert config['architecture']=='arm64'
for x in [m['config'],*m['layers']]:
 data=(root/x['digest'].replace(':','-')).read_bytes();assert len(data)==x['size'] and 'sha256:'+hashlib.sha256(data).hexdigest()==x['digest']
 try:
  with urllib.request.urlopen(urllib.request.Request(base+'/v2/'+repo+'/blobs/'+x['digest'],method='HEAD'),timeout=10) as response:assert response.status==200
  continue
 except urllib.error.HTTPError as error:
  if error.code!=404:raise
 with urllib.request.urlopen(urllib.request.Request(base+'/v2/'+repo+'/blobs/uploads/',data=b'',method='POST'),timeout=10) as response:location=urllib.parse.urljoin(base,response.headers['Location'])
 url=location+('&' if '?' in location else '?')+urllib.parse.urlencode({'digest':x['digest']})
 with urllib.request.urlopen(urllib.request.Request(url,data=data,method='PUT',headers={'Content-Type':'application/octet-stream'}),timeout=30) as response:assert response.status==201
with urllib.request.urlopen(urllib.request.Request(base+'/v2/'+repo+'/manifests/arm64-v19.2.0',data=raw,method='PUT',headers={'Content-Type':m['mediaType']}),timeout=10) as response:assert response.status==201 and response.headers['Docker-Content-Digest']==expected
print(json.dumps({'helperVersion':'19.2.0','architecture':'arm64','image':'127.0.0.1:30050/'+repo+'@'+expected}))
'''

def run(evidence):
 with HeavyRun('runner-helper-repair',512,evidence) as guard:
  image=json.loads(remote('python3 -c '+shlex.quote(UPLOAD),timeout=150))
  pods=kube(['-n','ns-devops','get','pods','-o','json'])['items']
  assert not any(p['metadata']['name'].startswith('runner-') and p['status']['phase'] in ('Pending','Running') for p in pods),'Wait for current Runner jobs'
  secret=kube(['-n','ns-devops','get','secret','gitlab-runner-config-secure','-o','json'])
  remote("sudo -n python3 -c "+shlex.quote("import pathlib,sys,os;p=pathlib.Path('/opt/petclinic-observability/backups/platform-20261011/gitlab-runner-secret-before-helper19.json');assert not p.exists();p.write_text(sys.stdin.read());os.chmod(p,0o600)"),json.dumps(secret))
  text=base64.b64decode(secret['data']['config.toml']).decode()
  assert 'arm64-v16.11.0' in text
  text=re.sub(r'(?m)^concurrent = \d+', 'concurrent = 1',text)
  text=re.sub(r'(?m)(\s*request_concurrency = )\d+',r'\g<1>1',text)
  text=re.sub(r'(?m)(\s*helper_image = ).*',r'\1"'+image['image']+'"',text)
  text+='''
    helper_memory_request = "128Mi"
    helper_memory_limit = "128Mi"
    helper_cpu_request = "100m"
    helper_cpu_limit = "500m"
    memory_request_overwrite_max_allowed = "2Gi"
    memory_limit_overwrite_max_allowed = "2Gi"
    cpu_request_overwrite_max_allowed = "1"
    cpu_limit_overwrite_max_allowed = "1"
    [runners.kubernetes.node_selector]
      "kubernetes.io/hostname" = "devops"
'''
  patch={'data':{'config.toml':base64.b64encode(text.encode()).decode()}}
  kube(['-n','ns-devops','patch','secret','gitlab-runner-config-secure','--type=merge','-p',json.dumps(patch)])
  # Secret directory projection reloads automatically; controller restart also
  # applies the measured 60 MiB -> 128 MiB full-process budget.
  patch={'spec':{'strategy':{'type':'Recreate','rollingUpdate':None},'template':{'spec':{'containers':[{'name':'gitlab-runner','resources':{'requests':{'memory':'128Mi','cpu':'100m'},'limits':{'memory':'128Mi','cpu':'500m'}}}]}}}}
  kube(['-n','ns-devops','patch','deployment','gitlab-runner','--type=strategic','-p',json.dumps(patch)])
  kube(['-n','ns-devops','rollout','status','deploy/gitlab-runner','--timeout=90s'],timeout=100)
  guard.check();guard.evidence.mkdir(parents=True,exist_ok=True)
  (guard.evidence/'result.json').write_text(json.dumps(image,indent=2));print(json.dumps(image))

if __name__=='__main__':
 import sys
 run(sys.argv[1])
