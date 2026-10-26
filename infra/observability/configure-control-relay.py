"""Apply the measured small control relay budget on the existing platform VM. No credentials are exported."""
import json,subprocess
EXPECTED_UID='b7e143f1-4c42-4436-bf4d-48b63d4d8dbf'
def run(*args):return subprocess.check_output(['kubectl',*args],text=True,timeout=150)
d=json.loads(run('-n','ns-devops','get','deployment','github-webhook-relay','-o','json'))
assert d['metadata']['uid']==EXPECTED_UID and d['spec']['replicas']==1,'Unexpected relay identity preserved'
cs=d['spec']['template']['spec']['containers'];assert len(cs)==1 and cs[0]['name']=='relay'
r=cs[0]['resources'];assert r['limits']['memory'] in ['96Mi','192Mi'] and r['requests']['memory'] in ['32Mi','64Mi']
if r['limits']['memory']!='192Mi' or r['requests']['memory']!='64Mi':
 patch=[{'op':'test','path':'/metadata/uid','value':EXPECTED_UID},{'op':'test','path':'/metadata/resourceVersion','value':d['metadata']['resourceVersion']},{'op':'replace','path':'/spec/template/spec/containers/0/resources/limits/memory','value':'192Mi'},{'op':'replace','path':'/spec/template/spec/containers/0/resources/requests/memory','value':'64Mi'}]
 run('-n','ns-devops','patch','deployment','github-webhook-relay','--type=json','-p',json.dumps(patch))
run('-n','ns-devops','rollout','status','deployment/github-webhook-relay','--timeout=120s')
print(json.dumps({'status':'success','uid':EXPECTED_UID,'requestMemory':'64Mi','limitMemory':'192Mi','cpuUnchanged':r['requests'].get('cpu'),'scope':'Only existing relay resource fields changed; image, auth, env and replica preserved'}))
