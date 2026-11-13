"""Run on devops as root. Scoped worker cordon/drain, never whole-node drain.

Preconditions: three ready application Pods on three nodes, no validation Pods,
one Petclinic Pod on aliyun, all other aliyun Pods are DaemonSets. Always uncordon.
No forced deletion, PDB bypass, local data removal or physical shutdown.
"""
import json
import pathlib
import ssl
import subprocess
import threading
import time
import urllib.error
import urllib.request

root=pathlib.Path('/opt/petclinic-observability/evidence/ha-20261006')
root.mkdir(parents=True,exist_ok=True)
output=root/'maintenance.json'
assert not output.exists(), 'Existing maintenance result; do not overwrite'
ctx=ssl.create_default_context(cafile='/var/lib/rancher/k3s/server/tls/server-ca.crt')
ctx.load_cert_chain('/var/lib/rancher/k3s/server/tls/client-admin.crt',
    '/var/lib/rancher/k3s/server/tls/client-admin.key')
api=urllib.request.build_opener(urllib.request.ProxyHandler({}),urllib.request.HTTPSHandler(context=ctx))
http=urllib.request.build_opener(urllib.request.ProxyHandler({}))
def call(path, method='GET',body=None):
    request=urllib.request.Request('https://127.0.0.1:6443'+path,method=method,
        data=None if body is None else json.dumps(body).encode(),headers={'Content-Type':'application/json'})
    with api.open(request,timeout=10) as response:return response.status,json.load(response)
def kube(parts):
    return subprocess.check_output(['k3s','kubectl']+parts,text=True,timeout=70)
def pods():return call('/api/v1/namespaces/petclinic/pods?labelSelector=app%3Dpetclinic')[1]['items']
def ready(p):return any(c['type']=='Ready' and c['status']=='True' for c in p['status'].get('conditions',[]))
def brief(p):return {'name':p['metadata']['name'],'node':p['spec'].get('nodeName'),
    'ready':ready(p),'terminating':bool(p['metadata'].get('deletionTimestamp')),'ip':p['status'].get('podIP')}
def eviction(p):
    body={'apiVersion':'policy/v1','kind':'Eviction','metadata':{'name':p['metadata']['name'],'namespace':'petclinic'},
        'deleteOptions':{'preconditions':{'uid':p['metadata']['uid']}}}
    try:
        status,value=call('/api/v1/namespaces/petclinic/pods/'+p['metadata']['name']+'/eviction?dryRun=All','POST',body)
    except urllib.error.HTTPError as error:
        status=error.code;value=json.load(error)
    return {'http_status':status,'response':value}
def query(base,path,params):
    import urllib.parse
    with http.open(base+path+'?'+urllib.parse.urlencode(params),timeout=15) as r:return json.load(r)
node='aliyun-worker'
initial=pods()
assert len(initial)==3 and all(ready(p) and not p['metadata'].get('deletionTimestamp') for p in initial)
assert len({p['spec']['nodeName'] for p in initial})==3
node_value=call('/api/v1/nodes/'+node)[1]
assert not node_value['spec'].get('unschedulable',False)
inventory=call('/api/v1/pods?fieldSelector=spec.nodeName%3D'+node)[1]['items']
for p in inventory:
    owners=p['metadata'].get('ownerReferences',[])
    if p['metadata']['namespace']=='petclinic' and p['metadata'].get('labels',{}).get('app')=='petclinic':
        assert any(o['kind']=='ReplicaSet' for o in owners)
        assert not any(v.get('persistentVolumeClaim') or v.get('emptyDir') for v in p['spec'].get('volumes',[]))
    else:assert any(o['kind']=='DaemonSet' for o in owners),'Non-Petclinic workload on maintenance node'
record={'node':node,'before':[brief(p) for p in initial],'inventory':[
    {'namespace':p['metadata']['namespace'],'name':p['metadata']['name'],
    'uid':p['metadata']['uid'],'owners':p['metadata'].get('ownerReferences',[])} for p in inventory],
    'http':[],'states':[],'restored_schedulable':False}
record['dry_run']=kube(['drain',node,'--ignore-daemonsets','--pod-selector=app=petclinic','--dry-run=server','--timeout=60s'])
assert not call('/api/v1/nodes/'+node)[1]['spec'].get('unschedulable',False)
old=next(p for p in initial if p['spec']['nodeName']==node)
record['initial_eviction_dry_run']=eviction(old)
assert record['initial_eviction_dry_run']['http_status']==201
stop=threading.Event()
def monitor():
    while not stop.is_set():
        for route in ['http://192.168.1.58/owners','http://10.43.39.130/owners']:
            started=time.time()
            try:
                request=urllib.request.Request(route,headers={'Host':'petclinic.devops.local'})
                with http.open(request,timeout=5) as r:status=r.status;r.read()
                record['http'].append({'time':started,'url':route,'status':status,'seconds':time.time()-started})
            except Exception as error:
                record['http'].append({'time':started,'url':route,'error':str(error)})
        stop.wait(.5)
thread=threading.Thread(target=monitor,daemon=True);thread.start()
drain=None
try:
    time.sleep(5)
    record['start']=time.time()
    print('Dry-run passed; cordoning aliyun-worker and draining only app=petclinic',flush=True)
    record['cordon']=kube(['cordon',node])
    drain=subprocess.Popen(['k3s','kubectl','drain',node,'--ignore-daemonsets',
        '--pod-selector=app=petclinic','--timeout=120s'],stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True)
    deadline=time.monotonic()+180
    while time.monotonic()<deadline:
        current=pods();pdb=call('/apis/policy/v1/namespaces/petclinic/poddisruptionbudgets/petclinic')[1]
        endpoints=call('/apis/discovery.k8s.io/v1/namespaces/petclinic/endpointslices?labelSelector=kubernetes.io%2Fservice-name%3Dpetclinic')[1]['items']
        state={'time':time.time(),'pods':[brief(p) for p in current],'pdb':pdb['status'],
            'ready_endpoints':[{'ip':e['addresses'],'node':e.get('nodeName'),'pod':e.get('targetRef',{}).get('name')}
                for s in endpoints for e in s['endpoints'] if e['conditions'].get('ready',False)]}
        record['states'].append(state)
        assert len(state['ready_endpoints'])>=2,'Service endpoint count below two'
        if pdb['status'].get('disruptionsAllowed')==0 and 'second_eviction_dry_run' not in record:
            candidate=next(p for p in current if p['metadata']['name']!=old['metadata']['name'] and ready(p) and not p['metadata'].get('deletionTimestamp'))
            record['second_eviction_dry_run']=eviction(candidate)
            assert record['second_eviction_dry_run']['http_status']==429,'PDB did not reject second eviction'
            print('PDB actual budget reached zero; second eviction dry-run rejected with HTTP 429',flush=True)
        active=[p for p in current if not p['metadata'].get('deletionTimestamp')]
        if len(active)==3 and all(ready(p) for p in active) and all(p['spec']['nodeName']!=node for p in active) and drain.poll()==0:
            record['after']=[brief(p) for p in active];break
        time.sleep(2)
    else:raise RuntimeError('Replacement failed to recover in maintenance window')
    record['drain_output']=drain.communicate(timeout=5)[0]
    assert drain.returncode==0
    assert record.get('second_eviction_dry_run',{}).get('http_status')==429
    record['old_pod']=old['metadata']['name']
    record['new_pod']=next(p['name'] for p in record['after'] if p['name'] not in {p['metadata']['name'] for p in initial})
    record['end']=time.time()
    # Allow real scrapes to record the replacement and the 2-ready transition.
    print('Replacement ready on remaining nodes; collecting real monitoring evidence',flush=True)
    time.sleep(35)
    for name,expr in {
        'ready':'sum(kube_pod_status_ready{namespace="petclinic",condition="true"})',
        'placement':'kube_pod_info{namespace="petclinic"}',
        'pdb':'kube_poddisruptionbudget_status_pod_disruptions_allowed{namespace="petclinic"}',
        'up':'up{namespace="petclinic",job="petclinic"}'}.items():
        record.setdefault('prometheus',{})[name]=query('http://10.43.111.46:9090','/api/v1/query_range',
            {'query':expr,'start':record['start']-30,'end':time.time(),'step':'5'})
    for name in [record['old_pod'],record['new_pod']]:
        record.setdefault('loki',{})[name]=query('http://10.43.7.197:3100','/loki/api/v1/query_range',
            {'query':'{app="petclinic",namespace="petclinic",pod="'+name+'"}',
                'since':'30m','limit':'3','direction':'backward'})
        assert record['loki'][name]['data']['result'], 'Missing migration log: '+name
    after_inventory=call('/api/v1/pods?fieldSelector=spec.nodeName%3D'+node)[1]['items']
    before_others={p['metadata']['uid'] for p in inventory if p['metadata']['namespace']!='petclinic'}
    assert before_others <= {p['metadata']['uid'] for p in after_inventory},'Other workload replaced'
    record['other_node_workloads_preserved']=True
finally:
    # Stop a timed-out drain before making the node schedulable again.
    if drain is not None and drain.poll() is None:drain.terminate();drain.wait(timeout=10)
    record['uncordon']=kube(['uncordon',node])
    record['restored_schedulable']=not call('/api/v1/nodes/'+node)[1]['spec'].get('unschedulable',False)
    time.sleep(5);stop.set();thread.join(timeout=12)
    record['http_summary']={'requests':len(record['http']),
        'non_200':sum(r.get('status')!=200 for r in record['http']),
        'max_seconds':max(r.get('seconds',0) for r in record['http'])}
    output.write_text(json.dumps(record,indent=2));output.chmod(0o600)
assert record['restored_schedulable'] and record['http_summary']['non_200']==0
print(json.dumps({'maintenance':'passed','http':record['http_summary'],
    'before':record['before'],'after':record['after'],'pdb_second_eviction':429,
    'uncordoned':record['restored_schedulable']}),flush=True)
