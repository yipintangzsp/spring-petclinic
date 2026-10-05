"""Validate current release on workers without sending production traffic or DB init.

Validation Pods have the existing observability label, but a deliberately unset
readiness gate excludes them from production Service routing. ContainersReady
and direct health are checked; disposable Service publishes only validation Pods.
"""
import copy
import importlib.util
import json
import shlex
import subprocess
import time
from pathlib import Path

spec = importlib.util.spec_from_file_location('audit', Path(__file__).with_name('audit-production.py'))
audit = importlib.util.module_from_spec(spec); spec.loader.exec_module(audit)
out = Path('evidence/2026-10-06/ha/workers.json')
owner = 'petclinic-ha-validation-20261006'
records = {'isolation':'unset readiness gate; no SQL initialization', 'workers':[], 'cleanup':False}
names = []
def cmd(parts, body=None, timeout=45):
    return subprocess.check_output(['ssh','-o','BatchMode=yes','192.168.1.58',
        shlex.join(['sudo','-n','k3s','kubectl']+parts)],
        input=None if body is None else json.dumps(body), text=True, timeout=timeout)
def get(parts): return json.loads(cmd(parts+['-o','json']))
def create(body): return cmd(['create','-f','-'],body)
def condition(p, name):
    return any(c['type']==name and c['status']=='True' for c in p['status'].get('conditions',[]))
def curl(pod, url):
    return cmd(['-n','petclinic','exec',pod,'--','curl','--noproxy','*','-fsS',
        '--connect-timeout','5','--max-time','15',url])
deployment = get(['-n','petclinic','get','deploy','petclinic'])
base = deployment['spec']['template']['spec']
assert not any(v.get('persistentVolumeClaim') for v in base.get('volumes',[]))
existing = get(['-n','petclinic','get','pods'])['items']
assert not any(p['metadata'].get('labels',{}).get('ha-validation')==owner for p in existing)
records['image'] = base['containers'][0]['image']
records['nodes'] = [{'name':n['metadata']['name'],'labels':n['metadata']['labels'],
    'taints':n['spec'].get('taints',[]),'allocatable':n['status']['allocatable'],
    'conditions':n['status']['conditions']} for n in get(['get','nodes'])['items']]
try:
    service={'apiVersion':'v1','kind':'Service','metadata':{'name':owner,'namespace':'petclinic',
        'labels':{'app.kubernetes.io/managed-by':owner}},'spec':{
        'selector':{'ha-validation':owner},'publishNotReadyAddresses':True,
        'ports':[{'name':'http','port':80,'targetPort':'http'}]}}
    create(service); records['service_created']=True
    for node in ['aliyun-worker','ucloud-worker']:
        name='petclinic-ha-check-'+node.split('-')[0]
        podspec=copy.deepcopy(base)
        podspec['nodeSelector']={'kubernetes.io/hostname':node}
        podspec.pop('topologySpreadConstraints',None); podspec.pop('affinity',None)
        podspec['readinessGates']=[{'conditionType':'ha.petclinic.devops.local/isolated'}]
        c=podspec['containers'][0]; c['imagePullPolicy']='Always'
        c['env'] += [{'name':'SPRING_SQL_INIT_MODE','value':'never'}]
        pod={'apiVersion':'v1','kind':'Pod','metadata':{'name':name,'namespace':'petclinic',
            'labels':{'app':'petclinic','ha-validation':owner,'app.kubernetes.io/managed-by':owner}},
            'spec':podspec}
        print('Creating isolated application validation on '+node,flush=True)
        create(pod); names.append(name)
        record={'node':node,'pod':name}; records['workers'].append(record)
        deadline=time.monotonic()+260
        while time.monotonic()<deadline:
            value=get(['-n','petclinic','get','pod',name])
            record['status']=value['status']
            if condition(value,'ContainersReady'): break
            statuses=value['status'].get('containerStatuses',[])
            if statuses and statuses[0].get('restartCount',0)>1: break
            time.sleep(5)
        record['events']=get(['-n','petclinic','get','events','--field-selector=involvedObject.name='+name])['items']
        assert condition(value,'ContainersReady'), 'Worker application failed: '+node
        assert not condition(value,'Ready'), 'Isolation gate lost'
        record['ip']=value['status']['podIP']
        record['image_id']=value['status']['containerStatuses'][0]['imageID']
        record['health']={path:json.loads(curl(name,'http://127.0.0.1:8080/actuator/health'+path))
            for path in ['', '/readiness','/liveness']}
        assert all(h['status']=='UP' for h in record['health'].values())
        record['dns']=cmd(['-n','petclinic','exec',name,'--','getent','hosts',
            'postgresql.ns-data.svc.cluster.local'])
        record['service_http']=bool(curl(name,'http://petclinic.petclinic.svc.cluster.local/owners'))
        record['validation_service_http']=bool(curl(name,'http://'+owner+'.petclinic.svc.cluster.local/owners'))
        record['kubernetes_service_http']=cmd(['-n','petclinic','exec',name,'--','curl','--noproxy','*',
            '-k','-sS','--max-time','10','-o','/dev/null','-w','%{http_code}',
            'https://kubernetes.default.svc.cluster.local/version'])
        assert record['kubernetes_service_http'] in ('200','401','403')
        production=next(p for p in existing if p['metadata'].get('labels',{}).get('app')=='petclinic')
        record['worker_to_devops_pod']=bool(curl(name,'http://'+production['status']['podIP']+':8080/owners'))
        record['devops_to_worker_pod']=audit.remote(shlex.join(['curl','--noproxy','*','-fsS',
            '--max-time','15','-o','/dev/null','-w','%{http_code}',
            'http://'+record['ip']+':8080/actuator/health/readiness']))
        assert record['devops_to_worker_pod']=='200'
        # Prometheus discovers not-ready endpoints; production routing excludes them.
        deadline=time.monotonic()+100
        while time.monotonic()<deadline:
            targets=audit.query('http://10.43.111.46:9090','/api/v1/targets')['data']['activeTargets']
            record['prometheus_targets']=[t for t in targets if t['labels'].get('pod')==name]
            record['loki']=audit.query('http://10.43.7.197:3100','/loki/api/v1/query_range',
                {'query':'{app="petclinic",namespace="petclinic",pod="'+name+'"}', 'since':'15m','limit':'2'})
            if record['prometheus_targets'] and all(t['health']=='up' for t in record['prometheus_targets']) and record['loki']['data']['result']: break
            time.sleep(5)
        assert record['prometheus_targets'] and all(t['health']=='up' for t in record['prometheus_targets']), 'Prometheus scrape failed'
        assert record['loki']['data']['result'], 'Alloy/Loki delivery failed'
        slices=get(['-n','petclinic','get','endpointslices','-l','kubernetes.io/service-name=petclinic'])['items']
        record['excluded_from_production']=all(not e['conditions'].get('ready',False)
            for s in slices for e in s['endpoints'] if e.get('targetRef',{}).get('name')==name)
        assert record['excluded_from_production']
        record['passed']=True
        print(node+': image, application, network, DNS, database, metrics and logs passed',flush=True)
        # One additional JVM at a time on the small workers.
        cmd(['-n','petclinic','delete','pod',name,'--wait=true','--timeout=60s'],timeout=75)
        names.remove(name)
    records['passed']=True
except Exception as error:
    records['error']=str(error)
    raise
finally:
    for name in names:
        p=get(['-n','petclinic','get','pod',name])
        assert p['metadata']['labels'].get('ha-validation')==owner
        cmd(['-n','petclinic','delete','pod',name,'--wait=true','--timeout=60s'],timeout=75)
    if records.get('service_created'):
        cmd(['-n','petclinic','delete','svc',owner])
    records['cleanup']=True
    out.parent.mkdir(parents=True,exist_ok=True);out.write_text(json.dumps(records,indent=2))
