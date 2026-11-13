"""Observe a specific Argo revision and its live placement, without patching it."""
import argparse
import importlib.util
import json
import time
from pathlib import Path

spec=importlib.util.spec_from_file_location('audit',Path(__file__).with_name('audit-production.py'))
audit=importlib.util.module_from_spec(spec);spec.loader.exec_module(audit)
parser=argparse.ArgumentParser();parser.add_argument('revision');parser.add_argument('output',type=Path)
parser.add_argument('--single-node',action='store_true');args=parser.parse_args()
rows=[];deadline=time.monotonic()+600
try:
    while time.monotonic()<deadline:
        app=audit.kube('-n argocd get application petclinic')
        deployment=audit.kube('-n petclinic get deployment petclinic')
        pods=audit.kube('-n petclinic get pods -l app=petclinic')['items']
        row={'time':time.time(),'argo':{k:app['status'].get(k) for k in ['sync','health','conditions']},
            'available':deployment['status'].get('availableReplicas',0),
            'image':deployment['spec']['template']['spec']['containers'][0]['image'],
            'pods':[{'name':p['metadata']['name'],'node':p['spec'].get('nodeName'),
                'terminating':bool(p['metadata'].get('deletionTimestamp')),
                'ready':any(c['type']=='Ready' and c['status']=='True' for c in p['status'].get('conditions',[]))}
                for p in pods]}
        row['http']=audit.remote('curl --noproxy "*" -sS --max-time 10 -H "Host: petclinic.devops.local" -o /dev/null -w "%{http_code}" http://192.168.1.58/owners').strip()
        rows.append(row)
        assert row['http']=='200' and row['available']>=2,'Availability regression'
        active=[p for p in row['pods'] if not p['terminating']]
        expected_selector={'kubernetes.io/hostname':'devops'} if args.single_node else {'kubernetes.io/os':'linux'}
        placement_ok=(all(p['node']=='devops' for p in active) if args.single_node
            else len({p['node'] for p in active})==3)
        if app['status']['sync']['revision']==args.revision and app['status']['sync']['status']=='Synced' and app['status']['health']['status']=='Healthy' and len(active)==3 and all(p['ready'] for p in active) and placement_ok and deployment['status'].get('availableReplicas')==3 and deployment['status'].get('observedGeneration')==deployment['metadata']['generation'] and deployment['spec']['template']['spec'].get('nodeSelector')==expected_selector:
            print(json.dumps({'revision':args.revision,'samples':len(rows),'minimum_available':min(r['available'] for r in rows),'all_http_200':True,'placement':active}),flush=True)
            break
        time.sleep(5)
    else:raise RuntimeError('GitOps convergence/placement timeout')
finally:
    args.output.parent.mkdir(parents=True,exist_ok=True);args.output.write_text(json.dumps(rows,indent=2))
