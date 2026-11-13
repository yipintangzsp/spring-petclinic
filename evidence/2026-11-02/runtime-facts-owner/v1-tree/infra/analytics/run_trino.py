"""Add one read-only catalog while preserving existing catalogs and engine version."""
import argparse,json,time
from pathlib import Path
from controlled import HeavyRun,kube,remote

CATALOG='''connector.name=postgresql
connection-url=jdbc:postgresql://postgresql.ns-data.svc.cluster.local:5432/petclinic
connection-user=${ENV:ANALYTICS_DB_USER}
connection-password=${ENV:ANALYTICS_DB_PASSWORD}
'''


def ready(name,guard):
    for i in range(75):
        guard.check();d=kube(['-n','data-infra','get','deploy',name,'-o','json'])
        s=d['status']
        if s.get('observedGeneration',0)>=d['metadata']['generation'] and s.get('updatedReplicas')==1 and s.get('availableReplicas')==1 and s.get('replicas')==1:return
        time.sleep(4)
    raise RuntimeError(name+' did not become ready within five minutes')


def run(evidence):
    evidence=Path(evidence);evidence.mkdir(parents=True,exist_ok=True)
    names=['trino-coordinator','trino-worker']
    previous={n:kube(['-n','data-infra','get','deploy',n,'-o','json']) for n in names}
    cm=kube(['-n','data-infra','get','cm','trino-catalog','-o','json'])
    # Backups are private: existing catalogs can contain legacy credentials.
    (evidence/'before-private.json').write_text(json.dumps({'deployments':previous,'catalog':cm}))
    (evidence/'before-private.json').chmod(0o600)
    with HeavyRun('trino-catalog',3072,evidence) as guard:
        patched=[]
        try:
            existing=cm.get('data',{}).get('clinic.properties')
            if existing not in [None,CATALOG]:raise RuntimeError('A different clinic catalog already exists')
            kube(['-n','data-infra','patch','cm','trino-catalog','--type=json','-p',json.dumps([
                {'op':'test','path':'/metadata/resourceVersion','value':cm['metadata']['resourceVersion']},
                {'op':'add','path':'/data/clinic.properties','value':CATALOG}])])
            for name in names:
                guard.check();d=previous[name];c=d['spec']['template']['spec']['containers'][0]
                envfrom=c.get('envFrom',[])
                if {'secretRef':{'name':'petclinic-reporting-db'}} not in envfrom:envfrom=envfrom+[{'secretRef':{'name':'petclinic-reporting-db'}}]
                patch={'spec':{'strategy':{'type':'RollingUpdate','rollingUpdate':{'maxSurge':0,'maxUnavailable':1}},'template':{'spec':{'containers':[{'name':c['name'],'envFrom':envfrom,'resources':{'requests':{'memory':'2Gi','cpu':'250m'},'limits':{'memory':'2Gi','cpu':'1000m'}}}]}}}}
                kube(['-n','data-infra','patch','deploy',name,'--type=strategic','-p',json.dumps(patch)]);patched.append(name);ready(name,guard)
                print(name+' ready with reporting-only catalog',flush=True)
            script=Path(__file__).with_name('trino_queries.py').read_text()
            remote("umask 077; cat > /tmp/petclinic-trino-queries.py",script)
            output='/opt/petclinic-observability/backups/platform-20261011/trino-queries.json'
            address=kube(['-n','data-infra','get','svc','trino','-o','json'])['spec']['clusterIP']
            result=remote('sudo -n python3 /tmp/petclinic-trino-queries.py --base '+ 'http'+'://'+address+':8080 --output '+output,timeout=210)
            stored=remote('sudo -n cat '+output);(evidence/'queries.json').write_text(stored)
            print(result,flush=True)
        except Exception as error:
            (evidence/'failure.txt').write_text(str(error))
            # Restore the previous catalog before removing its environment references.
            current=kube(['-n','data-infra','get','cm','trino-catalog','-o','json'])
            previous_catalog=cm.get('data',{}).get('clinic.properties')
            if previous_catalog is None:
                if 'clinic.properties' in current.get('data',{}):
                    kube(['-n','data-infra','patch','cm','trino-catalog','--type=json','-p',json.dumps([{'op':'remove','path':'/data/clinic.properties'}])])
            else:
                kube(['-n','data-infra','patch','cm','trino-catalog','--type=merge','-p',json.dumps({'data':{'clinic.properties':previous_catalog}})])
            for name in patched:
                old=previous[name];container=old['spec']['template']['spec']['containers'][0]
                kube(['-n','data-infra','patch','deploy',name,'--type=json','-p',json.dumps([
                    {'op':'replace','path':'/spec/template/spec/containers/0','value':container},
                    {'op':'replace','path':'/spec/strategy','value':old['spec']['strategy']}])]);ready(name,guard)
            raise

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--evidence',required=True);a=p.parse_args();run(a.evidence)
