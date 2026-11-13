"""Bounded local-query mode when cloud exchange latency fails dashboard acceptance."""
import argparse,json,shlex,time
from pathlib import Path
from controlled import HeavyRun,kube,remote


def run(evidence):
    evidence=Path(evidence);evidence.mkdir(parents=True,exist_ok=True)
    cm=kube(['-n','data-infra','get','cm','trino-coordinator','-o','json'])
    deployments=kube(['-n','data-infra','get','deploy','trino-coordinator','trino-worker','-o','json'])
    (evidence/'before-private.json').write_text(json.dumps({'config':cm,'deployments':deployments}));(evidence/'before-private.json').chmod(0o600)
    with HeavyRun('trino-local-query',2560,evidence) as guard:
        settings=cm['data']['config.properties'];assert 'node-scheduler.include-coordinator=false' in settings or 'node-scheduler.include-coordinator=true' in settings
        settings=settings.replace('node-scheduler.include-coordinator=false','node-scheduler.include-coordinator=true')
        kube(['-n','data-infra','patch','cm','trino-coordinator','--type=json','-p',json.dumps([{'op':'test','path':'/metadata/resourceVersion','value':cm['metadata']['resourceVersion']},{'op':'replace','path':'/data/config.properties','value':settings}])])
        kube(['-n','data-infra','scale','deploy','trino-worker','--replicas=0'])
        kube(['-n','data-infra','rollout','restart','deploy/trino-coordinator'])
        for _ in range(75):
            guard.check();d=kube(['-n','data-infra','get','deploy','trino-coordinator','-o','json']);s=d['status']
            if s.get('observedGeneration',0)>=d['metadata']['generation'] and s.get('updatedReplicas')==1 and s.get('availableReplicas')==1 and s.get('replicas')==1:break
            time.sleep(3)
        else:raise RuntimeError('Local Trino coordinator did not become ready; backups retained')
        remote('umask 077; cat > /tmp/petclinic-trino-queries.py',Path(__file__).with_name('trino_queries.py').read_text())
        ip=kube(['-n','data-infra','get','svc','trino','-o','json'])['spec']['clusterIP'];output='/opt/petclinic-observability/backups/platform-20261011/trino-local-queries.json'
        result=remote('sudo -n python3 /tmp/petclinic-trino-queries.py --base '+ 'http'+'://'+ip+':8080 --output '+output,timeout=210)
        (evidence/'queries.json').write_text(remote('sudo -n cat '+output));print(result,flush=True)

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--evidence',required=True);a=p.parse_args();run(a.evidence)
