"""Exercise approved isolated canary/blue-green delivery, then return lab compute to zero."""
import argparse
import datetime as dt
import hashlib
import json
from pathlib import Path
import shlex
import subprocess
import sys
import time

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path.insert(0, str(ROOT / 'infra/analytics'))
sys.path.insert(0, str(ROOT / 'infra/devops-lab/iac'))
from controlled import HeavyRun, kube, remote, sample, jenkins
from run import gate

NS = 'rollouts-lab'
CLI = '/opt/petclinic-observability/tools/kubectl-argo-rollouts-v1.10.1'
CLI_SHA = 'c677dec8cdf124b2ff60f475587ebd4a728015e512a1a1090a8c21b119ebbdf1'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build', type=int, required=True)
    parser.add_argument('--revision', required=True)
    parser.add_argument('--evidence', type=Path, required=True)
    args = parser.parse_args()
    if len(args.revision) != 40 or any(c not in '0123456789abcdef' for c in args.revision):
        raise ValueError('Exact approved commit required')
    args.evidence.mkdir(parents=True, mode=0o700, exist_ok=False)
    def save(name, value):
        (args.evidence / (name + '.json')).write_text(json.dumps(value, indent=2))
    def source(path):
        name = 'infra/devops-lab/' + path
        content = subprocess.check_output(['git', 'show', args.revision + ':' + name], cwd=ROOT)
        if content != (ROOT / name).read_bytes():
            raise RuntimeError('Local source differs from approved revision: ' + name)
        return json.loads(content)
    # Verify all configuration and this runner, not only the caller's SHA.
    subprocess.run(['git', 'diff', '--exit-code', args.revision, '--',
                    'infra/devops-lab/rollouts', 'infra/devops-lab/rollouts-controller',
                    'infra/devops-lab/applications/platform-rollouts.json',
                    'infra/devops-lab/applications/rollouts-lab.json'], cwd=ROOT, check=True)
    save('jenkins-gate', gate(args.build, args.revision))
    if remote('sudo -n sha256sum ' + shlex.quote(CLI)).split()[0] != CLI_SHA:
        raise RuntimeError('Verified official CLI is required')
    # Offline upstream validation catches semantic rules omitted by CRD schema.
    for obj in source('rollouts/resources.json')['items']:
        if obj['kind'] == 'Rollout':
            command = ['sudo', '-n', CLI, 'lint', '-f', '/dev/stdin']
            save('lint-' + obj['metadata']['name'], remote(shlex.join(command), json.dumps(obj)))
    save('admission', [sample(), sample(), sample()])
    lab = source('rollouts/resources.json')
    desired = {x['metadata']['name']: x for x in lab['items'] if x['kind'] == 'Rollout'}
    app = source('applications/rollouts-lab.json')
    uids = {}
    usage = []
    paused = False
    with HeavyRun('rollouts-lab', 1024, args.evidence) as guard:
        def wait(name, reader, predicate, timeout=240):
            end = time.monotonic() + timeout
            while time.monotonic() < end:
                if name != 'compute-stopped':
                    guard.check()
                value = reader()
                try:
                    usage.append({'at':time.time(),'value':kube(['-n',NS,'top','pods','--containers'])})
                    save('pod-usage-samples',usage)
                except RuntimeError:
                    pass
                if predicate(value):
                    save(name, value)
                    print('PASS', name, flush=True)
                    return value
                time.sleep(4)
            save(name + '-timeout', value)
            raise RuntimeError(name + ' timeout')
        def get(name):
            return kube(['-n', NS, 'get', 'rollout', name, '-o', 'json'])
        def patch(name, value):
            x = get(name)
            if x['metadata']['uid'] != uids[name]:
                raise RuntimeError('Rollout ownership changed')
            return kube(['-n', NS, 'patch', 'rollout', name, '--type=merge', '-p', json.dumps(value), '-o', 'json'])
        def cli(*parts):
            guard.check()
            return remote(shlex.join(['sudo', '-n', CLI, '--kubeconfig', '/etc/rancher/k3s/k3s.yaml', '-n', NS, *parts]), timeout=30)
        def requests(service, count=20):
            ip = kube(['-n', NS, 'get', 'svc', service, '-o', 'json'])['spec']['clusterIP']
            code = '''import json,urllib.request,urllib.error,urllib.parse,sys,time
ip=sys.argv[1];n=int(sys.argv[2]);rows=[]
opener=urllib.request.build_opener(urllib.request.ProxyHandler({}))
for _ in range(n):
 try:
  r=opener.open(urllib.parse.urlunsplit(('http',ip+':8080','/','','')),timeout=3);rows.append({'code':r.status,'body':r.read().decode()})
 except urllib.error.HTTPError as e:rows.append({'code':e.code,'body':e.read().decode()})
 time.sleep(0.05)
print(json.dumps(rows))'''
            return json.loads(remote(shlex.join(['python3', '-c', code, ip, str(count)]), timeout=count * 4 + 10))
        def scenario(name, version, replicas):
            x=json.loads(json.dumps(desired[name]));x['spec']['replicas']=replicas
            x['spec']['template']['spec']['containers'][0]['env'][0]['value']=version
            patch(name, {'spec': {'replicas': replicas, 'template': x['spec']['template']}})
        def healthy(name, evidence):
            return wait(evidence, lambda:get(name), lambda x: x.get('status',{}).get('phase')=='Healthy' and x.get('status',{}).get('observedGeneration')==str(x['metadata']['generation']))
        def snapshot(name):
            save(name+'-rollout',get('delivery'))
            save(name+'-analysis',kube(['-n',NS,'get','analysisruns','-o','json']))
            save(name+'-replicasets',kube(['-n',NS,'get','rs','-o','json']))
            save(name+'-pods',kube(['-n',NS,'get','pods','-o','json']))
            save(name+'-usage',kube(['-n',NS,'top','pods','--containers']))
        try:
            # Bootstrap only after exact source passes the existing release pipeline.
            controller = source('applications/platform-rollouts.json')
            for owned_app in [controller,app]:
                old=kube(['-n','argocd','get','application',owned_app['metadata']['name'],'--ignore-not-found','-o','json'])
                if old and old['metadata'].get('labels',{}).get('petclinic.devops.local/owner')!='rollouts-lab':
                    raise RuntimeError('Foreign Application preserved')
            ns=kube(['get','ns',NS,'--ignore-not-found','-o','json'])
            if ns and ns['metadata'].get('labels',{}).get('petclinic.devops.local/owner')!='rollouts-lab':
                raise RuntimeError('Foreign namespace preserved')
            kube(['apply','-f','-'],controller)
            wait('controller-ready', lambda:kube(['-n',NS,'get','deploy','argo-rollouts','--ignore-not-found','-o','json']),
                 lambda x:bool(x) and x.get('status',{}).get('availableReplicas',0)==1, 300)
            kube(['apply','-f','-'],app)
            wait('lab-synced',lambda:kube(['-n','argocd','get','application','rollouts-lab','-o','json']),
                 lambda x:x.get('status',{}).get('sync',{}).get('status')=='Synced',300)
            kube(['-n','argocd','patch','application','rollouts-lab','--type=merge','-p',json.dumps({'spec':{'syncPolicy':{'automated':None}}})])
            paused=True
            for name in desired:
                x=get(name);uids[name]=x['metadata']['uid']
                if x['metadata']['labels'].get('petclinic.devops.local/owner')!='rollouts-lab':raise RuntimeError('Foreign rollout')
            save('owned-uids',uids)
            guard.compute_stopped=False
            scenario('delivery','v1',2)
            healthy('delivery','initial-v1')
            rows=requests('delivery-stable');save('initial-http',rows)
            assert all(x['code']==200 and json.loads(x['body'])['release']=='v1' for x in rows)
            scenario('delivery','v2',2)
            wait('v2-paused',lambda:get('delivery'),lambda x:bool(x.get('status',{}).get('pauseConditions')) and x['status'].get('updatedReplicas',0)>0)
            rows=requests('delivery',60);save('v2-canary-distribution',rows)
            assert {json.loads(x['body'])['release'] for x in rows}=={'v1','v2'}
            snapshot('v2-canary')
            cli('promote','delivery')
            healthy('delivery','v2-promoted')
            snapshot('v2-success')
            # Reapplying identical template must not create a new AnalysisRun or revision.
            before=get('delivery');runs=kube(['-n',NS,'get','analysisruns','-o','json'])
            scenario('delivery','v2',2);time.sleep(12)
            after=get('delivery');after_runs=kube(['-n',NS,'get','analysisruns','-o','json'])
            assert before['status']['currentPodHash']==after['status']['currentPodHash']
            assert {x['metadata']['uid'] for x in runs['items']}=={x['metadata']['uid'] for x in after_runs['items']}
            save('repeat-safe',{'before':before,'after':after,'analysisRunCount':len(after_runs['items'])})
            scenario('delivery','bad',2)
            wait('bad-paused',lambda:get('delivery'),lambda x:bool(x.get('status',{}).get('pauseConditions')) and x['status'].get('currentPodHash')!=x['status'].get('stableRS'))
            rows=requests('delivery-canary');save('bad-http',rows);assert all(x['code']==500 for x in rows)
            cli('promote','delivery')
            wait('automatic-abort',lambda:get('delivery'),lambda x:x.get('status',{}).get('abort') is True)
            snapshot('failed')
            wait('bad-scaled-down',lambda:kube(['-n',NS,'get','rs','-l','app=delivery','-o','json']),
                 lambda x:all(r.get('spec',{}).get('replicas',0)==0 for r in x['items'] if r['spec']['template']['spec']['containers'][0]['env'][0]['value']=='bad'))
            rows=requests('delivery',40);save('after-abort-http',rows)
            assert all(x['code']==200 and json.loads(x['body'])['release']=='v2' for x in rows)
            # Retry the same real defect: it must fail again rather than silently pass.
            cli('retry','rollout','delivery')
            wait('retry-paused',lambda:get('delivery'),lambda x:not x.get('status',{}).get('abort') and bool(x.get('status',{}).get('pauseConditions')))
            cli('promote','delivery')
            wait('retry-abort',lambda:get('delivery'),lambda x:x.get('status',{}).get('abort') is True)
            snapshot('retry-failed')
            failed=kube(['-n',NS,'get','analysisruns','-o','json'])['items']
            assert len([a for a in failed if a.get('status',{}).get('phase')=='Failed' and any(m.get('phase')=='Failed' for m in a['status'].get('metricResults',[]))])>=2
            scenario('delivery','v2',2);healthy('delivery','rollback-recovered')
            scenario('delivery','v2',0)
            wait('canary-stopped',lambda:kube(['-n',NS,'get','pods','-l','app=delivery','-o','json']),lambda x:not x['items'])
            scenario('blue','v1',1);healthy('blue','blue-v1')
            scenario('blue','v2',1)
            wait('blue-paused',lambda:get('blue'),lambda x:bool(x.get('status',{}).get('pauseConditions')))
            active=requests('blue-active');preview=requests('blue-preview');save('blue-before-switch',{'active':active,'preview':preview})
            assert all(json.loads(x['body'])['release']=='v1' for x in active)
            assert all(json.loads(x['body'])['release']=='v2' for x in preview)
            cli('promote','blue');healthy('blue','blue-v2-promoted')
            rows=requests('blue-active');save('blue-after-switch',rows)
            assert all(x['code']==200 and json.loads(x['body'])['release']=='v2' for x in rows)
            save('scenario-results',{'success':True,'completed':dt.datetime.now(dt.timezone.utc).isoformat(),'build':args.build,'source':args.revision})
        finally:
            if uids:
                save('final-events',kube(['-n',NS,'get','events','-o','json']))
                save('controller-log',kube(['-n',NS,'logs','deploy/argo-rollouts','--tail=250']))
                for name in uids:
                    # Stop replicas before restoring the source template; never start a cleanup rollout.
                    patch(name,{'spec':{'replicas':0}})
                wait('compute-stopped',lambda:kube(['-n',NS,'get','pods','-o','json']),
                     lambda x:all(p['metadata']['labels'].get('app') not in desired for p in x['items']))
                guard.compute_stopped=True
                for name in uids:
                    kube(['apply','-f','-'],desired[name])
                    remote(shlex.join(['sudo','-n',CLI,'--kubeconfig','/etc/rancher/k3s/k3s.yaml','-n',NS,'promote',name,'--full']))  # Only after zero serving pods.
            if paused:kube(['apply','-f','-'],app)
    save('jenkins-restored',jenkins('/api/json?tree=quietingDown,jobs[name,lastBuild[building]]'))
    save('acceptance',{'success':True,'cleanupConfirmed':True,'completed':dt.datetime.now(dt.timezone.utc).isoformat(),'build':args.build,'source':args.revision})


if __name__=='__main__':
    main()
