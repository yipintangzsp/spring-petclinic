"""Extend the existing Superset image with two pinned drivers and private charts."""
import argparse,copy,datetime,json,re,shlex,time
from pathlib import Path
from controlled import HeavyRun,kube,remote


def ready(name,guard):
    for _ in range(90):
        guard.check();d=kube(['-n','data-infra','get','deploy',name,'-o','json']);s=d['status']
        if s.get('observedGeneration',0)>=d['metadata']['generation'] and s.get('updatedReplicas')==1 and s.get('availableReplicas')==1 and s.get('replicas')==1:return
        time.sleep(4)
    raise RuntimeError('Superset web rollout did not finish')


def run(evidence):
    root=Path(__file__).parent;evidence=Path(evidence);evidence.mkdir(parents=True,exist_ok=True)
    before=kube(['-n','data-infra','get','deploy','superset','-o','json']);worker=kube(['-n','data-infra','get','deploy','superset-worker','-o','json'])
    assert worker['spec']['replicas']==0,'Preserve any active Celery work'
    pod='petclinic-superset-control-'+datetime.datetime.now().strftime('%H%M%S')
    (evidence/'web-before-private.json').write_text(json.dumps(before));(evidence/'web-before-private.json').chmod(0o600)
    with HeavyRun('superset-dashboard',3072,evidence) as guard:
        guard.compute_stopped=False;patched=False
        try:
            # Only the existing Superset metadata database is backed up here.
            backup='/opt/petclinic-observability/backups/platform-20261011/superset-before-dashboard-'+datetime.datetime.now().strftime('%H%M%S')+'.sql'
            command=shlex.join(['sudo','-n','kubectl','-n','ns-data','exec','deploy/mysql','--','sh','-c','MYSQL_PWD="$MYSQL_ROOT_PASSWORD" mysqldump -uroot --single-transaction --routines --events --databases superset'])
            remote(shlex.join(['bash','-o','pipefail','-c','umask 077; '+command+' | sudo -n tee '+backup+' >/dev/null']),timeout=60)
            remote('sudo -n test -s '+backup+' && sudo -n chmod 600 '+backup)
            proof=remote('sudo -n sha256sum '+backup+'; sudo -n wc -c '+backup)
            (evidence/'metadata-backup-proof.txt').write_text(proof);print('Superset metadata backup saved',flush=True)
            remote('mkdir -p /tmp/petclinic-superset-build; cat > /tmp/petclinic-superset-build/Dockerfile',(root/'superset/Dockerfile').read_text())
            base='192.168.1.58:30050/library/superset@sha256:f9360eb1ee9b9f99f2d05d5c0dfdb7fd18c4c878719b7d2d267a725060a396da'
            tag='127.0.0.1:30050/platform-upgrade/superset-analytics:6.1.0-20261011'
            log=remote('sudo -n env DOCKER_BUILDKIT=0 docker build --memory=512m --cpu-period=100000 --cpu-quota=100000 --build-arg BASE_IMAGE='+shlex.quote(base)+' -t '+tag+' /tmp/petclinic-superset-build',timeout=420)
            (evidence/'driver-build.log').write_text(log);guard.check()
            result=remote('sudo -n docker run --rm --memory=256m --cpus=0.5 --entrypoint /app/.venv/bin/python '+tag+' -c '+shlex.quote("import json,platform,psycopg2,trino,mysql.connector;print(json.dumps({'architecture':platform.machine(),'psycopg2':psycopg2.__version__,'trino':trino.__version__,'mysqlconnector':mysql.connector.__version__}))"),timeout=60)
            (evidence/'driver-versions.json').write_text(result);print('Native drivers verified',result.strip(),flush=True)
            log=remote('sudo -n docker push '+tag,timeout=180);(evidence/'driver-push.log').write_text(log)
            digest=re.findall(r'digest: (sha256:[a-f0-9]{64})',log)[-1];image=tag.split(':6.1.0-')[0]+'@'+digest
            (evidence/'image.json').write_text(json.dumps({'base':base,'image':image,'drivers':json.loads(result)},indent=2))
            c=before['spec']['template']['spec']['containers'][0]
            kube(['-n','data-infra','patch','deploy','superset','--type=strategic','-p',json.dumps({'spec':{'strategy':{'type':'RollingUpdate','rollingUpdate':{'maxSurge':0,'maxUnavailable':1}},'template':{'spec':{'containers':[{'name':c['name'],'image':image,'resources':{'requests':{'memory':'768Mi','cpu':'100m'},'limits':{'memory':'768Mi','cpu':'1000m'}}}]}}}})]);patched=True;ready('superset',guard);print('Superset web ready with preserved configuration',flush=True)
            cm=pod+'-code';kube(['create','-f','-'],{'apiVersion':'v1','kind':'ConfigMap','metadata':{'name':cm,'namespace':'data-infra','labels':{'app':'petclinic-analysis'}},'data':{'create_dashboard.py':(root/'superset/create_dashboard.py').read_text()}})
            spec=copy.deepcopy(before['spec']['template']['spec']);spec.pop('initContainers',None);spec['containers']=spec['containers'][:1];c=spec['containers'][0]
            c['name']='control';c['image']=image;c['command']=['bash','-c'];c['args']=['sleep 1800'];c['resources']={'requests':{'memory':'768Mi','cpu':'100m'},'limits':{'memory':'768Mi','cpu':'1000m'}}
            for k in ['livenessProbe','readinessProbe','startupProbe']:c.pop(k,None)
            c.setdefault('env',[]).append({'name':'CLINIC_TRINO_URI','value':'trino://reporter@trino.data-infra.svc.cluster.local:8080/clinic/petclinic_analytics'})
            spec.setdefault('volumes',[]).append({'name':'chart-code','configMap':{'name':cm}});c.setdefault('volumeMounts',[]).append({'name':'chart-code','mountPath':'/opt/clinic','readOnly':True})
            spec['automountServiceAccountToken']=False;spec['restartPolicy']='Never';spec['activeDeadlineSeconds']=1800
            kube(['create','-f','-'],{'apiVersion':'v1','kind':'Pod','metadata':{'name':pod,'namespace':'data-infra','labels':{'app':'petclinic-analysis','purpose':'superset-control'}},'spec':spec})
            for _ in range(40):
                guard.check();p=kube(['-n','data-infra','get','pod',pod,'-o','json'])
                if any(c.get('ready') for c in p['status'].get('containerStatuses',[])):break
                time.sleep(3)
            else:raise RuntimeError('Superset control pod did not start')
            logs=str(kube(['-n','data-infra','exec',pod,'--','/app/.venv/bin/python','/opt/clinic/create_dashboard.py'],timeout=180));(evidence/'create-dashboard-private.log').write_text(logs)
            results=[line[7:] for line in logs.splitlines() if line.startswith('RESULT:')];assert len(results)==1
            result=json.loads(results[0]);(evidence/'dashboard.json').write_text(json.dumps(result,indent=2));print('Dashboard created',json.dumps(result),flush=True)
            # Keep the administration pod only for the bounded browser verification window.
            (evidence/'control-pod.txt').write_text(pod)
            print('Control pod ready for authenticated browser verification',pod,flush=True)
            for _ in range(90):
                guard.check()
                if (evidence/'browser-complete.json').exists():break
                time.sleep(3)
            else:raise RuntimeError('Superset browser verification deadline exceeded')
        except Exception as error:
            (evidence/'failure.txt').write_text(str(error))
            if patched:
                kube(['-n','data-infra','patch','deploy','superset','--type=json','-p',json.dumps([{'op':'replace','path':'/spec/template/spec/containers/0','value':before['spec']['template']['spec']['containers'][0]},{'op':'replace','path':'/spec/strategy','value':before['spec']['strategy']}])]);ready('superset',guard)
            raise
        finally:
            kube(['-n','data-infra','delete','pod',pod,'--ignore-not-found','--wait=false'])
            for _ in range(40):
                p=kube(['-n','data-infra','get','pods','-o','json'])['items']
                if not any(x['metadata']['name']==pod and x['status']['phase'] not in ['Succeeded','Failed'] for x in p):break
                time.sleep(3)
            else:raise RuntimeError('Superset control compute remains; retain Lease')
            guard.compute_stopped=True

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--evidence',required=True);a=p.parse_args();run(a.evidence)
