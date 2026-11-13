"""Validate the owned dashboard using the already verified Superset image."""
import argparse,copy,datetime,json,subprocess,time
from pathlib import Path
from controlled import HeavyRun,kube


def run(image,evidence,browser_python,browser_script):
    evidence=Path(evidence);evidence.mkdir(parents=True,exist_ok=True)
    name='petclinic-superset-verify-'+datetime.datetime.now().strftime('%H%M%S')
    before=kube(['-n','data-infra','get','deploy','superset','-o','json'])
    (evidence/'web-before-verification-private.json').write_text(json.dumps(before));(evidence/'web-before-verification-private.json').chmod(0o600)
    with HeavyRun('superset-render',2048,evidence) as guard:
        guard.compute_stopped=False
        try:
            c=before['spec']['template']['spec']['containers'][0]
            kube(['-n','data-infra','patch','deploy','superset','--type=strategic','-p',json.dumps({'spec':{'strategy':{'type':'RollingUpdate','rollingUpdate':{'maxSurge':0,'maxUnavailable':1}},'template':{'spec':{'containers':[{'name':c['name'],'image':image,'resources':{'requests':{'memory':'768Mi','cpu':'100m'},'limits':{'memory':'768Mi','cpu':'1000m'}}}]}}}})])
            for _ in range(75):
                guard.check();d=kube(['-n','data-infra','get','deploy','superset','-o','json']);s=d['status']
                if s.get('observedGeneration',0)>=d['metadata']['generation'] and s.get('updatedReplicas')==1 and s.get('availableReplicas')==1 and s.get('replicas')==1:break
                time.sleep(3)
            else:raise RuntimeError('Superset web not ready')
            cm=name+'-code';kube(['create','-f','-'],{'apiVersion':'v1','kind':'ConfigMap','metadata':{'name':cm,'namespace':'data-infra','labels':{'app':'petclinic-analysis'}},'data':{'create_dashboard.py':Path(__file__).with_name('superset').joinpath('create_dashboard.py').read_text()}})
            spec=copy.deepcopy(d['spec']['template']['spec']);spec.pop('initContainers',None);spec['containers']=spec['containers'][:1];c=spec['containers'][0]
            c['name']='control';c['command']=['bash','-c'];c['args']=['sleep 900']
            for k in ['livenessProbe','readinessProbe','startupProbe']:c.pop(k,None)
            c.setdefault('env',[]).append({'name':'CLINIC_TRINO_URI','value':'trino://reporter@trino.data-infra.svc.cluster.local:8080/clinic/petclinic_analytics'})
            spec.setdefault('volumes',[]).append({'name':'clinic-code','configMap':{'name':cm}});c.setdefault('volumeMounts',[]).append({'name':'clinic-code','mountPath':'/opt/clinic','readOnly':True})
            spec['automountServiceAccountToken']=False;spec['restartPolicy']='Never';spec['activeDeadlineSeconds']=900
            kube(['create','-f','-'],{'apiVersion':'v1','kind':'Pod','metadata':{'name':name,'namespace':'data-infra','labels':{'app':'petclinic-analysis'}},'spec':spec})
            for _ in range(45):
                guard.check();p=kube(['-n','data-infra','get','pod',name,'-o','json'])
                if any(c.get('ready') for c in p['status'].get('containerStatuses',[])):break
                time.sleep(2)
            else:raise RuntimeError('Superset verification pod did not start')
            log=str(kube(['-n','data-infra','exec',name,'--','/app/.venv/bin/python','/opt/clinic/create_dashboard.py'],timeout=120));(evidence/'create-dashboard-private.log').write_text(log)
            data=json.loads(next(l[7:] for l in log.splitlines() if l.startswith('RESULT:')))
            (evidence/'dashboard.json').write_text(json.dumps(data,indent=2));(evidence/'control-pod.txt').write_text(name);print('Verifying actual dashboard',data,flush=True)
            # The browser keeps authentication cookies in memory; outputs contain aggregate data only.
            result=subprocess.run([browser_python,browser_script],capture_output=True,text=True,timeout=180)
            (evidence/'browser-stdout.txt').write_text(result.stdout);(evidence/'browser-stderr.txt').write_text(result.stderr)
            if result.returncode:raise RuntimeError('Superset browser acceptance failed; see private browser evidence')
            guard.check();print(result.stdout,flush=True)
        finally:
            kube(['-n','data-infra','delete','pod',name,'--ignore-not-found','--wait=false'])
            for _ in range(40):
                p=kube(['-n','data-infra','get','pods','-o','json'])['items']
                if not any(x['metadata']['name']==name and x['status']['phase'] not in ['Succeeded','Failed'] for x in p):break
                time.sleep(3)
            else:raise RuntimeError('Verification compute remains; retain Lease')
            guard.compute_stopped=True

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--image',required=True);p.add_argument('--evidence',required=True);p.add_argument('--browser-python',required=True);p.add_argument('--browser-script',required=True);a=p.parse_args();run(a.image,a.evidence,a.browser_python,a.browser_script)
