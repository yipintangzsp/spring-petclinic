"""Run the existing Airflow core temporarily, preserve metadata, then return to zero."""
import argparse,copy,datetime,json,time
from pathlib import Path
from controlled import HeavyRun,kube

CORE=['airflow-api-server','airflow-scheduler','airflow-dag-processor','airflow-statsd']
ALL=CORE+['airflow-triggerer']


def replicas(count):
    return [f'{name}={count if name in CORE else 0}' for name in ALL]


def switch(count,revision):
    # Pin the reviewed configuration so unrelated source pushes cannot start compute.
    kube(['-n','argocd','patch','application','airflow','--type=merge','-p',json.dumps({
        'spec':{'source':{'targetRevision':revision,'kustomize':{'replicas':replicas(count)}}},
        'metadata':{'annotations':{'argocd.argoproj.io/refresh':'hard'}}})])


def python(pod,code):
    out=kube(['-n','data-infra','exec',pod,'--','python','-c',code],timeout=45)
    lines=str(out).splitlines()
    matches=[s[7:] for s in lines if s.startswith('RESULT:')]
    if len(matches)!=1:raise RuntimeError('Airflow control command returned no unique result: '+str(out)[-800:])
    return json.loads(matches[0])


def run(revision,evidence):
    evidence=Path(evidence);evidence.mkdir(parents=True,exist_ok=True)
    pod='petclinic-airflow-control-'+datetime.datetime.now().strftime('%H%M%S')
    history=[]
    with HeavyRun('airflow',4096,evidence) as guard:
        guard.compute_stopped = False
        try:
            switch(1,revision)
            for _ in range(70):
                guard.check()
                ready=True
                for name in CORE:
                    item=kube(['-n','data-infra','get','deployment',name,'-o','json'])
                    ready=ready and item['status'].get('readyReplicas',0)==1
                if ready:break
                time.sleep(6)
            else:raise RuntimeError('Airflow core did not become ready within seven minutes')
            sched=kube(['-n','data-infra','get','deployment','airflow-scheduler','-o','json'])
            spec=copy.deepcopy(sched['spec']['template']['spec']);spec.pop('initContainers',None)
            spec['containers']=spec['containers'][:1];c=spec['containers'][0];c['name']='control'
            c['command']=['bash','-c'];c['args']=['sleep 1800']
            c['resources']={'requests':{'memory':'512Mi','cpu':'100m'},'limits':{'memory':'512Mi','cpu':'500m'}}
            for k in ['livenessProbe','readinessProbe','startupProbe']:c.pop(k,None)
            spec['automountServiceAccountToken']=False;spec['restartPolicy']='Never';spec['activeDeadlineSeconds']=1800
            kube(['create','-f','-'],{'apiVersion':'v1','kind':'Pod','metadata':{'name':pod,'namespace':'data-infra','labels':{'app':'petclinic-analysis','purpose':'airflow-control'}},'spec':spec})
            for _ in range(30):
                guard.check();p=kube(['-n','data-infra','get','pod',pod,'-o','json'])
                if any(c.get('ready') for c in p['status'].get('containerStatuses',[])):break
                time.sleep(3)
            else:raise RuntimeError('Airflow control pod not ready')
            details=python(pod,"import airflow,inspect,json;from airflow.api.common.trigger_dag import trigger_dag;print('RESULT:'+json.dumps({'version':airflow.__version__,'triggerSignature':str(inspect.signature(trigger_dag))}))")
            (evidence/'runtime.json').write_text(json.dumps(details,indent=2));print('Airflow runtime',details,flush=True)
            # Wait until the real dag-processor persists the DAG; no dag.test shortcuts.
            for _ in range(40):
                guard.check()
                found=python(pod,"import json;from airflow.models.dag import DagModel;from airflow.utils.session import create_session\nwith create_session() as s:\n d=s.get(DagModel,'petclinic_insights');print('RESULT:'+json.dumps({'parsed':d is not None}))")
                if found['parsed']:break
                time.sleep(5)
            else:raise RuntimeError('DAG was not parsed by the installed dag processor')
            for mode in ['none','retry','timeout','none']:
                guard.check();runid='manual__platform_'+datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%S')+'_'+mode
                conf={'from':'2026-01-01','to':'2026-12-31','verify_retry':mode}
                code="import inspect,json;from airflow.api.common.trigger_dag import trigger_dag;from airflow.models.dag import DagModel;from airflow.utils.session import create_session\nwith create_session() as s:\n d=s.get(DagModel,'petclinic_insights');d.is_paused=False\nkwargs="+repr({'dag_id':'petclinic_insights','run_id':runid,'conf':conf})+"\nr=trigger_dag(**kwargs);print('RESULT:'+json.dumps({'run_id':r.run_id,'state':str(r.state)}))"
                triggered=python(pod,code);print('Triggered',runid,flush=True)
                for _ in range(66):
                    guard.check()
                    code="import json;from airflow.models.dagrun import DagRun;from airflow.models.taskinstance import TaskInstance;from airflow.utils.session import create_session\nwith create_session() as s:\n r=s.query(DagRun).filter_by(dag_id='petclinic_insights',run_id="+repr(runid)+").one();tasks=s.query(TaskInstance).filter_by(dag_id='petclinic_insights',run_id=r.run_id).all();print('RESULT:'+json.dumps({'run_id':r.run_id,'state':str(r.state),'tasks':[{'task_id':t.task_id,'state':str(t.state),'try_number':t.try_number,'start':str(t.start_date),'end':str(t.end_date)} for t in tasks]}))"
                    result=python(pod,code);history.append(result);(evidence/'dag-history.json').write_text(json.dumps(history,indent=2))
                    if result['state'] in ['success','failed']:break
                    time.sleep(5)
                else:raise RuntimeError('DAG run exceeded acceptance deadline')
                print('DAG result',json.dumps(result),flush=True)
                if result['state']!='success':raise RuntimeError('DAG run failed')
                if mode!='none' and not any(t['task_id']=='bounded_read' and t['try_number']==2 for t in result['tasks']):raise RuntimeError('Probe did not exercise an actual second attempt')
        finally:
            # Save scheduler diagnostics before shutting down. Logs stay in private evidence.
            for name in CORE:
                try:(evidence/(name+'.log')).write_text(str(kube(['-n','data-infra','logs','deploy/'+name,'--all-containers=true','--tail=180'])))
                except Exception as error:(evidence/(name+'.log-error')).write_text(str(error))
            kube(['-n','data-infra','delete','pod',pod,'--ignore-not-found','--wait=false'])
            switch(0,revision)
            for _ in range(50):
                pods=kube(['-n','data-infra','get','pods','-o','json'])['items']
                active=[p for p in pods if p['metadata'].get('labels',{}).get('release')=='airflow' or p['metadata'].get('labels',{}).get('kubernetes_executor')=='True']
                if not active:break
                time.sleep(3)
            else:raise RuntimeError('Airflow compute still exists; retain Lease for investigation')
            guard.compute_stopped = True

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--revision',required=True);p.add_argument('--evidence',required=True);a=p.parse_args();run(a.revision,a.evidence)
