"""Run and accept the real serial Petclinic Airflow workflow, then scale Airflow to zero."""
import argparse
import copy
import datetime
import json
import time
from pathlib import Path

from controlled import blockers, http_bad, jenkins, kube, sample

CORE = ['airflow-api-server', 'airflow-scheduler', 'airflow-dag-processor', 'airflow-statsd']
ALL = CORE + ['airflow-triggerer']


def replicas(count):
    return [{'name': name, 'count': count if name in CORE else 0} for name in ALL]


def switch(count, revision):
    kube(['-n', 'argocd', 'patch', 'application', 'airflow', '--type=merge', '-p', json.dumps({
        'spec': {'source': {'targetRevision': revision, 'kustomize': {'replicas': replicas(count)}}},
        'metadata': {'annotations': {'argocd.argoproj.io/refresh': 'hard'}},
    })])


def python(pod, code):
    out = kube(['-n', 'data-infra', 'exec', pod, '--', 'python', '-c', code], timeout=45)
    matches = [line[7:] for line in str(out).splitlines() if line.startswith('RESULT:')]
    if len(matches) != 1:
        raise RuntimeError('Airflow control command returned no unique result: ' + str(out)[-800:])
    return json.loads(matches[0])


def wait_ready(record):
    for _ in range(70):
        record()
        if all(kube(['-n', 'data-infra', 'get', 'deployment', name, '-o', 'json'])
               ['status'].get('readyReplicas', 0) == 1 for name in CORE):
            return
        time.sleep(6)
    raise RuntimeError('Airflow core did not become ready within seven minutes')


def wait_run(pod, run_id, evidence, history, record):
    for _ in range(300):
        record()
        code = ("import json;from airflow.models.dagrun import DagRun;from airflow.models.taskinstance import TaskInstance;"
                "from airflow.utils.session import create_session\nwith create_session() as s:\n"
                " r=s.query(DagRun).filter_by(dag_id='petclinic_insights',run_id=" + repr(run_id) + ").one();"
                "tasks=s.query(TaskInstance).filter_by(dag_id='petclinic_insights',run_id=r.run_id).all();"
                "print('RESULT:'+json.dumps({'run_id':r.run_id,'state':str(r.state),"
                "'tasks':[{'task_id':t.task_id,'state':str(t.state),'try_number':t.try_number,"
                "'start':str(t.start_date),'end':str(t.end_date)} for t in tasks]}))")
        result = python(pod, code)
        history.append(result)
        (evidence / 'dag-history.json').write_text(json.dumps(history, indent=2))
        if result['state'] in ('success', 'failed'):
            return result
        time.sleep(6)
    raise RuntimeError('DAG run exceeded the 30 minute acceptance deadline')


def run(revision, evidence_path):
    evidence = Path(evidence_path)
    evidence.mkdir(parents=True, exist_ok=True)
    pod = 'petclinic-airflow-control-' + datetime.datetime.now().strftime('%H%M%S')
    history, samples = [], []
    owned_quiet = False

    def record():
        value = sample()
        samples.append(value)
        reasons = blockers(value, previous_failures=samples[0]['failures'])
        if http_bad(value):
            reasons.append('Business/API health check failed')
        if reasons:
            raise RuntimeError('Safety stop: ' + '; '.join(reasons))
        (evidence / 'resource-samples.json').write_text(json.dumps(samples, indent=2))
        return value

    before = record()
    if before['availableMiB'] < 10240:
        raise RuntimeError('Airflow orchestration requires at least 10240 MiB node MemAvailable')
    try:
        state = jenkins('/api/json?tree=quietingDown,jobs[name,lastBuild[building]]')
        if not state.get('quietingDown'):
            jenkins('/quietDown', 'POST')
            owned_quiet = True
        state = jenkins('/api/json?tree=quietingDown,jobs[name,lastBuild[building]]')
        active = [job['name'] for job in state.get('jobs', []) if job.get('lastBuild', {}).get('building')]
        if active:
            raise RuntimeError('Jenkins still has active builds: ' + ','.join(active))

        switch(1, revision)
        wait_ready(record)
        scheduler = kube(['-n', 'data-infra', 'get', 'deployment', 'airflow-scheduler', '-o', 'json'])
        spec = copy.deepcopy(scheduler['spec']['template']['spec'])
        spec.pop('initContainers', None)
        spec['containers'] = spec['containers'][:1]
        container = spec['containers'][0]
        container['name'] = 'control'
        container['command'] = ['bash', '-c']
        container['args'] = ['sleep 3600']
        container['resources'] = {'requests': {'memory': '512Mi', 'cpu': '100m'},
                                  'limits': {'memory': '512Mi', 'cpu': '500m'}}
        for key in ('livenessProbe', 'readinessProbe', 'startupProbe'):
            container.pop(key, None)
        spec['automountServiceAccountToken'] = False
        spec['restartPolicy'] = 'Never'
        spec['activeDeadlineSeconds'] = 3600
        kube(['create', '-f', '-'], {'apiVersion': 'v1', 'kind': 'Pod',
             'metadata': {'name': pod, 'namespace': 'data-infra',
                          'labels': {'app': 'petclinic-analysis', 'purpose': 'airflow-control'}},
             'spec': spec})
        for _ in range(40):
            record()
            item = kube(['-n', 'data-infra', 'get', 'pod', pod, '-o', 'json'])
            if any(status.get('ready') for status in item['status'].get('containerStatuses', [])):
                break
            time.sleep(3)
        else:
            raise RuntimeError('Airflow control pod not ready')

        runtime = python(pod, "import airflow,json;print('RESULT:'+json.dumps({'version':airflow.__version__}))")
        (evidence / 'runtime.json').write_text(json.dumps(runtime, indent=2))
        for _ in range(40):
            found = python(pod, "import json;from airflow.models.dag import DagModel;from airflow.utils.session import create_session\nwith create_session() as s:\n d=s.get(DagModel,'petclinic_insights');print('RESULT:'+json.dumps({'parsed':d is not None}))")
            if found['parsed']:
                break
            record()
            time.sleep(5)
        else:
            raise RuntimeError('DAG was not parsed by the installed DAG processor')

        for index, mode in enumerate(('none', 'retry', 'none'), 1):
            stamp = datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%S')
            run_id = f'manual__orchestration_{stamp}_{index}_{mode}'
            conf = {'from': '2026-01-01', 'to': '2026-12-31', 'verify_retry': mode}
            code = ("import json;from airflow.utils.types import DagRunTriggeredByType;"
                    "from airflow.api.common.trigger_dag import trigger_dag;from airflow.models.dag import DagModel;"
                    "from airflow.utils.session import create_session\nwith create_session() as s:\n"
                    " d=s.get(DagModel,'petclinic_insights');d.is_paused=False\nkwargs="
                    + repr({'dag_id': 'petclinic_insights', 'run_id': run_id, 'conf': conf})
                    + "\nkwargs['triggered_by']=DagRunTriggeredByType.CLI\nr=trigger_dag(**kwargs);"
                    "print('RESULT:'+json.dumps({'run_id':r.run_id,'state':str(r.state)}))")
            python(pod, code)
            result = wait_run(pod, run_id, evidence, history, record)
            if result['state'] != 'success':
                raise RuntimeError('DAG run failed: ' + run_id)
            if mode == 'retry' and not any(task['task_id'] == 'validate' and task['try_number'] == 2
                                            for task in result['tasks']):
                raise RuntimeError('Controlled failure did not produce a second validate attempt')
    finally:
        for name in CORE:
            try:
                logs = kube(['-n', 'data-infra', 'logs', 'deploy/' + name,
                             '--all-containers=true', '--tail=300'])
                (evidence / (name + '.log')).write_text(str(logs))
            except Exception as error:
                (evidence / (name + '.log-error')).write_text(str(error))
        try:
            kube(['-n', 'data-infra', 'delete', 'pod', pod, '--ignore-not-found', '--wait=false'])
            switch(0, revision)
        finally:
            if owned_quiet:
                jenkins('/cancelQuietDown', 'POST')


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--revision', required=True)
    parser.add_argument('--evidence', required=True)
    arguments = parser.parse_args()
    run(arguments.revision, arguments.evidence)
