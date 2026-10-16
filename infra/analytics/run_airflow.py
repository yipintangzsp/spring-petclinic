"""Accept normal, failed, retried and replayed runs before enabling a weekly schedule."""
import argparse
import copy
import datetime
import hashlib
import json
import re
import subprocess
import time
from pathlib import Path

from controlled import HOST, blockers, http_bad, jenkins, kube, sample
from clinic_task import wait_owned_sonar

CORE = ['airflow-api-server', 'airflow-scheduler', 'airflow-dag-processor', 'airflow-statsd']
ALL = CORE + ['airflow-triggerer']


def replicas(count):
    return [{'name': name, 'count': count if name in CORE else 0} for name in ALL]


def switch(count, revision, scheduled=False):
    patches = []
    for name in CORE[:3]:
        patches.append({'target': {'kind': 'Deployment', 'name': name}, 'patch': json.dumps({
            'apiVersion': 'apps/v1', 'kind': 'Deployment', 'metadata': {'name': name},
            'spec': {'template': {'metadata': {'annotations': {'petclinic.devops.local/revision': revision}},
                     'spec': {'containers': [{'name': 'api-server' if name == CORE[0] else
                         'scheduler' if name == CORE[1] else 'dag-processor',
                         'env': [{'name': 'PETCLINIC_ANALYTICS_SCHEDULE',
                                  'value': '30 2 * * 1' if scheduled else ''}]}]}}}})})
    kube(['-n', 'argocd', 'patch', 'application', 'airflow', '--type=merge', '-p', json.dumps({
        'spec': {'source': {'targetRevision': revision, 'kustomize': {'replicas': replicas(count),
                                                                   'patches': patches}}},
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


def page(evidence, run_id, suffix):
    result = subprocess.run(['curl', '--noproxy', '*', '--resolve', f'petclinic.devops.local:80:{HOST}',
                             '-sS', '--max-time', '8',
                             '-w', '\n%{http_code}', 'http' + '://petclinic.devops.local/insights'],
                            capture_output=True, text=True, timeout=10)
    html, _, status = result.stdout.rpartition('\n')
    if result.returncode or status != '200':
        (evidence / f'{run_id}-page-error.json').write_text(json.dumps({
            'exit_code': result.returncode, 'http_status': status, 'stderr': result.stderr[-1000:]}))
        raise RuntimeError('Business insights page failed during orchestration: HTTP ' + status)
    (evidence / f'{run_id}-{suffix}.html').write_text(html)
    return {'http_status': int(status), 'states': re.findall(r'analysis-(running|success|failed)', html),
            'sha256': hashlib.sha256(html.encode()).hexdigest()}


def database(pod):
    return python(pod, "import sys,json;sys.path.insert(0,'/opt/airflow/dags');from clinic_task import connect\n"
                  "with connect() as db,db.cursor() as c:\n"
                  " c.execute(\"SELECT run_id,generated_at::text FROM petclinic_analytics.runs WHERE status='success' ORDER BY generated_at DESC LIMIT 1\");latest=c.fetchone()\n"
                  " c.execute('SELECT count(*),count(DISTINCT visit_id) FROM petclinic_analytics.visit_facts');facts=c.fetchone()\n"
                  " c.execute('SELECT count(*) FROM petclinic_analytics.daily_visits');daily=c.fetchone()[0]\n"
                  " c.execute('SELECT count(*) FROM petclinic_analytics.pet_types');types=c.fetchone()[0]\n"
                  " c.execute('SELECT batch_id,dag_run_id,status,stage,attempt FROM petclinic_analytics.executions ORDER BY started_at DESC LIMIT 1');execution=c.fetchone()\n"
                  " print('RESULT:'+json.dumps({'last_success':latest,'facts':facts,'daily_rows':daily,'type_rows':types,'execution':execution}))")


def wait_run(pod, run_id, evidence, history, record):
    observed = set()
    # Cover the 45-minute DAG timeout and allow terminal state/log collection.
    deadline = time.monotonic() + 3000
    while time.monotonic() < deadline:
        record()
        code = ("import json;from airflow.models.dagrun import DagRun;from airflow.models.taskinstance import TaskInstance;"
                "from airflow.utils.session import create_session\nwith create_session() as s:\n"
                " r=s.query(DagRun).filter_by(dag_id='petclinic_insights',run_id=" + repr(run_id) + ").one();"
                "tasks=s.query(TaskInstance).filter_by(dag_id='petclinic_insights',run_id=r.run_id).all();"
                "print('RESULT:'+json.dumps({'run_id':r.run_id,'state':str(r.state),"
                "'tasks':[{'task_id':t.task_id,'state':str(t.state),'try_number':t.try_number,"
                "'start':str(t.start_date),'end':str(t.end_date)} for t in tasks]}))")
        result = python(pod, code)
        details = python(pod, "import json;from airflow.models.xcom import XComModel;from airflow.utils.session import create_session\n"
                         "with create_session() as s:\n"
                         " rows=s.query(XComModel).filter_by(dag_id='petclinic_insights',run_id=" + repr(run_id) + ",key='return_value').all()\n"
                         " print('RESULT:'+json.dumps({x.task_id:XComModel.deserialize_value(x) for x in rows}))")
        result['xcom'] = details
        result['page'] = page(evidence, run_id, 'current')
        for state in result['page']['states']:
            if state not in observed:
                (evidence / f'{run_id}-{state}.html').write_bytes(
                    (evidence / f'{run_id}-current.html').read_bytes())
                observed.add(state)
        result['observed_page_states'] = sorted(observed)
        application = details.get('spark_submit')
        if application and 'spark-captured' not in observed:
            app = kube(['-n', 'default', 'get', 'sparkapplication', application, '-o', 'json'])
            driver = app.get('status', {}).get('driverInfo', {}).get('podName')
            if driver and app.get('status', {}).get('applicationState', {}).get('state') == 'COMPLETED':
                (evidence / f'{run_id}-spark.json').write_text(json.dumps(app, indent=2))
                logs = kube(['-n', 'default', 'logs', driver, '--tail=600'])
                (evidence / f'{run_id}-spark.log').write_text(str(logs))
                observed.add('spark-captured')
        history.append(result)
        (evidence / 'dag-history.json').write_text(json.dumps(history, indent=2))
        if result['state'] in ('success', 'failed'):
            # The business page has a ten-second summary cache.
            time.sleep(11)
            result['page'] = page(evidence, run_id, 'terminal')
            result['database'] = database(pod)
            files = python(pod, "import json;from pathlib import Path\n"
                           "root=Path('/opt/airflow/logs/dag_id=petclinic_insights/run_id=' + " + repr(run_id) + ")\n"
                           "logs={str(p.relative_to(root)):p.read_text(errors='replace')[-250000:] for p in root.rglob('*.log')}\n"
                           "print('RESULT:'+json.dumps(logs))")
            log_root = evidence / (run_id + '-task-logs')
            for name, content in files.items():
                path = log_root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(content)
            result['task_log_files'] = sorted(files)
            result['jenkins'] = jenkins('/api/json?tree=quietingDown,jobs[name,lastBuild[building]]')
            (evidence / f'{run_id}.json').write_text(json.dumps(result, indent=2))
            return result
        time.sleep(6)
    raise RuntimeError('DAG run exceeded the 50 minute acceptance deadline')


def restore_owned_sonar(lease, evidence):
    metadata = lease['metadata']
    original = json.loads(metadata.get('annotations', {}).get('petclinic.devops.local/paused-sonar', 'null'))
    if original is None:
        return
    holder = lease['spec']['holderIdentity']
    namespace, name = 'sonarqube', 'sonarqube-sonarqube'
    item = kube(['-n', namespace, 'get', 'statefulset', name, '-o', 'json'])
    owner = item['metadata'].get('annotations', {}).get('petclinic.devops.local/analysis-holder')
    if item['metadata']['uid'] != original['uid'] or owner not in (None, holder):
        raise RuntimeError('Sonar ownership changed; retain Jenkins quiet and Lease')
    if owner is None and item['spec']['replicas'] != original['replicas']:
        raise RuntimeError('Unowned Sonar state changed; refuse restoration')
    if item['spec']['replicas'] != original['replicas']:
        kube(['-n', namespace, 'patch', 'statefulset', name, '--type=json', '-p', json.dumps([
            {'op': 'test', 'path': '/metadata/uid', 'value': original['uid']},
            {'op': 'test', 'path': '/metadata/annotations/petclinic.devops.local~1analysis-holder', 'value': holder},
            {'op': 'replace', 'path': '/spec/replicas', 'value': original['replicas']}])])
    def read_state():
        nonlocal item
        item = kube(['-n', namespace, 'get', 'statefulset', name, '-o', 'json'])
        return {'uid': item['metadata']['uid'],
                'owner': item['metadata'].get('annotations', {}).get('petclinic.devops.local/analysis-holder'),
                'replicas': item['spec']['replicas'], 'ready_replicas': item['status'].get('readyReplicas', 0),
                'generation': item['metadata'].get('generation'),
                'observed_generation': item['status'].get('observedGeneration')}
    restored = wait_owned_sonar(read_state, original, owner)
    if item['metadata'].get('annotations', {}).get('petclinic.devops.local/analysis-holder') == holder:
        kube(['-n', namespace, 'patch', 'statefulset', name, '--type=json', '-p', json.dumps([
            {'op': 'test', 'path': '/metadata/uid', 'value': original['uid']},
            {'op': 'test', 'path': '/metadata/annotations/petclinic.devops.local~1analysis-holder', 'value': holder},
            {'op': 'remove', 'path': '/metadata/annotations/petclinic.devops.local~1analysis-holder'}])])
    (evidence / 'abort-sonar-restored.json').write_text(json.dumps({
        'holder': holder, 'uid': original['uid'], 'replicas': original['replicas'],
        'ready': True, 'restoration': restored}, indent=2))


def abort_owned(run_ids, evidence):
    """Stop only compute carrying this acceptance controller's run identities."""
    actions = []
    for run_id in run_ids:
        execution = hashlib.sha256(run_id.encode()).hexdigest()[:12]
        holder = 'airflow:' + hashlib.sha256(run_id.encode()).hexdigest()[:24]
        for namespace in ('default', 'ns-bigdata'):
            for item in kube(['-n', namespace, 'get', 'pods', '-l', 'execution=' + execution, '-o', 'json'])['items']:
                kube(['-n', namespace, 'delete', 'pod', item['metadata']['name'], '--wait=false'])
                actions.append(item['metadata']['name'])
        for app in kube(['-n', 'default', 'get', 'sparkapplications', '-l', 'execution=' + execution, '-o', 'json'])['items']:
            kube(['-n', 'default', 'delete', 'sparkapplication', app['metadata']['name'], '--wait=false'])
        for name in ('flink-jobmanager', 'flink-taskmanager'):
            deployment = kube(['-n', 'ns-bigdata', 'get', 'deployment', name, '-o', 'json'])
            if deployment['metadata'].get('annotations', {}).get('petclinic.devops.local/analysis-execution') == execution:
                kube(['-n', 'ns-bigdata', 'scale', 'deployment', name, '--replicas=0'])
        # Worker ownership is recorded in KubernetesExecutor annotations.
        for worker in kube(['-n', 'data-infra', 'get', 'pods', '-o', 'json'])['items']:
            if worker['metadata'].get('annotations', {}).get('run_id') == run_id:
                kube(['-n', 'data-infra', 'delete', 'pod', worker['metadata']['name'], '--wait=false'])
        for _ in range(60):
            active = []
            for namespace in ('default', 'ns-bigdata'):
                active += [p for p in kube(['-n', namespace, 'get', 'pods', '-l', 'execution=' + execution, '-o', 'json'])['items']
                           if p['status']['phase'] not in ('Succeeded', 'Failed')]
            for name in ('flink-jobmanager', 'flink-taskmanager'):
                deployment = kube(['-n', 'ns-bigdata', 'get', 'deployment', name, '-o', 'json'])
                if deployment['metadata'].get('annotations', {}).get('petclinic.devops.local/analysis-execution') == execution:
                    selector = ','.join(k+'='+v for k,v in deployment['spec']['selector']['matchLabels'].items())
                    active += [p for p in kube(['-n', 'ns-bigdata', 'get', 'pods', '-l', selector, '-o', 'json'])['items']
                               if p['status']['phase'] not in ('Succeeded', 'Failed')]
            if not active:
                break
            time.sleep(2)
        else:
            raise RuntimeError('Owned compute remains active; retain the shared Lease and Jenkins pause')
        leases = kube(['-n', 'data-infra', 'get', 'leases', '-o', 'json'])['items']
        for lease in leases:
            if lease['metadata']['name'] == 'platform-heavy' and lease['spec'].get('holderIdentity') == holder:
                restore_owned_sonar(lease, evidence)
                kube(['-n', 'data-infra', 'delete', 'lease', 'platform-heavy', '--wait=false'])
        for cm in kube(['-n', 'default', 'get', 'configmaps', '-l', 'airflow-holder=' + holder.replace(':', '-'), '-o', 'json'])['items']:
            kube(['-n', 'default', 'delete', 'configmap', cm['metadata']['name']])
    (evidence / 'abort-cleanup.json').write_text(json.dumps({'run_ids': run_ids, 'actions': actions}, indent=2))


def run(revision, evidence_path, keep_running=False):
    evidence = Path(evidence_path)
    evidence.mkdir(parents=True, exist_ok=True)
    pod = 'petclinic-airflow-control-' + datetime.datetime.now().strftime('%H%M%S')
    history, samples = [], []
    owned_quiet = False
    accepted = False
    run_ids, results = [], []
    initial_quiet = False
    bad_http = 0

    def record():
        nonlocal bad_http
        value = sample()
        bad_http = bad_http + 1 if http_bad(value) else 0
        samples.append(value)
        reasons = blockers(value, bad_http=bad_http, previous_failures=samples[0]['failures'])
        if not value['apiReady'] or (len(samples) == 1 and http_bad(value)):
            reasons.append('API or initial business health check failed')
        if value.get('mac', {}).get('swapUsedMiB', 0) - samples[0].get('mac', {}).get('swapUsedMiB', 0) > 512:
            reasons.append('Mac swap grew by more than 512 MiB')
        if reasons:
            raise RuntimeError('Safety stop: ' + '; '.join(reasons))
        (evidence / 'resource-samples.json').write_text(json.dumps(samples, indent=2))
        return value

    for index in range(5):
        before = record()
        if before['availableMiB'] < 10240:
            raise RuntimeError('Airflow orchestration requires at least 10240 MiB node MemAvailable in all five admission samples')
        if index < 4:
            time.sleep(15)
    if any(kube(['-n', 'data-infra', 'get', 'deployment', name, '-o', 'json'])['spec']['replicas']
           for name in CORE):
        raise RuntimeError('Acceptance expects idle Airflow core; do not take over an existing scheduler')
    try:
        state = jenkins('/api/json?tree=quietingDown,jobs[name,lastBuild[building]]')
        initial_quiet = state.get('quietingDown', False)
        if not state.get('quietingDown'):
            jenkins('/quietDown', 'POST')
            owned_quiet = True
        state = jenkins('/api/json?tree=quietingDown,jobs[name,lastBuild[building]]')
        active = [job['name'] for job in state.get('jobs', [])
                  if (job.get('lastBuild') or {}).get('building')]
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
        container['args'] = ['sleep 14400']
        container['resources'] = {'requests': {'memory': '512Mi', 'cpu': '100m'},
                                  'limits': {'memory': '512Mi', 'cpu': '500m'}}
        for key in ('livenessProbe', 'readinessProbe', 'startupProbe'):
            container.pop(key, None)
        spec['automountServiceAccountToken'] = False
        spec['restartPolicy'] = 'Never'
        spec['activeDeadlineSeconds'] = 14400
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
        active = python(pod, "import json;from airflow.models.dagrun import DagRun;from airflow.utils.session import create_session\n"
                        "with create_session() as s:\n"
                        " print('RESULT:'+json.dumps([r.run_id for r in s.query(DagRun).filter(DagRun.dag_id=='petclinic_insights',DagRun.state.in_(['queued','running'])).all()]))")
        if active:
            raise RuntimeError('Existing active DAG runs require inspection before acceptance: ' + str(active))

        # Allow each DAG's guard to pause and restore Jenkins itself. The host
        # controller never acquires the same shared Lease a second time.
        if owned_quiet:
            jenkins('/cancelQuietDown', 'POST')
            owned_quiet = False
        for index, mode in enumerate(('none', 'fail', 'retry', 'none'), 1):
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
            run_ids.append(run_id)
            result = wait_run(pod, run_id, evidence, history, record)
            expected = 'failed' if mode == 'fail' else 'success'
            if result['state'] != expected:
                raise RuntimeError(f'DAG run {run_id}: expected {expected}, observed {result["state"]}')
            if result['jenkins'].get('quietingDown', False) != initial_quiet:
                raise RuntimeError('The DAG did not restore the original Jenkins state')
            if not result['xcom'].get('cleanup', {}).get('sonar_restored'):
                raise RuntimeError('The DAG did not verify Sonar restoration before resuming Jenkins')
            if not result['xcom'].get('cleanup', {}).get('released'):
                raise RuntimeError('DAG cleanup did not confirm resource and Lease release')
            leases = kube(['-n', 'data-infra', 'get', 'leases', '-o', 'json'])['items']
            if any(l['metadata']['name'] == 'platform-heavy' for l in leases):
                raise RuntimeError('Shared heavy Lease remains after the DAG')
            if mode == 'fail':
                if result['database']['last_success'] != results[0]['database']['last_success']:
                    raise RuntimeError('A failed batch replaced the last successful publication')
                if 'failed' not in result['page']['states']:
                    raise RuntimeError('The business page does not show the actual failed status')
            else:
                if 'success' not in result['page']['states']:
                    raise RuntimeError('The business page does not show verified success')
                if 'running' not in result['observed_page_states']:
                    raise RuntimeError('No running business-page state was captured')
                if results and result['xcom']['snapshot']['batch_id'] != results[0]['xcom']['snapshot']['batch_id']:
                    raise RuntimeError('Replay did not use the same unchanged bounded batch')
                if index > 1 and any(result['database'][key] != results[0]['database'][key]
                                     for key in ('facts', 'daily_rows', 'type_rows')):
                    raise RuntimeError('Replay added duplicate analytics facts or summaries')
            if mode == 'retry' and not any(task['task_id'] == 'flink' and task['try_number'] == 2
                                            for task in result['tasks']):
                raise RuntimeError('Controlled failure did not produce a second Flink attempt')
            if mode == 'fail' and not any(t['task_id'] == 'flink' and t['try_number'] == 2 for t in result['tasks']):
                raise RuntimeError('Terminal failure did not exhaust its bounded retry')
            results.append(result)
            (evidence / 'acceptance.json').write_text(json.dumps(results, indent=2))
        accepted = True
    finally:
        safe_to_resume = False
        for name in CORE:
            try:
                logs = kube(['-n', 'data-infra', 'logs', 'deploy/' + name,
                             '--all-containers=true', '--tail=300'])
                (evidence / (name + '.log')).write_text(str(logs))
            except Exception as error:
                (evidence / (name + '.log-error')).write_text(str(error))
        try:
            if not accepted:
                switch(0, revision)
                # Stop dispatch before deleting only this controller's workers.
                for _ in range(60):
                    scheduler_state = kube(['-n', 'data-infra', 'get', 'deployment', 'airflow-scheduler', '-o', 'json'])
                    if scheduler_state['status'].get('replicas', 0) == 0:
                        break
                    time.sleep(2)
                else:
                    raise RuntimeError('Scheduler has not stopped; preserve Jenkins pause and shared Lease')
                abort_owned(run_ids, evidence)
                if run_ids:
                    code = ("import json;from airflow.models.dagrun import DagRun;from airflow.models.taskinstance import TaskInstance;"
                            "from airflow.utils.session import create_session;from airflow.utils.state import DagRunState,TaskInstanceState\n"
                            "with create_session() as s:\n"
                            " for r in s.query(DagRun).filter(DagRun.dag_id=='petclinic_insights',DagRun.run_id.in_(" + repr(run_ids) + ")).all():\n"
                            "  if r.state in ('queued','running'):r.set_state(DagRunState.FAILED)\n"
                            " for t in s.query(TaskInstance).filter(TaskInstance.dag_id=='petclinic_insights',TaskInstance.run_id.in_(" + repr(run_ids) + ")).all():\n"
                            "  if t.state in ('queued','running','scheduled','up_for_retry','up_for_reschedule'):t.set_state(TaskInstanceState.FAILED,session=s)\n"
                            "print('RESULT:'+json.dumps({'marked_failed':True}))")
                    python(pod, code)
                    python(pod, "import sys,json;sys.path.insert(0,'/opt/airflow/dags');from clinic_task import connect\n"
                           "with connect() as db,db.cursor() as c:\n"
                           " c.execute(\"UPDATE petclinic_analytics.executions SET status='failed',stage='controller-abort',finished_at=now(),updated_at=now(),error='Acceptance controller stopped; inspect private evidence' WHERE dag_run_id=ANY(%s) AND status='running'\",(" + repr(run_ids) + ",))\n"
                           "print('RESULT:'+json.dumps({'status_recorded':True}))")
            else:
                switch(1 if keep_running else 0, revision, scheduled=keep_running)
                (evidence / 'desired-state.json').write_text(json.dumps({'revision': revision,
                    'airflow_core_replicas': 1 if keep_running else 0,
                    'schedule': '30 2 * * 1' if keep_running else None,
                    'timezone': 'Asia/Shanghai', 'catchup': False, 'max_active_runs': 1}, indent=2))
            safe_to_resume = True
        finally:
            kube(['-n', 'data-infra', 'delete', 'pod', pod, '--ignore-not-found', '--wait=false'])
            if safe_to_resume and (owned_quiet or not initial_quiet):
                jenkins('/cancelQuietDown', 'POST')


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--revision', required=True)
    parser.add_argument('--evidence', required=True)
    parser.add_argument('--keep-running', action='store_true')
    arguments = parser.parse_args()
    run(arguments.revision, arguments.evidence, arguments.keep_running)
