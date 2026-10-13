"""Run and repeat a real bounded SparkApplication while keeping the Operator active."""
import argparse
import csv
import datetime
import hashlib
import io
import json
import shlex
import time
from pathlib import Path

from controlled import HeavyRun, kube, remote

OP = ['spark-operator-controller', 'spark-operator-webhook']
RUNTIME_IMAGE = ('127.0.0.1:30050/platform-upgrade/spark-runtime@'
                 'sha256:711ace285d47914adfeec1a4db16d30632cade0717c971e9049d4adf59dcb500')


def mysql(sql, timeout=60):
    command = shlex.join([
        'sudo', '-n', 'kubectl', '-n', 'ns-data', 'exec', '-i', 'deploy/mysql', '--',
        'sh', '-lc', 'MYSQL_PWD="$MYSQL_ROOT_PASSWORD" mysql -uroot --batch --raw --skip-column-names',
    ])
    return remote(command, sql, timeout)


def quote(value):
    return "'" + str(value).replace('\\', '\\\\').replace("'", "''") + "'"


def baseline(batch_id, snapshot_sha, rows, start, end):
    values = ',\n'.join(
        '(' + ','.join([quote(batch_id), str(r['visit_id']), quote(r['visit_date']),
                        str(r['pet_id']), quote(r['pet_type']), quote(snapshot_sha)]) + ')'
        for r in rows
    )
    ddl = """
CREATE DATABASE IF NOT EXISTS petclinic_analytics_baseline;
CREATE TABLE IF NOT EXISTS petclinic_analytics_baseline.snapshot_visits (
 batch_id VARCHAR(96) NOT NULL, visit_id BIGINT NOT NULL, visit_date DATE NOT NULL,
 pet_id BIGINT NOT NULL, pet_type VARCHAR(64) NOT NULL, snapshot_sha CHAR(64) NOT NULL,
 PRIMARY KEY (batch_id,visit_id)
);
CREATE TABLE IF NOT EXISTS petclinic_analytics_baseline.runs (
 batch_id VARCHAR(96) PRIMARY KEY, snapshot_sha CHAR(64) NOT NULL,
 window_start DATE NOT NULL, window_end DATE NOT NULL, input_rows INT NOT NULL,
 updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);
"""
    load = f"""
INSERT INTO petclinic_analytics_baseline.runs
 (batch_id,snapshot_sha,window_start,window_end,input_rows)
 VALUES ({quote(batch_id)},{quote(snapshot_sha)},{quote(start)},{quote(end)},{len(rows)})
 ON DUPLICATE KEY UPDATE
 snapshot_sha=IF(snapshot_sha=VALUES(snapshot_sha),snapshot_sha,NULL),
 window_start=VALUES(window_start),window_end=VALUES(window_end),input_rows=VALUES(input_rows);
INSERT INTO petclinic_analytics_baseline.snapshot_visits
 (batch_id,visit_id,visit_date,pet_id,pet_type,snapshot_sha) VALUES
{values}
 ON DUPLICATE KEY UPDATE
 visit_date=VALUES(visit_date),pet_id=VALUES(pet_id),pet_type=VALUES(pet_type),
 snapshot_sha=VALUES(snapshot_sha);
SELECT COUNT(*),COUNT(DISTINCT visit_id),
 SUM(visit_date BETWEEN {quote(start)} AND {quote(end)}),MIN(visit_date),MAX(visit_date)
 FROM petclinic_analytics_baseline.snapshot_visits WHERE batch_id={quote(batch_id)};
SELECT pet_type,COUNT(*) FROM petclinic_analytics_baseline.snapshot_visits
 WHERE batch_id={quote(batch_id)} AND visit_date BETWEEN {quote(start)} AND {quote(end)}
 GROUP BY pet_type ORDER BY pet_type;
"""
    lines = [line.split('\t') for line in mysql(ddl + load).splitlines() if line.strip()]
    summary = lines[0]
    return {
        'engine': 'MySQL', 'batchId': batch_id, 'snapshotSha256': snapshot_sha,
        'inputRows': int(summary[0]), 'uniqueVisitIds': int(summary[1]),
        'windowVisits': int(summary[2]), 'sourceMinimumDate': summary[3],
        'sourceMaximumDate': summary[4],
        'visitsByPetType': [{'type': row[0], 'visits': int(row[1])} for row in lines[1:]],
    }


def wait_operator(guard):
    for name in OP:
        deployment = kube(['-n', 'ns-bigdata', 'get', 'deploy', name, '-o', 'json'])
        if deployment['spec']['replicas'] != 1:
            raise RuntimeError(f'{name} must remain enabled at one replica')
    for _ in range(40):
        guard.check()
        if all(kube(['-n', 'ns-bigdata', 'get', 'deploy', name, '-o', 'json'])
               ['status'].get('readyReplicas') == 1 for name in OP):
            return
        time.sleep(3)
    raise RuntimeError('Installed Spark Operator is not Ready')


def one_application(name, config_map, batch_id, start, end, evidence, guard):
    role = {
        'cores': 1, 'coreLimit': '1000m', 'memory': '512m', 'memoryOverhead': '512m',
        'labels': {'app': 'petclinic-analysis', 'acceptance': name, 'batch': batch_id},
        'volumeMounts': [{'name': 'snapshot', 'mountPath': '/opt/clinic', 'readOnly': True}],
        'securityContext': {'runAsUser': 185, 'runAsGroup': 185, 'runAsNonRoot': True,
                            'allowPrivilegeEscalation': False, 'capabilities': {'drop': ['ALL']},
                            'seccompProfile': {'type': 'RuntimeDefault'}},
    }
    app = {
        'apiVersion': 'sparkoperator.k8s.io/v1beta2', 'kind': 'SparkApplication',
        'metadata': {'name': name, 'namespace': 'default',
                     'labels': {'app': 'petclinic-analysis', 'batch': batch_id}},
        'spec': {
            'type': 'Python', 'pythonVersion': '3', 'mode': 'cluster', 'image': RUNTIME_IMAGE,
            'imagePullPolicy': 'IfNotPresent', 'sparkVersion': '4.0.1',
            'mainApplicationFile': 'local:///opt/clinic/clinic_snapshot.py',
            'arguments': ['--from', start, '--to', end, '--batch-id', batch_id,
                          '--ui-hold-seconds', '45'],
            'restartPolicy': {'type': 'Never'}, 'timeToLiveSeconds': 600,
            'nodeSelector': {'kubernetes.io/hostname': 'devops'},
            'sparkConf': {
                'spark.sql.shuffle.partitions': '1', 'spark.default.parallelism': '1',
                'spark.ui.enabled': 'true', 'spark.ui.retainedJobs': '100',
                'spark.driver.maxResultSize': '64m',
                'spark.kubernetes.driver.request.cores': '1',
                'spark.kubernetes.executor.request.cores': '1',
            },
            'volumes': [{'name': 'snapshot', 'configMap': {'name': config_map}}],
            'driver': {**role, 'serviceAccount': 'spark-operator-spark'},
            'executor': {**role, 'instances': 1},
        },
    }
    evidence.mkdir(parents=True, exist_ok=True)
    (evidence / 'application.json').write_text(json.dumps(app, indent=2))
    kube(['create', '-f', '-'], app)
    ui = None
    state = None
    try:
        for _ in range(120):
            guard.check()
            state = kube(['-n', 'default', 'get', 'sparkapplication', name, '-o', 'json'])
            (evidence / 'application-status.json').write_text(json.dumps(state, indent=2))
            pod = state.get('status', {}).get('driverInfo', {}).get('podName')
            status = state.get('status', {}).get('applicationState', {}).get('state')
            if pod and ui is None and status == 'RUNNING':
                try:
                    ui = kube(['get', '--raw',
                               f'/api/v1/namespaces/default/pods/{pod}:4040/proxy/api/v1/applications'])
                    if not isinstance(ui, list) or not ui:
                        ui = None
                    else:
                        (evidence / 'driver-ui.json').write_text(json.dumps(ui, indent=2))
                        (evidence / 'ui-access.txt').write_text(
                            'UI is live only while the Driver is running. From the Mac run:\n'
                            f"ssh -t -L 4040:127.0.0.1:4040 192.168.1.58 "
                            f"'sudo kubectl -n default port-forward pod/{pod} 4040:4040'\n"
                            'Then open http://127.0.0.1:4040\n')
                except Exception:
                    ui = None
            if status in ['COMPLETED', 'FAILED', 'SUBMISSION_FAILED']:
                break
            time.sleep(3)
        else:
            raise RuntimeError('Spark exceeded the bounded acceptance deadline')
        pod = state.get('status', {}).get('driverInfo', {}).get('podName')
        if not pod:
            raise RuntimeError('Spark did not create a driver')
        logs = str(kube(['-n', 'default', 'logs', pod, '--tail=400']))
        (evidence / 'driver.log').write_text(logs)
        if status != 'COMPLETED':
            raise RuntimeError('Spark application failed: ' + str(state.get('status', {}).get('applicationState')))
        matches = [line.split('CLINIC_RESULT:', 1)[1] for line in logs.splitlines()
                   if 'CLINIC_RESULT:' in line]
        if len(matches) != 1 or ui is None:
            raise RuntimeError('Spark result or live Driver UI evidence is missing')
        result = json.loads(matches[0])
        result['sparkApplication'] = name
        result['driverPod'] = pod
        result['driverUiVerified'] = True
        (evidence / 'result.json').write_text(json.dumps(result, indent=2))
        return result
    finally:
        kube(['-n', 'default', 'delete', 'sparkapplication', name,
              '--ignore-not-found', '--wait=false'])
        for _ in range(50):
            active = [p for p in kube(['-n', 'default', 'get', 'pods', '-o', 'json'])['items']
                      if p['metadata'].get('labels', {}).get('acceptance') == name
                      and p['status']['phase'] not in ['Succeeded', 'Failed']]
            if not active:
                break
            time.sleep(3)
        else:
            raise RuntimeError('Spark Driver or Executor remains active')


def run(evidence, start, end, repeats):
    root = Path(__file__).parent
    evidence = Path(evidence)
    evidence.mkdir(parents=True, exist_ok=True)
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    batch_id = f'petclinic-spark-{start}-{end}-{stamp}'.lower()
    base_name = 'petclinic-spark-' + datetime.datetime.now().strftime('%H%M%S')
    config_map = base_name + '-snapshot'

    with HeavyRun('spark-snapshot', 4096, evidence) as guard:
        guard.compute_stopped = False
        created_config = False
        try:
            wait_operator(guard)
            text = remote(
                "sudo -n kubectl exec -n ns-data deploy/postgresql -- psql -U postgres -d petclinic "
                "-Atc \"SET statement_timeout='5s'; COPY (SELECT v.id AS visit_id,v.visit_date,"
                "v.pet_id,t.name AS pet_type FROM public.visits v JOIN public.pets p ON p.id=v.pet_id "
                "JOIN public.types t ON t.id=p.type_id ORDER BY v.id LIMIT 5001) "
                "TO STDOUT WITH CSV HEADER;\"")
            lines = [line for line in text.splitlines() if line != 'SET']
            rows = list(csv.DictReader(io.StringIO('\n'.join(lines))))
            if not 0 < len(rows) <= 5000:
                raise RuntimeError('Source snapshot is empty or exceeds 5000 rows')
            ids = [int(row['visit_id']) for row in rows]
            if len(ids) != len(set(ids)):
                raise RuntimeError('Source snapshot contains duplicate visit IDs')
            snapshot = '\n'.join(lines) + '\n'
            snapshot_sha = hashlib.sha256(snapshot.encode()).hexdigest()
            proof = {
                'batchId': batch_id, 'inputRows': len(rows), 'uniqueVisitIds': len(set(ids)),
                'windowStart': start, 'windowEnd': end,
                'sourceMinimumDate': min(row['visit_date'] for row in rows),
                'sourceMaximumDate': max(row['visit_date'] for row in rows),
                'snapshotSha256': snapshot_sha, 'sourceKind': 'demo',
                'capturedAt': datetime.datetime.now(datetime.timezone.utc).isoformat(),
            }
            (evidence / 'snapshot-proof.json').write_text(json.dumps(proof, indent=2))
            baseline_first = baseline(batch_id, snapshot_sha, rows, start, end)
            (evidence / 'mysql-baseline.json').write_text(json.dumps(baseline_first, indent=2))
            kube(['create', '-f', '-'], {
                'apiVersion': 'v1', 'kind': 'ConfigMap',
                'metadata': {'name': config_map, 'namespace': 'default',
                             'labels': {'app': 'petclinic-analysis', 'batch': batch_id}},
                'data': {'visits.csv': snapshot,
                         'clinic_snapshot.py': (root / 'spark/clinic_snapshot.py').read_text()},
            })
            created_config = True
            results = []
            for index in range(1, repeats + 1):
                result = one_application(f'{base_name}-{index}', config_map, batch_id,
                                         start, end, evidence / f'run-{index}', guard)
                for field in ('inputRows', 'uniqueVisitIds', 'windowVisits',
                              'sourceMinimumDate', 'sourceMaximumDate'):
                    if result[field] != baseline_first[field]:
                        raise RuntimeError(f'Spark and MySQL baseline differ for {field}')
                if result['visitsByPetType'] != baseline_first['visitsByPetType']:
                    raise RuntimeError('Spark and MySQL pet-type summaries differ')
                results.append(result)
            baseline_repeat = baseline(batch_id, snapshot_sha, rows, start, end)
            if baseline_repeat != baseline_first:
                raise RuntimeError('Repeated MySQL baseline load changed the immutable result')
            output = {'batchId': batch_id, 'snapshot': proof, 'mysql': baseline_first,
                      'sparkRuns': results, 'idempotentReplay': True}
            (evidence / 'acceptance.json').write_text(json.dumps(output, indent=2))
            print(json.dumps({'batchId': batch_id,
                              'applications': [r['sparkApplication'] for r in results],
                              'applicationIds': [r['applicationId'] for r in results],
                              'jobIds': [r['jobIds'] for r in results],
                              'inputRows': results[0]['inputRows'],
                              'windowVisits': results[0]['windowVisits'],
                              'mysqlMatched': True, 'idempotentReplay': True}), flush=True)
        finally:
            if created_config:
                kube(['-n', 'default', 'delete', 'configmap', config_map,
                      '--ignore-not-found', '--wait=false'])
            active = [p for p in kube(['-n', 'default', 'get', 'pods', '-o', 'json'])['items']
                      if p['metadata'].get('labels', {}).get('batch') == batch_id
                      and p['status']['phase'] not in ['Succeeded', 'Failed']]
            if active:
                raise RuntimeError('Spark batch compute remains active; retain heavy Lease')
            guard.compute_stopped = True


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--evidence', required=True)
    parser.add_argument('--from', dest='start', required=True)
    parser.add_argument('--to', dest='end', required=True)
    parser.add_argument('--repeats', type=int, default=2, choices=[1, 2])
    args = parser.parse_args()
    run(args.evidence, args.start, args.end, args.repeats)
