"""Bounded, append-only visit analysis; no patient names, notes or addresses.

The current Visit controller creates records; no update/delete watermark exists.
If that contract changes, add CDC or updated_at before claiming incremental edits.
"""
import argparse
import csv
import datetime as dt
import hashlib
import io
import json
import os
import time
import urllib.request

MAX_ROWS = 5000
SPARK_IMAGE = ('127.0.0.1:30050/platform-upgrade/spark-runtime@'
               'sha256:711ace285d47914adfeec1a4db16d30632cade0717c971e9049d4adf59dcb500')
LEASE_NAMESPACE = 'data-infra'
LEASE_NAME = 'platform-heavy'


def connect():
    import psycopg2
    return psycopg2.connect(host=os.environ['ANALYTICS_DB_HOST'],
                            dbname=os.environ.get('ANALYTICS_DB_NAME', 'petclinic'),
                            user=os.environ['ANALYTICS_DB_USER'],
                            password=os.environ['ANALYTICS_DB_PASSWORD'],
                            connect_timeout=8,
                            options='-c statement_timeout=5000 -c lock_timeout=3000')


def window(start, end):
    first, last = dt.date.fromisoformat(start), dt.date.fromisoformat(end)
    if not 0 <= (last - first).days <= 365:
        raise ValueError('The inclusive analysis window must be 1..366 days')
    return first, last


def snapshot_identity(source_sha256, counts, types):
    identity = {'visits_sha256': source_sha256, 'counts': counts,
                'pet_types': sorted(types, key=lambda item: item['name'])}
    return hashlib.sha256(json.dumps(identity, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def extract(start, end):
    first, last = window(start, end)
    with connect() as db:
        db.set_session(readonly=True, isolation_level='REPEATABLE READ')
        with db.cursor() as cur:
            cur.execute('SELECT COALESCE(MAX(visit_id),0) FROM petclinic_analytics.visit_facts')
            watermark = cur.fetchone()[0]
            counts = {}
            for table in ('owners', 'pets', 'vets', 'visits'):
                cur.execute(f'SELECT count(*) FROM (SELECT id FROM public.{table} LIMIT %s) bounded', (MAX_ROWS + 1,))
                counts[table] = cur.fetchone()[0]
                if counts[table] > MAX_ROWS:
                    raise ValueError(f'{table} exceeds approved {MAX_ROWS}-row snapshot budget')
            cur.execute('''SELECT v.id,v.visit_date,v.pet_id,(p.id IS NOT NULL)
                           FROM public.visits v LEFT JOIN public.pets p ON p.id=v.pet_id
                           WHERE v.id > %s ORDER BY v.id LIMIT %s''', (watermark, MAX_ROWS + 1))
            visits = [{'id': row[0], 'date': row[1].isoformat() if row[1] else None,
                       'pet_id': row[2], 'pet_exists': row[3]} for row in cur.fetchall()]
            cur.execute('''SELECT t.name,count(*) FROM public.pets p JOIN public.types t ON p.type_id=t.id
                           GROUP BY t.name ORDER BY t.name LIMIT 65''')
            types = [{'name': row[0], 'pets': row[1]} for row in cur.fetchall()]
            cur.execute('''SELECT count(*) FROM public.pets p LEFT JOIN public.types t ON p.type_id=t.id
                           WHERE t.id IS NULL''')
            missing_type = cur.fetchone()[0]
            cur.execute('''SELECT v.id,v.visit_date,v.pet_id,t.name
                           FROM public.visits v JOIN public.pets p ON p.id=v.pet_id
                           JOIN public.types t ON t.id=p.type_id ORDER BY v.id LIMIT %s''', (MAX_ROWS + 1,))
            source = io.StringIO()
            writer = csv.writer(source, lineterminator='\n')
            writer.writerow(['visit_id', 'visit_date', 'pet_id', 'pet_type'])
            writer.writerows((r[0], r[1].isoformat(), r[2], r[3]) for r in cur.fetchall())
            source_sha256 = hashlib.sha256(source.getvalue().encode()).hexdigest()
    return {'window_start': str(first), 'window_end': str(last), 'watermark': watermark,
            'counts': counts, 'visits': visits, 'types': types, 'missing_type': missing_type,
            'source_sha256': source_sha256,
            'source_metadata_sha256': snapshot_identity(source_sha256, counts, types)}


def quality(batch):
    window(batch['window_start'], batch['window_end'])
    visits = batch['visits']
    if len(visits) > MAX_ROWS or len(batch['types']) > 64:
        raise ValueError('Input exceeds approved bounded budget')
    ids = [v['id'] for v in visits]
    if len(ids) != len(set(ids)):
        raise ValueError('Duplicate visit IDs')
    if batch['missing_type'] or sum(t['pets'] for t in batch['types']) != batch['counts']['pets']:
        raise ValueError('Pet type dimensions do not reconcile')
    for v in visits:
        if not v['date'] or not v['pet_exists'] or not v['pet_id'] or v['id'] <= batch['watermark']:
            raise ValueError('Missing date, foreign key or invalid incremental watermark')
        dt.date.fromisoformat(v['date'])
    return batch


def publish(batch, run_id, publication_status='success'):
    from psycopg2.extras import execute_values
    if not run_id or len(run_id) > 200:
        raise ValueError('Invalid analysis run ID')
    if publication_status not in ('success', 'pending'):
        raise ValueError('Unsupported publication status')
    kind = os.environ.get('ANALYTICS_SOURCE_KIND', '')
    if kind not in ('demo', 'business'):
        raise ValueError('Explicit demo/business provenance is required')
    started = time.monotonic()
    with connect() as db:
        with db.cursor() as cur:
            # One writer across Airflow and manual tasks; publication is atomic.
            cur.execute('SELECT pg_try_advisory_xact_lock(761011)')
            if not cur.fetchone()[0]:
                raise RuntimeError('Another Petclinic analysis is active')
            cur.execute('''SELECT window_start,window_end,source_kind,owners,pets,vets,visits,watermark
                           FROM petclinic_analytics.runs WHERE run_id=%s''', (run_id,))
            prior = cur.fetchone()
            if prior:
                if (str(prior[0]),str(prior[1]),prior[2]) != (batch['window_start'],batch['window_end'],kind):
                    raise ValueError('Cannot reuse an immutable run ID for a different window/source')
                result = {'event':'analysis_success','run_id':run_id,'idempotent_replay':True,
                          'counts':dict(zip(('owners','pets','vets','visits'),prior[3:7])),
                          'watermark':prior[7],'new_input_rows':0}
                print(json.dumps(result), flush=True)
                return result
            if batch['visits']:
                execute_values(cur, '''INSERT INTO petclinic_analytics.visit_facts (visit_id,visit_date,pet_id)
                                      VALUES %s ON CONFLICT (visit_id) DO NOTHING''',
                               [(v['id'], v['date'], v['pet_id']) for v in batch['visits']], page_size=500)
            cur.execute('SELECT count(*),COALESCE(MAX(visit_id),0) FROM petclinic_analytics.visit_facts')
            facts, watermark = cur.fetchone()
            if facts != batch['counts']['visits']:
                raise ValueError('Incremental facts do not reconcile with the source snapshot; publication rolled back')
            counts = batch['counts']
            cur.execute('''INSERT INTO petclinic_analytics.runs
                        (run_id,generated_at,window_start,window_end,source_kind,owners,pets,vets,visits,watermark,input_rows,status)
                        VALUES (%s,now(),%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                        ON CONFLICT (run_id) DO UPDATE SET generated_at=EXCLUDED.generated_at,
                        owners=EXCLUDED.owners,pets=EXCLUDED.pets,vets=EXCLUDED.vets,visits=EXCLUDED.visits,
                        watermark=EXCLUDED.watermark,input_rows=EXCLUDED.input_rows''',
                        (run_id,batch['window_start'],batch['window_end'],kind,counts['owners'],
                         counts['pets'],counts['vets'],counts['visits'],watermark,len(batch['visits']),publication_status))
            cur.execute('''INSERT INTO petclinic_analytics.daily_visits (run_id,stat_date,visits)
                           SELECT %s,visit_date,count(*) FROM petclinic_analytics.visit_facts
                           WHERE visit_date BETWEEN %s AND %s GROUP BY visit_date
                           ON CONFLICT (run_id,stat_date) DO UPDATE SET visits=EXCLUDED.visits''',
                        (run_id,batch['window_start'],batch['window_end']))
            if batch['types']:
                execute_values(cur, '''INSERT INTO petclinic_analytics.pet_types (run_id,type,pets)
                                      VALUES %s ON CONFLICT (run_id,type) DO UPDATE SET pets=EXCLUDED.pets''',
                               [(run_id,t['name'],t['pets']) for t in batch['types']])
            cur.execute('SELECT COALESCE(sum(visits),0) FROM petclinic_analytics.daily_visits WHERE run_id=%s', (run_id,))
            window_visits = int(cur.fetchone()[0])
    result = {'event': 'analysis_success', 'run_id': run_id, 'source_kind': kind,
              'counts': counts, 'window_visits': window_visits, 'new_input_rows': len(batch['visits']),
              'watermark': watermark, 'duration_seconds': round(time.monotonic()-started, 3)}
    print(json.dumps(result), flush=True)
    return result


def _kube():
    from kubernetes import client, config
    config.load_incluster_config()
    return client.CoreV1Api(), client.AppsV1Api(), client.CustomObjectsApi(), client.CoordinationV1Api()


def check_resources(baseline=None):
    core, _, _, coordination = _kube()
    measured = core.read_namespaced_config_map('platform-host-resources', 'data-infra')
    value = json.loads(measured.data['sample.json'])
    if not 0 <= time.time() - value['at'] <= 90:
        raise RuntimeError('Host/VM resource measurement is stale; stop compute safely')
    if baseline is None:
        lease = coordination.read_namespaced_lease(LEASE_NAME, LEASE_NAMESPACE)
        baseline = json.loads((lease.metadata.annotations or {}).get(
            'petclinic.devops.local/guard-baseline', '{}'))
    mac = value.get('mac') or {}
    reasons = []
    if mac.get('diskFreeMiB', 0) < 8192 or value['diskFreeMiB'] < 8192:
        reasons.append('host or VM disk below 8 GiB')
    if mac.get('freePercent', 0) < 10:
        reasons.append('Mac free memory below 10 percent')
    if mac.get('swapUsedMiB', 0) - baseline.get('macSwapMiB', mac.get('swapUsedMiB', 0)) > 512:
        reasons.append('Mac swap grew by more than 512 MiB')
    if value['availableMiB'] < 1536:
        reasons.append('VM MemAvailable below 1536 MiB')
    if value['pressure']['memory']['full']['avg10'] > 5 or value['pressure']['io']['full']['avg10'] > 10:
        reasons.append('VM memory or I/O full PSI exceeded its stop threshold')
    if not value['apiReady'] or value.get('consecutiveBadHttp', 0) >= 3:
        reasons.append('API or repeated business checks failed')
    for condition in value['conditions']:
        if condition['type'] == 'Ready' and condition['status'] != 'True':
            reasons.append('devops is not Ready')
        if condition['type'].endswith('Pressure') and condition['status'] == 'True':
            reasons.append(condition['type'])
    prior = baseline.get('failures', value['failures'])
    if any(failure not in prior for failure in value['failures']):
        reasons.append('new OOM or eviction')
    if reasons:
        raise RuntimeError('Resource safety stop: ' + '; '.join(reasons))
    return value


def _selector_pod(namespace, deployment):
    core, apps, _, _ = _kube()
    labels = apps.read_namespaced_deployment(deployment, namespace).spec.selector.match_labels
    selector = ','.join(f'{key}={value}' for key, value in labels.items())
    pods = [pod for pod in core.list_namespaced_pod(namespace, label_selector=selector).items
            if pod.status.phase == 'Running']
    if not pods:
        raise RuntimeError(f'No running pod for {namespace}/{deployment}')
    return pods[0].metadata.name


def finite_input(command, body):
    import base64
    payload = body.encode()
    if len(payload) > 512 * 1024:
        raise ValueError('Remote exec input exceeds the 512 KiB bound')
    encoded = base64.b64encode(payload).decode()
    chunks = [encoded[i:i + 32768] for i in range(0, len(encoded), 32768)]
    # Linux also limits each argument to 128 KiB, independently of ARG_MAX.
    # printf is a shell builtin; a finite pipe supplies portable stdin EOF.
    script = ('count="$1"; shift; payload=""; while [ "$count" -gt 0 ]; do '
              'payload="$payload$1"; shift; count=$((count-1)); done; '
              'printf %s "$payload" | base64 -d | "$@"')
    return ['sh', '-c', script, 'petclinic-exec', str(len(chunks)), *chunks, *command]


def _exec(namespace, deployment, command, body=None, timeout=90, pod=None):
    from kubernetes.stream import stream
    core, _, _, _ = _kube()
    pod = pod or _selector_pod(namespace, deployment)
    if body is not None:
        command = finite_input(command, body)
    channel = stream(core.connect_get_namespaced_pod_exec, pod, namespace, command=command,
                     stderr=True, stdin=False, stdout=True, tty=False,
                     _preload_content=False, _request_timeout=timeout)
    output = ''
    deadline = time.monotonic() + timeout
    next_probe = time.monotonic() + 15
    while channel.is_open() and time.monotonic() < deadline:
        if time.monotonic() >= next_probe:
            try:
                check_resources()
            except Exception:
                channel.close()
                raise
            next_probe = time.monotonic() + 15
        channel.update(timeout=1)
        if channel.peek_stdout():
            output += channel.read_stdout()
        if channel.peek_stderr():
            output += channel.read_stderr()
    if channel.is_open():
        channel.close()
        raise TimeoutError(f'Remote exec exceeded {timeout} seconds')
    code = channel.returncode
    channel.close()
    if code != 0:
        raise RuntimeError(f'Remote exec failed with code {code}: {output[-1500:]}')
    return output


def _code(name):
    core, _, _, _ = _kube()
    data = core.read_namespaced_config_map('petclinic-analysis-code', 'data-infra').data or {}
    if name not in data:
        raise RuntimeError(f'Analysis ConfigMap is missing {name}')
    return data[name]


def _jenkins(path, method='GET'):
    allowed = {'/api/json?tree=quietingDown,jobs[name,lastBuild[building]]',
               '/quietDown', '/cancelQuietDown'}
    if path not in allowed:
        raise ValueError('Unsupported Jenkins resource operation')
    script = r"""const fs=require('fs');(async()=>{const i=JSON.parse(fs.readFileSync(0,'utf8'));
const h={Authorization:'Basic '+Buffer.from(process.env.JENKINS_USER+':'+process.env.JENKINS_PASS).toString('base64')};
if(i.method==='POST'){const q=await fetch(process.env.JENKINS_URL+'/crumbIssuer/api/json',{headers:h});
const c=await q.json();h[c.crumbRequestField]=c.crumb;h.Cookie=q.headers.getSetCookie().map(x=>x.split(';')[0]).join('; ')}
const r=await fetch(process.env.JENKINS_URL+i.path,{method:i.method,headers:h,signal:AbortSignal.timeout(12000)});
if(!r.ok)throw Error('HTTP '+r.status);console.log(await r.text())})().catch(e=>{console.error(e.message);process.exit(1)})"""
    output = _exec('ns-devops', 'github-webhook-relay',
                   ['node', '--max-old-space-size=24', '-e', script],
                   json.dumps({'path': path, 'method': method}), 40)
    return json.loads(output) if output.strip().startswith('{') else output.strip()


def _execution(batch_id, stage, status=None, **values):
    columns = {'spark_application', 'spark_application_id', 'flink_job_id',
               'kafka_input_topic', 'kafka_output_topic', 'kafka_consumer_group',
               'trino_query_id', 'superset_chart_id', 'error'}
    invalid = set(values) - columns
    if invalid:
        raise ValueError(f'Unsupported execution fields: {invalid}')
    assignments = ['stage=%s', 'updated_at=now()']
    params = [stage]
    if status:
        assignments.append('status=%s')
        params.append(status)
        if status in ('success', 'failed'):
            assignments.append('finished_at=now()')
    for key, value in values.items():
        assignments.append(f'{key}=%s')
        params.append(value)
    params.append(batch_id)
    with connect() as db, db.cursor() as cur:
        cur.execute(f"UPDATE petclinic_analytics.executions SET {','.join(assignments)} WHERE batch_id=%s", params)


def acquire_guard(start, end, dag_run_id):
    window(start, end)
    core, _, _, coordination = _kube()
    node = core.read_node('devops')
    if not any(c.type == 'Ready' and c.status == 'True' for c in node.status.conditions):
        raise RuntimeError('devops node is not Ready')
    measured = check_resources({})
    available = measured['availableMiB']
    # Airflow is already running here and included in MemAvailable. Reserve the
    # remaining 4096 MiB compute, 768 MiB task and 1250 MiB safety allowance.
    if available < 6114:
        raise RuntimeError(f'Available memory {available:.0f} MiB is below the 6114 MiB remaining-task budget')
    holder = 'airflow:' + hashlib.sha256(dag_run_id.encode()).hexdigest()[:24]
    now = dt.datetime.now(dt.timezone.utc)
    from kubernetes import client
    lease = client.V1Lease(metadata=client.V1ObjectMeta(name=LEASE_NAME, namespace=LEASE_NAMESPACE,
                           annotations={'petclinic.devops.local/budget-mib': '8192',
                                        'petclinic.devops.local/guard-baseline': json.dumps({
                                            'macSwapMiB': measured['mac']['swapUsedMiB'],
                                            'failures': measured['failures']})}),
                           spec=client.V1LeaseSpec(holder_identity=holder, acquire_time=now,
                                                  renew_time=now, lease_duration_seconds=3600))
    try:
        made = coordination.create_namespaced_lease(LEASE_NAMESPACE, lease)
    except client.exceptions.ApiException as error:
        if error.status != 409:
            raise
        made = coordination.read_namespaced_lease(LEASE_NAME, LEASE_NAMESPACE)
        if made.spec.holder_identity != holder:
            raise RuntimeError(f'Heavy resource lock is held by {made.spec.holder_identity}')
    owned_quiet = False
    try:
        state = _jenkins('/api/json?tree=quietingDown,jobs[name,lastBuild[building]]')
        owned_quiet = not state.get('quietingDown', False)
        if owned_quiet:
            _jenkins('/quietDown', 'POST')
        state = _jenkins('/api/json?tree=quietingDown,jobs[name,lastBuild[building]]')
        active = [job['name'] for job in state.get('jobs', []) if (job.get('lastBuild') or {}).get('building')]
        if active:
            raise RuntimeError(f'Jenkins still has active builds: {active}')
    except Exception:
        if owned_quiet:
            try:
                _jenkins('/cancelQuietDown', 'POST')
            except Exception:
                pass
        coordination.delete_namespaced_lease(LEASE_NAME, LEASE_NAMESPACE)
        raise
    return {'holder': holder, 'lease_uid': made.metadata.uid, 'owned_quiet': owned_quiet,
            'dag_run_id': dag_run_id, 'from': start, 'to': end,
            'available_mib': round(available, 2)}


def create_snapshot(guard):
    with connect() as db:
        db.set_session(readonly=True, isolation_level='REPEATABLE READ')
        with db.cursor() as cur:
            cur.execute('''SELECT v.id,v.visit_date,v.pet_id,t.name
                           FROM public.visits v JOIN public.pets p ON p.id=v.pet_id
                           JOIN public.types t ON t.id=p.type_id ORDER BY v.id LIMIT %s''', (MAX_ROWS + 1,))
            rows = cur.fetchall()
            cur.execute('SELECT count(*) FROM public.owners'); owners = cur.fetchone()[0]
            cur.execute('SELECT count(*) FROM public.pets'); pets = cur.fetchone()[0]
            cur.execute('SELECT count(*) FROM public.vets'); vets = cur.fetchone()[0]
            cur.execute('''SELECT t.name,count(*) FROM public.pets p JOIN public.types t ON t.id=p.type_id
                           GROUP BY t.name ORDER BY t.name LIMIT 65''')
            types = [{'name': row[0], 'pets': row[1]} for row in cur.fetchall()]
    if not 0 < len(rows) <= MAX_ROWS:
        raise RuntimeError('Bounded visit snapshot is empty or exceeds 5000 rows')
    buffer = io.StringIO(); writer = csv.writer(buffer, lineterminator='\n')
    writer.writerow(['visit_id', 'visit_date', 'pet_id', 'pet_type'])
    writer.writerows((row[0], row[1].isoformat(), row[2], row[3]) for row in rows)
    text = buffer.getvalue(); digest = hashlib.sha256(text.encode()).hexdigest()
    counts = {'owners': owners, 'pets': pets, 'vets': vets, 'visits': len(rows)}
    if any(count > MAX_ROWS for count in counts.values()) or len(types) > 64:
        raise ValueError('Snapshot dimensions exceed the approved row budget')
    metadata_digest = snapshot_identity(digest, counts, types)
    batch_id = f"petclinic-{guard['from']}-{guard['to']}-{metadata_digest[:12]}"
    execution_id = hashlib.sha256(guard['dag_run_id'].encode()).hexdigest()[:12]
    name = 'petclinic-' + digest[:20]
    core, _, _, _ = _kube()
    from kubernetes import client
    data = {'visits.csv': text, 'clinic_snapshot.py': _code('clinic_snapshot.py')}
    body = client.V1ConfigMap(metadata=client.V1ObjectMeta(name=name, namespace='default',
                              labels={'app': 'petclinic-analysis', 'batch': batch_id,
                                      'airflow-holder': guard['holder'].replace(':', '-')}), data=data)
    try:
        core.create_namespaced_config_map('default', body)
    except client.exceptions.ApiException as error:
        if error.status != 409:
            raise
        current = core.read_namespaced_config_map(name, 'default')
        if (current.metadata.labels or {}).get('airflow-holder') != guard['holder'].replace(':', '-'):
            raise RuntimeError('Snapshot ConfigMap belongs to another execution; preserve it for inspection')
        if current.data != data:
            raise RuntimeError('Immutable snapshot ConfigMap name collision')
    with connect() as db, db.cursor() as cur:
        cur.execute('''INSERT INTO petclinic_analytics.executions
                    (batch_id,dag_run_id,window_start,window_end,status,stage,attempt)
                    VALUES (%s,%s,%s,%s,'running','snapshot',1)
                    ON CONFLICT (batch_id) DO UPDATE SET dag_run_id=EXCLUDED.dag_run_id,
                    status='running',stage='snapshot',started_at=now(),finished_at=NULL,error=NULL,
                    attempt=petclinic_analytics.executions.attempt+1,updated_at=now()''',
                    (batch_id, guard['dag_run_id'], guard['from'], guard['to']))
    return {'batch_id': batch_id, 'config_map': name, 'sha256': digest, 'input_rows': len(rows),
            'source_metadata_sha256': metadata_digest,
            'unique_visit_ids': len({row[0] for row in rows}), 'owners': owners, 'pets': pets,
            'vets': vets, 'execution_id': execution_id, 'holder': guard['holder'],
            'minimum_date': min(row[1] for row in rows).isoformat(),
            'maximum_date': max(row[1] for row in rows).isoformat()}


def validate_snapshot(snapshot, start, end, fail_probe=False, try_number=1):
    if fail_probe and try_number == 1:
        raise RuntimeError('Controlled first-attempt orchestration failure')
    if snapshot['input_rows'] != snapshot['unique_visit_ids']:
        raise ValueError('Snapshot visit IDs are not unique')
    core, _, _, _ = _kube()
    text = core.read_namespaced_config_map(snapshot['config_map'], 'default').data['visits.csv']
    rows = list(csv.DictReader(io.StringIO(text)))
    if hashlib.sha256(text.encode()).hexdigest() != snapshot['sha256'] or len(rows) != snapshot['input_rows']:
        raise ValueError('Snapshot content does not match its immutable metadata')
    window_rows = [row for row in rows if start <= row['visit_date'] <= end]
    by_type = {}
    for row in window_rows:
        by_type[row['pet_type']] = by_type.get(row['pet_type'], 0) + 1
    # MySQL runs the independent baseline query in its existing pod. Credentials stay in that pod.
    quote = lambda value: "'" + str(value).replace("'", "''") + "'"
    values = ','.join(f"({quote(snapshot['batch_id'])},{r['visit_id']},{quote(r['visit_date'])},{r['pet_id']},{quote(r['pet_type'])},{quote(snapshot['sha256'])})" for r in rows)
    sql = f'''CREATE DATABASE IF NOT EXISTS petclinic_analytics_baseline;
CREATE TABLE IF NOT EXISTS petclinic_analytics_baseline.snapshot_visits
(batch_id VARCHAR(96),visit_id BIGINT,visit_date DATE,pet_id BIGINT,pet_type VARCHAR(64),snapshot_sha CHAR(64),PRIMARY KEY(batch_id,visit_id));
INSERT INTO petclinic_analytics_baseline.snapshot_visits VALUES {values}
ON DUPLICATE KEY UPDATE visit_date=VALUES(visit_date),pet_id=VALUES(pet_id),pet_type=VALUES(pet_type),snapshot_sha=VALUES(snapshot_sha);
SELECT 'counts',COUNT(*),COUNT(DISTINCT visit_id),SUM(visit_date BETWEEN {quote(start)} AND {quote(end)})
FROM petclinic_analytics_baseline.snapshot_visits WHERE batch_id={quote(snapshot['batch_id'])};
SELECT 'type',pet_type,COUNT(*) FROM petclinic_analytics_baseline.snapshot_visits
WHERE batch_id={quote(snapshot['batch_id'])} AND visit_date BETWEEN {quote(start)} AND {quote(end)}
GROUP BY pet_type ORDER BY pet_type;'''
    result = _exec('ns-data', 'mysql', ['sh', '-lc', 'MYSQL_PWD="$MYSQL_ROOT_PASSWORD" mysql -uroot --batch --raw --skip-column-names'], sql, 90)
    last = next(line.split('\t')[1:] for line in result.splitlines() if line.startswith('counts\t'))
    mysql = {'input_rows': int(last[0]), 'unique_visit_ids': int(last[1]), 'window_visits': int(last[2])}
    mysql_types = {parts[1]: int(parts[2]) for line in result.splitlines()
                   if (parts := line.split('\t'))[0] == 'type'}
    expected = {'input_rows': len(rows), 'unique_visit_ids': len({r['visit_id'] for r in rows}),
                'window_visits': len(window_rows)}
    if mysql != expected or mysql_types != by_type:
        raise ValueError(f'MySQL baseline mismatch: {mysql} != {expected}')
    _execution(snapshot['batch_id'], 'validated')
    return {**expected, 'visits_by_pet_type': [{'type': key, 'visits': by_type[key]} for key in sorted(by_type)],
            'visits_by_type': mysql_types, 'window_start': start, 'window_end': end,
            'mysql': mysql}


def submit_spark(snapshot, start, end):
    _, _, custom, _ = _kube()
    name = 'petclinic-airflow-' + snapshot['execution_id']
    role = {'cores': 1, 'coreLimit': '1000m', 'memory': '512m', 'memoryOverhead': '512m',
            'labels': {'app': 'petclinic-analysis', 'batch': snapshot['batch_id'],
                       'execution': snapshot['execution_id']},
            'volumeMounts': [{'name': 'snapshot', 'mountPath': '/opt/clinic', 'readOnly': True}],
            'securityContext': {'runAsUser': 185, 'runAsGroup': 185, 'runAsNonRoot': True,
                                'allowPrivilegeEscalation': False, 'capabilities': {'drop': ['ALL']}}}
    body = {'apiVersion': 'sparkoperator.k8s.io/v1beta2', 'kind': 'SparkApplication',
            'metadata': {'name': name, 'namespace': 'default',
                         'labels': {'app': 'petclinic-analysis', 'batch': snapshot['batch_id'],
                                    'execution': snapshot['execution_id']}},
            'spec': {'type': 'Python', 'pythonVersion': '3', 'mode': 'cluster', 'image': SPARK_IMAGE,
                     'imagePullPolicy': 'IfNotPresent', 'sparkVersion': '4.0.1',
                     'mainApplicationFile': 'local:///opt/clinic/clinic_snapshot.py',
                     'arguments': ['--from', start, '--to', end, '--batch-id', snapshot['batch_id'],
                                   '--ui-hold-seconds', '45'],
                     'restartPolicy': {'type': 'Never'}, 'timeToLiveSeconds': 900,
                     'nodeSelector': {'kubernetes.io/hostname': 'devops'},
                     'sparkConf': {'spark.sql.shuffle.partitions': '1', 'spark.default.parallelism': '1',
                                   'spark.ui.enabled': 'true', 'spark.driver.maxResultSize': '64m'},
                     'volumes': [{'name': 'snapshot', 'configMap': {'name': snapshot['config_map']}}],
                     'driver': {**role, 'serviceAccount': 'spark-operator-spark'},
                     'executor': {**role, 'instances': 1}}}
    try:
        custom.create_namespaced_custom_object('sparkoperator.k8s.io', 'v1beta2', 'default',
                                               'sparkapplications', body)
    except Exception as error:
        if getattr(error, 'status', None) != 409:
            raise
        raise RuntimeError(f'SparkApplication {name} already exists for this DAG run') from error
    _execution(snapshot['batch_id'], 'spark-submitted', spark_application=name)
    return name


def verify_spark(snapshot, baseline, application):
    core, _, custom, _ = _kube()
    app = custom.get_namespaced_custom_object('sparkoperator.k8s.io', 'v1beta2', 'default',
                                              'sparkapplications', application)
    state = app.get('status', {}).get('applicationState', {}).get('state')
    if state != 'COMPLETED':
        raise RuntimeError(f'SparkApplication terminal state is {state}')
    pod = app.get('status', {}).get('driverInfo', {}).get('podName')
    logs = core.read_namespaced_pod_log(pod, 'default', tail_lines=500)
    matches = [line.split('CLINIC_RESULT:', 1)[1] for line in logs.splitlines() if 'CLINIC_RESULT:' in line]
    if len(matches) != 1:
        raise RuntimeError('Spark driver did not emit one business result')
    result = json.loads(matches[0])
    for source, target in [('inputRows', 'input_rows'), ('uniqueVisitIds', 'unique_visit_ids'),
                           ('windowVisits', 'window_visits')]:
        if result[source] != baseline[target]:
            raise ValueError(f'Spark/MySQL mismatch for {source}')
    if {item['type']: item['visits'] for item in result['visitsByPetType']} != baseline['visits_by_type']:
        raise ValueError('Spark/MySQL visit type totals do not reconcile')
    application_id = app.get('status', {}).get('sparkApplicationId', result.get('applicationId'))
    _execution(snapshot['batch_id'], 'spark-complete', spark_application=application,
               spark_application_id=application_id)
    return {'application': application, 'application_id': application_id,
            'driver_pod': pod, 'job_ids': result.get('jobIds', []), 'result': result,
            'ui_command': f"ssh -t -L 4040:127.0.0.1:4040 192.168.1.58 'sudo kubectl -n default port-forward pod/{pod} 4040:4040'"}


def _flink_api(path, method='GET', payload=None):
    request = urllib.request.Request('http' + '://flink-jobmanager.ns-bigdata:8081' + path,
                                     data=None if payload is None else json.dumps(payload).encode(),
                                     method=method, headers={'Content-Type': 'application/json'})
    with urllib.request.urlopen(request, timeout=12) as response:
        text = response.read().decode()
    return json.loads(text) if text else {}


def run_flink_bounded(snapshot, baseline, fail_probe='none', try_number=1):
    core, apps, _, _ = _kube()
    input_topic, output_topic, group = ('petclinic-window-092657-input',
                                         'petclinic-window-092657-output',
                                         'petclinic-airflow-window-v1')
    jobs = []
    owned = []
    client_pod = 'petclinic-flink-sql-' + snapshot['execution_id']
    created_client = False

    def topic_end(topic):
        result = _exec('ns-bigdata', 'kafka', ['env', 'KAFKA_HEAP_OPTS=-Xms32M -Xmx128M',
                       '/opt/kafka/bin/kafka-get-offsets.sh', '--bootstrap-server', 'localhost:9092',
                       '--topic', topic])
        return {int(parts[1]): int(parts[2]) for line in result.splitlines()
                if len(parts := line.split(':')) == 3 and parts[0] == topic}

    try:
        for name in ('flink-jobmanager', 'flink-taskmanager'):
            deployment = apps.read_namespaced_deployment(name, 'ns-bigdata')
            if deployment.spec.replicas != 0 or (deployment.status.replicas or 0) != 0:
                raise RuntimeError(f'{name} is already enabled; refusing to take over existing compute')
            apps.patch_namespaced_deployment(name, 'ns-bigdata', {'metadata': {'annotations': {
                'petclinic.devops.local/analysis-execution': snapshot['execution_id']}}})
            owned.append(name)
            apps.patch_namespaced_deployment_scale(name, 'ns-bigdata', {'spec': {'replicas': 1}})
        for _ in range(90):
            check_resources()
            if all((apps.read_namespaced_deployment(name, 'ns-bigdata').status.ready_replicas or 0) == 1
                   for name in ('flink-jobmanager', 'flink-taskmanager')):
                break
            time.sleep(4)
        else:
            raise RuntimeError('Flink core did not become Ready')
        for _ in range(30):
            check_resources()
            try:
                overview = _flink_api('/overview')
                if overview.get('slots-total', 0) == 1 and overview.get('flink-version') == '2.3.0':
                    break
            except OSError:
                pass
            time.sleep(2)
        else:
            raise RuntimeError('Flink registered no single bounded task slot')
        input_before, output_before = topic_end(input_topic), topic_end(output_topic)
        if set(input_before) != {0} or set(output_before) != {0}:
            raise RuntimeError('Existing analytics topics must retain their one-partition layout')
        sql = _code('clinic_windows.sql').replace('petclinic-snapshot-20261011', input_topic) \
            .replace('petclinic-windows-20261011', output_topic) \
            .replace('petclinic-flink-20261011', group) \
            .replace('Petclinic bounded snapshot window acceptance', 'Petclinic Airflow bounded replay windows') \
            .replace("'scan.startup.mode'='earliest-offset'",
                     "'scan.startup.mode'='specific-offsets',\n 'scan.startup.specific-offsets'='partition:0,offset:"
                     + str(input_before[0]) + "'")
        import copy
        jm = apps.read_namespaced_deployment('flink-jobmanager', 'ns-bigdata')
        spec = copy.deepcopy(core.api_client.sanitize_for_serialization(jm.spec.template.spec))
        spec['containers'] = spec['containers'][:1]
        container = spec['containers'][0]
        container['name'] = 'sql-client'
        container['command'] = ['bash', '-c']
        container['args'] = ['sleep 900']
        container['resources'] = {'requests': {'memory': '1024Mi', 'cpu': '100m'},
                                  'limits': {'memory': '1024Mi', 'cpu': '1000m'}}
        for key in ('ports', 'livenessProbe', 'readinessProbe', 'startupProbe'):
            container.pop(key, None)
        spec['automountServiceAccountToken'] = False
        spec['restartPolicy'] = 'Never'
        spec['activeDeadlineSeconds'] = 900
        core.create_namespaced_pod('ns-bigdata', {'apiVersion': 'v1', 'kind': 'Pod',
            'metadata': {'name': client_pod, 'labels': {'app': 'petclinic-analysis',
                                                      'execution': snapshot['execution_id']}},
            'spec': spec})
        created_client = True
        for _ in range(60):
            check_resources()
            pod = core.read_namespaced_pod(client_pod, 'ns-bigdata')
            if any(c.ready for c in (pod.status.container_statuses or [])):
                break
            time.sleep(2)
        else:
            raise RuntimeError('Bounded Flink SQL client did not become Ready')
        submit = _exec('ns-bigdata', 'flink-jobmanager', ['bash', '-lc',
                       "cat >/tmp/petclinic-airflow.sql; /opt/flink/bin/sql-client.sh -Djobmanager.rpc.address=flink-jobmanager -Drest.address=flink-jobmanager -Drest.port=8081 -f /tmp/petclinic-airflow.sql"],
                       "SET 'execution.target'='remote';\nSET 'execution.attached'='false';\n" + sql,
                       120, pod=client_pod)
        import re
        found = re.findall(r'Job ID:\s*([a-f0-9]{32})', submit)
        for _ in range(20):
            check_resources()
            running = [job for job in _flink_api('/jobs/overview').get('jobs', []) if job['state'] == 'RUNNING']
            if len(running) == 1:
                job_id = running[0]['jid']; jobs.append(job_id); break
            time.sleep(2)
        else:
            raise RuntimeError('No unique running Flink job after SQL submission: ' + submit[-1000:])
        _execution(snapshot['batch_id'], 'flink-running', flink_job_id=job_id,
                   kafka_input_topic=input_topic, kafka_output_topic=output_topic,
                   kafka_consumer_group=group)
        # A completed checkpoint proves the Kafka source was initialized before
        # producing this batch (a first group starts at the existing topic end).
        for _ in range(30):
            check_resources()
            if _flink_api('/jobs/' + job_id + '/checkpoints').get('counts', {}).get('completed', 0):
                break
            time.sleep(2)
        else:
            raise RuntimeError('Flink source did not initialize a checkpoint before batch publication')
        text = core.read_namespaced_config_map(snapshot['config_map'], 'default').data['visits.csv']
        rows = list(csv.DictReader(io.StringIO(text)))
        messages = '\n'.join(json.dumps({'snapshot_id': snapshot['batch_id'], 'visit_id': int(row['visit_id']),
                                           'visit_date': row['visit_date']}) for row in rows) + '\n'
        _exec('ns-bigdata', 'kafka', ['env', 'KAFKA_HEAP_OPTS=-Xms32M -Xmx128M',
              '/opt/kafka/bin/kafka-console-producer.sh', '--bootstrap-server', 'localhost:9092',
              '--topic', input_topic, '--producer-property', 'acks=all',
              '--producer-property', 'enable.idempotence=true'], messages, 90)
        input_after = topic_end(input_topic)
        if input_after[0] - input_before[0] < len(rows):
            raise RuntimeError('Kafka did not persist the complete bounded message batch')
        values = {}
        raw = ''
        offsets = ''
        for _ in range(40):
            check_resources()
            raw = _exec('ns-bigdata', 'kafka', ['sh', '-lc',
                   f'env KAFKA_HEAP_OPTS="-Xms32M -Xmx128M" /opt/kafka/bin/kafka-console-consumer.sh --bootstrap-server localhost:9092 --topic {output_topic} --partition 0 --offset {output_before[0]} --timeout-ms 4000 --max-messages 10000 --consumer-property isolation.level=read_committed --property print.key=true --property key.separator="\t" 2>/dev/null || test $? -eq 1'], timeout=20)
            read_keys = set()
            for line in raw.splitlines():
                if '\t' in line:
                    key, value = line.split('\t', 1)
                    if value not in ('', 'null'):
                        decoded = json.loads(value)
                        if decoded.get('snapshot_id') == snapshot['batch_id']:
                            if key in read_keys:
                                raise ValueError('Duplicate final processing-window key in committed Kafka output')
                            read_keys.add(key)
                            values[key] = decoded
            total = sum(int(value['visits']) for value in values.values())
            offsets = _exec('ns-bigdata', 'kafka', ['env', 'KAFKA_HEAP_OPTS=-Xms32M -Xmx128M',
                            '/opt/kafka/bin/kafka-consumer-groups.sh', '--bootstrap-server', 'localhost:9092',
                            '--describe', '--group', group])
            committed = [int(parts[3]) for line in offsets.splitlines()
                         if len(parts := line.split()) >= 5 and parts[0] == group
                         and parts[1] == input_topic and parts[3].isdigit()]
            if total == baseline['input_rows'] and committed and min(committed) >= input_after[0]:
                break
            if total > baseline['input_rows']:
                raise RuntimeError('Flink output duplicated the bounded batch')
            time.sleep(3)
        else:
            raise RuntimeError('Flink daily window output did not reconcile')
        checkpoint = None
        for _ in range(30):
            check_resources()
            checks = _flink_api('/jobs/' + job_id + '/checkpoints')
            if checks.get('counts', {}).get('completed', 0) > 0:
                checkpoint = checks.get('latest', {}).get('completed'); break
            time.sleep(3)
        if checkpoint is None:
            raise RuntimeError('Flink completed no checkpoint')
        annual = sum(int(value['visits']) for value in values.values()
                     if baseline['window_start'] <= value['visit_date'] <= baseline['window_end'])
        if annual != baseline['window_visits']:
            raise ValueError('Flink business-date window does not match MySQL')
        for value in values.values():
            duration = dt.datetime.fromisoformat(value['window_end']) - dt.datetime.fromisoformat(value['window_start'])
            if duration.total_seconds() != 5:
                raise ValueError('Flink output does not use the accepted five-second processing-time windows')
        output_after = topic_end(output_topic)
        if output_after[0] <= output_before[0]:
            raise RuntimeError('Flink emitted no newly committed window messages for this execution')
        controlled_failure = fail_probe == 'fail' or (fail_probe == 'retry' and try_number == 1)
        print('CLINIC_FLINK_EVIDENCE:' + json.dumps({
            'dag_run_execution': snapshot['execution_id'], 'batch_id': snapshot['batch_id'],
            'try_number': try_number, 'job_id': job_id, 'checkpoint': checkpoint,
            'input_offsets_before': input_before, 'input_offsets_after': input_after,
            'output_offsets_before': output_before, 'output_offsets_after': output_after,
            'consumer_group': group, 'consumer_offsets': offsets,
            'input_rows': len(rows), 'output_visits': total, 'window_visits': annual,
            'controlled_failure': controlled_failure}), flush=True)
        if controlled_failure:
            raise RuntimeError('Controlled failure after real Kafka window output and checkpoint verification')
        try:
            _flink_api('/jobs/' + job_id + '?mode=cancel', 'PATCH')
        except Exception:
            pass
        _execution(snapshot['batch_id'], 'flink-complete', flink_job_id=job_id,
                   kafka_input_topic=input_topic, kafka_output_topic=output_topic,
                   kafka_consumer_group=group)
        return {'job_id': job_id, 'input_topic': input_topic, 'output_topic': output_topic,
                'consumer_group': group, 'input_rows': len(rows), 'output_visits': total,
                'window_visits': annual, 'window_kind': 'five-second processing-time replay; visit_date retained',
                'output_keys': len(values), 'checkpoint': checkpoint, 'offsets': offsets,
                'input_offsets_before': input_before, 'input_offsets_after': input_after,
                'output_offsets_before': output_before, 'output_offsets_after': output_after,
                'message_sample': list(values.values())[:3]}
    finally:
        for job in jobs:
            try:
                _flink_api('/jobs/' + job + '?mode=cancel', 'PATCH')
            except Exception:
                pass
        for name in owned:
            apps.patch_namespaced_deployment_scale(name, 'ns-bigdata', {'spec': {'replicas': 0}})
        if created_client:
            core.delete_namespaced_pod(client_pod, 'ns-bigdata')
        # A retry must not start a new core while the previous attempt still has
        # terminating compute or its SQL client. Retain evidence and the Lease
        # if graceful cleanup cannot be confirmed.
        for _ in range(60):
            active = []
            for name in owned:
                deployment = apps.read_namespaced_deployment(name, 'ns-bigdata')
                selector = ','.join(f'{key}={value}' for key, value in deployment.spec.selector.match_labels.items())
                active.extend(p.metadata.name for p in core.list_namespaced_pod(
                    'ns-bigdata', label_selector=selector).items if p.status.phase not in ('Succeeded', 'Failed'))
            active.extend(p.metadata.name for p in core.list_namespaced_pod(
                'ns-bigdata', label_selector='execution=' + snapshot['execution_id']).items
                if p.status.phase not in ('Succeeded', 'Failed'))
            if not active:
                break
            time.sleep(2)
        else:
            raise RuntimeError(f'Flink attempt compute has not exited: {active}')


def publish_orchestrated(snapshot, start, end, dag_run_id):
    batch = quality(extract(start, end))
    if batch['source_sha256'] != snapshot['sha256'] or batch['source_metadata_sha256'] != snapshot['source_metadata_sha256']:
        raise ValueError('Source changed after the bounded snapshot; retain the last successful result')
    result = publish(batch, 'airflow:' + snapshot['batch_id'], 'pending')
    _execution(snapshot['batch_id'], 'published')
    return result


def verify_trino_and_superset(snapshot, baseline):
    sql = ("SELECT r.visits,COALESCE(sum(d.visits),0) FROM clinic.petclinic_analytics.runs r "
           "LEFT JOIN clinic.petclinic_analytics.daily_visits d ON d.run_id=r.run_id "
           "WHERE r.run_id='airflow:" + snapshot['batch_id'].replace("'", "''")
           + "' AND r.status IN ('pending','success') GROUP BY r.visits")
    request = urllib.request.Request('http' + '://trino.data-infra:8080/v1/statement', data=sql.encode(), method='POST',
                                     headers={'X-Trino-User': 'petclinic-airflow', 'X-Trino-Catalog': 'clinic',
                                              'X-Trino-Schema': 'petclinic_analytics'})
    with urllib.request.urlopen(request, timeout=20) as response:
        page = json.loads(response.read())
    query_id = page['id']; rows = page.get('data', [])
    while page.get('nextUri'):
        with urllib.request.urlopen(page['nextUri'], timeout=20) as response:
            page = json.loads(response.read())
        rows.extend(page.get('data', []))
    if not rows or int(rows[0][0]) != snapshot['input_rows']:
        raise ValueError('Trino result does not match the source snapshot')
    if int(rows[0][1]) != baseline['window_visits']:
        raise ValueError('Trino annual visits do not match the MySQL baseline')
    with urllib.request.urlopen('http' + '://superset.data-infra:8088/health', timeout=10) as response:
        health = response.read().decode().strip()
    if response.status != 200:
        raise RuntimeError('Superset health endpoint failed')
    # Run the existing chart's real API handler and Trino query in a bounded
    # verification process. Authentication stays within the existing Superset pod.
    chart = _exec('data-infra', 'superset', ['/app/.venv/bin/python', '-', 'airflow:' + snapshot['batch_id']],
                  _code('verify_chart.py'), 90)
    responses = [line[7:] for line in chart.splitlines() if line.startswith('RESULT:')]
    if len(responses) != 1:
        raise RuntimeError('Superset did not return one chart response')
    chart_result = json.loads(responses[0])
    chart_id = chart_result['chart_id']
    if chart_result['annual_visits'] != baseline['window_visits']:
        raise ValueError('Superset chart does not match the MySQL annual baseline')
    _execution(snapshot['batch_id'], 'verified', trino_query_id=query_id, superset_chart_id=chart_id)
    return {'trino_query_id': query_id, 'trino_visits': int(rows[0][0]),
            'trino_window_visits': int(rows[0][1]),
            'superset_health': health, 'superset_chart_id': chart_id,
            'superset_chart_response': chart_result,
            'mysql_window_visits': baseline['window_visits']}


def complete_execution(snapshot):
    with connect() as db, db.cursor() as cur:
        cur.execute("UPDATE petclinic_analytics.runs SET status='success' WHERE run_id=%s",
                    ('airflow:' + snapshot['batch_id'],))
        if cur.rowcount != 1:
            raise RuntimeError('No staged analytics result to publish')
        cur.execute("""UPDATE petclinic_analytics.executions
                       SET stage='complete',status='success',finished_at=now(),updated_at=now()
                       WHERE batch_id=%s""", (snapshot['batch_id'],))
    return {'batch_id': snapshot['batch_id'], 'status': 'success'}


def release_guard(guard, snapshot=None, failed=False, error=None):
    core, apps, custom, coordination = _kube()
    current = coordination.read_namespaced_lease(LEASE_NAME, LEASE_NAMESPACE)
    if current.metadata.uid != guard['lease_uid'] or current.spec.holder_identity != guard['holder']:
        raise RuntimeError('Heavy resource Lease ownership changed; refusing unsafe cleanup')
    from kubernetes.client.exceptions import ApiException

    def ignore_missing(operation):
        try:
            return operation()
        except ApiException as problem:
            if problem.status != 404:
                raise

    owned_flink = []
    status_error = None
    if snapshot:
        if failed:
            try:
                _execution(snapshot['batch_id'], 'failed', 'failed', error=(error or 'Airflow task failed')[:2000])
            except Exception as problem:
                status_error = problem
        for app in custom.list_namespaced_custom_object('sparkoperator.k8s.io', 'v1beta2', 'default',
                                                        'sparkapplications',
                                                        label_selector='execution=' + snapshot['execution_id']).get('items', []):
            ignore_missing(lambda: custom.delete_namespaced_custom_object(
                'sparkoperator.k8s.io', 'v1beta2', 'default', 'sparkapplications', app['metadata']['name']))
        for name in ('flink-jobmanager', 'flink-taskmanager'):
            deployment = apps.read_namespaced_deployment(name, 'ns-bigdata')
            if (deployment.metadata.annotations or {}).get(
                    'petclinic.devops.local/analysis-execution') == snapshot['execution_id']:
                apps.patch_namespaced_deployment_scale(name, 'ns-bigdata', {'spec': {'replicas': 0}})
                owned_flink.append(name)
        for pod in core.list_namespaced_pod('ns-bigdata', label_selector='execution=' + snapshot['execution_id']).items:
            ignore_missing(lambda: core.delete_namespaced_pod(pod.metadata.name, 'ns-bigdata'))
        for _ in range(60):
            active = [pod.metadata.name for pod in core.list_namespaced_pod(
                'default', label_selector='execution=' + snapshot['execution_id']).items
                if pod.status.phase not in ('Succeeded', 'Failed')]
            for name in owned_flink:
                deployment = apps.read_namespaced_deployment(name, 'ns-bigdata')
                selector = ','.join(f'{key}={value}' for key, value in deployment.spec.selector.match_labels.items())
                active.extend(pod.metadata.name for pod in core.list_namespaced_pod(
                    'ns-bigdata', label_selector=selector).items
                    if pod.status.phase not in ('Succeeded', 'Failed'))
            active.extend(pod.metadata.name for pod in core.list_namespaced_pod(
                'ns-bigdata', label_selector='execution=' + snapshot['execution_id']).items
                if pod.status.phase not in ('Succeeded', 'Failed'))
            if not active:
                break
            time.sleep(2)
        else:
            raise RuntimeError(f'Compute did not exit: {active}; retaining Lease and Jenkins pause')
        ignore_missing(lambda: core.delete_namespaced_config_map(snapshot['config_map'], 'default'))
    else:
        # Snapshot creation can fail after creating the ConfigMap but before
        # returning its XCom. Its ownership label still permits precise cleanup.
        for item in core.list_namespaced_config_map('default', label_selector=
                'airflow-holder=' + guard['holder'].replace(':', '-')).items:
            ignore_missing(lambda: core.delete_namespaced_config_map(item.metadata.name, 'default'))
    if guard.get('owned_quiet'):
        _jenkins('/cancelQuietDown', 'POST')
    coordination.delete_namespaced_lease(LEASE_NAME, LEASE_NAMESPACE)
    if status_error:
        raise RuntimeError('Compute released and Jenkins restored, but failure status could not be saved') from status_error
    return {'released': True, 'jenkins_resumed': guard.get('owned_quiet', False)}


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--from', dest='start', required=True)
    parser.add_argument('--to', dest='end', required=True)
    parser.add_argument('--run-id', required=True)
    args = parser.parse_args()
    publish(quality(extract(args.start, args.end)), args.run_id)
