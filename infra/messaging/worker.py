"""Bounded AMQP worker. PostgreSQL outbox versions make every retry durable.
No external notifications, arbitrary commands, or heavyweight analytics jobs are run.
"""
import datetime as dt
import hashlib
import json
import os
import signal
import sys
import time
import uuid
from pathlib import Path
from urllib.parse import urlparse

sys.path.insert(0, '/opt/clinic-deps/pika.whl')
KINDS = ('visit_followup', 'statistics_report', 'release_deployed')
EXCHANGE = 'clinic.events.v1'
DEAD_EXCHANGE = 'clinic.dead.v1'
DEAD_QUEUE = 'clinic.dead.v1'
MAX_ATTEMPTS = 3
STOP = False


def log(action, **fields):
    print(json.dumps({'at': dt.datetime.now(dt.timezone.utc).isoformat(),
                      'service': {'name': 'clinic-message-worker'}, 'action': action, **fields}), flush=True)


def parse_window(payload):
    start = dt.date.fromisoformat(payload['from'])
    end = dt.date.fromisoformat(payload['to'])
    if not 0 <= (end - start).days <= 365:
        raise ValueError('invalid_report_window')
    return start, end


def next_state(attempt):
    return ('failed', 0) if attempt >= MAX_ATTEMPTS else ('retrying', 5 * attempt)


def decode_envelope(body, message_id):
    if len(body) > 8192:
        raise ValueError('message_too_large')
    envelope = json.loads(body)
    if (not isinstance(envelope, dict) or not isinstance(message_id, str)
            or not 1 <= len(message_id) <= 128 or not isinstance(envelope.get('payload'), dict)
            or envelope.get('schema_version') != 1 or envelope.get('event_id') != message_id):
        raise ValueError('invalid_message_identity')
    if (envelope.get('kind') not in KINDS or type(envelope.get('delivery_version')) is not int
            or not 1 <= envelope['delivery_version'] <= 1000000000):
        raise ValueError('invalid_message_schema')
    return envelope


def connect_db():
    import psycopg2
    uri = urlparse(os.environ['POSTGRES_URL'].removeprefix('jdbc:'))
    return psycopg2.connect(host=uri.hostname, port=uri.port or 5432, dbname=uri.path.lstrip('/'),
                           user=os.environ['POSTGRES_USER'], password=os.environ['POSTGRES_PASS'],
                           connect_timeout=5, application_name='clinic-message-worker',
                           options='-c statement_timeout=5000 -c lock_timeout=2000')


def topology(channel):
    channel.exchange_declare(exchange=EXCHANGE, exchange_type='direct', durable=True)
    channel.exchange_declare(exchange=DEAD_EXCHANGE, exchange_type='direct', durable=True)
    channel.queue_declare(queue=DEAD_QUEUE, durable=True, arguments={'x-queue-type': 'classic'})
    channel.queue_bind(queue=DEAD_QUEUE, exchange=DEAD_EXCHANGE, routing_key='dead')
    for kind in KINDS:
        name = 'clinic.' + kind + '.v1'
        channel.queue_declare(queue=name, durable=True, arguments={
            'x-queue-type': 'classic', 'x-dead-letter-exchange': DEAD_EXCHANGE,
            'x-dead-letter-routing-key': 'dead'})
        channel.queue_bind(queue=name, exchange=EXCHANGE, routing_key=kind)


def run_handler(cursor, event_id, kind, payload):
    if kind == 'visit_followup':
        cursor.execute('''INSERT INTO clinic_messaging.followups(event_id,visit_id,pet_id,owner_id)
                          VALUES (%s,%s,%s,%s) ON CONFLICT (event_id) DO NOTHING''',
                       (event_id, int(payload['visit_id']), int(payload['pet_id']), int(payload['owner_id'])))
        return {'followup': 'todo', 'visit_id': int(payload['visit_id'])}
    if kind == 'statistics_report':
        start, end = parse_window(payload)
        cursor.execute('''SELECT (SELECT count(*) FROM owners),(SELECT count(*) FROM pets),
                          (SELECT count(*) FROM vets),(SELECT count(*) FROM visits
                          WHERE visit_date BETWEEN %s AND %s)''', (start, end))
        owners, pets, vets, visits = cursor.fetchone()
        cursor.execute('''INSERT INTO clinic_messaging.report_results
                          (event_id,window_start,window_end,owners,pets,vets,visits)
                          VALUES (%s,%s,%s,%s,%s,%s,%s) ON CONFLICT (event_id) DO NOTHING''',
                       (event_id, start, end, owners, pets, vets, visits))
        return {'from': str(start), 'to': str(end), 'owners': owners, 'pets': pets, 'vets': vets, 'visits': visits}
    if kind == 'release_deployed':
        cursor.execute('''INSERT INTO clinic_messaging.release_audit(event_id,release,build,source_commit)
                          VALUES (%s,%s,%s,%s) ON CONFLICT (event_id) DO NOTHING''',
                       (event_id, payload['release'], int(payload['build']), payload['source_commit']))
        return {'release': payload['release'], 'build': int(payload['build']), 'audit': 'recorded'}
    raise ValueError('unsupported_job')


def dispatch(db, publisher):
    import pika
    for _ in range(10):
        with db:
            with db.cursor() as cursor:
                cursor.execute('''SELECT event_id,kind,payload,delivery_version,status,created_at
                                  FROM clinic_messaging.jobs
                                  WHERE confirmed_version < delivery_version AND next_attempt_at <= now()
                                  ORDER BY next_attempt_at FOR UPDATE SKIP LOCKED LIMIT 1''')
                row = cursor.fetchone()
                if row is None:
                    return
                event_id, kind, payload, version, status, created = row
                envelope = {'schema_version': 1, 'event_id': event_id, 'kind': kind,
                            'delivery_version': version, 'occurred_at': created.isoformat(), 'payload': json.loads(payload)}
                dead = status == 'failed'
                publisher.basic_publish(exchange=DEAD_EXCHANGE if dead else EXCHANGE,
                                        routing_key='dead' if dead else kind, mandatory=True,
                                        body=json.dumps(envelope).encode(),
                                        properties=pika.BasicProperties(message_id=event_id,
                                            delivery_mode=2, content_type='application/json'))
                cursor.execute('''UPDATE clinic_messaging.jobs SET confirmed_version=%s,
                                  updated_at=now() WHERE event_id=%s AND delivery_version=%s''',
                               (version, event_id, version))
        log('publisher_confirmed', event_id=event_id, version=version, dead_letter=dead)


def consume(db, channel, method, properties, body):
    try:
        envelope = decode_envelope(body, properties.message_id)
    except (ValueError, KeyError, TypeError):
        channel.basic_nack(method.delivery_tag, requeue=False)
        log('invalid_message_dead_lettered')
        return
    event_id, version = envelope['event_id'], envelope['delivery_version']
    # Persist the attempt separately so the UI can show running; all actual effects
    # and success are committed together below. An unacked crash can safely resume.
    with db:
        with db.cursor() as cursor:
            cursor.execute('''SELECT kind,payload,status,delivery_version,cycle_attempt,attempts
                              FROM clinic_messaging.jobs WHERE event_id=%s FOR UPDATE''', (event_id,))
            row = cursor.fetchone()
            if row is None:
                channel.basic_nack(method.delivery_tag, requeue=False)
                log('unknown_event_dead_lettered', event_id=event_id)
                return
            if row[2] in ('success', 'failed') or row[3] != version:
                channel.basic_ack(method.delivery_tag)
                log('duplicate_or_obsolete_acked', event_id=event_id, version=version)
                return
            kind, payload, status, _, cycle, attempts = row
            if kind != envelope['kind'] or json.loads(payload) != envelope['payload']:
                channel.basic_nack(method.delivery_tag, requeue=False)
                log('payload_mismatch_dead_lettered', event_id=event_id)
                return
            attempt = cycle if status == 'running' else cycle + 1
            total = attempts if status == 'running' else attempts + 1
            cursor.execute('''UPDATE clinic_messaging.jobs SET status='running',cycle_attempt=%s,
                              attempts=%s,updated_at=now() WHERE event_id=%s''', (attempt, total, event_id))
    log('running', event_id=event_id, kind=kind, attempt=attempt, redelivered=method.redelivered)
    try:
        with db:
            with db.cursor() as cursor:
                cursor.execute('SELECT status,delivery_version FROM clinic_messaging.jobs WHERE event_id=%s FOR UPDATE', (event_id,))
                current = cursor.fetchone()
                if current[0] == 'success' or current[1] != version:
                    channel.basic_ack(method.delivery_tag)
                    return
                payload = json.loads(payload)
                if attempt <= int(payload.get('_acceptance_fail_until', 0)):
                    raise ValueError('controlled_acceptance_failure')
                result = run_handler(cursor, event_id, kind, payload)
                cursor.execute('''UPDATE clinic_messaging.jobs SET status='success',result=%s,
                                  last_error=NULL,updated_at=now(),confirmed_version=delivery_version
                                  WHERE event_id=%s''', (json.dumps(result), event_id))
    except Exception as error:
        # Failure and the *next* outbox version are one DB transaction. ACK only
        # after it commits; a crash before retry publish cannot lose the retry.
        with db:
            with db.cursor() as cursor:
                state, delay = next_state(attempt)
                cursor.execute('''UPDATE clinic_messaging.jobs SET status=%s,last_error=%s,
                                  delivery_version=delivery_version+1,
                                  next_attempt_at=now()+(%s * interval '1 second'),updated_at=now()
                                  WHERE event_id=%s AND delivery_version=%s''',
                               (state, type(error).__name__, delay, event_id, version))
        channel.basic_ack(method.delivery_tag)
        log(state, event_id=event_id, kind=kind, attempt=attempt, error_type=type(error).__name__)
        return
    channel.basic_ack(method.delivery_tag)
    log('success', event_id=event_id, kind=kind, attempt=attempt)


def daemon():
    import pika
    global STOP
    signal.signal(signal.SIGTERM, lambda *_: globals().__setitem__('STOP', True))
    while not STOP:
        db = connection = None
        try:
            db = connect_db()
            parameters = pika.ConnectionParameters(os.environ['RABBITMQ_HOST'], 5672, 'petclinic',
                pika.PlainCredentials(os.environ['RABBITMQ_USER'], os.environ['RABBITMQ_PASS']),
                heartbeat=30, blocked_connection_timeout=5, socket_timeout=5, stack_timeout=10)
            connection = pika.BlockingConnection(parameters)
            publisher = connection.channel(); topology(publisher); publisher.confirm_delivery()
            consumer = connection.channel(); consumer.basic_qos(prefetch_count=1)
            for kind in KINDS:
                consumer.basic_consume(queue='clinic.' + kind + '.v1', auto_ack=False,
                    on_message_callback=lambda c, m, p, b: consume(db, c, m, p, b))
            log('ready', worker_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(), consumer_concurrency=1)
            while not STOP:
                dispatch(db, publisher)
                connection.process_data_events(time_limit=1)
                Path('/tmp/clinic-mq-ready').touch()
        except Exception as error:
            Path('/tmp/clinic-mq-ready').unlink(missing_ok=True)
            log('connection_or_dispatch_retry', error_type=type(error).__name__)
            time.sleep(5)
        finally:
            if connection and connection.is_open:
                connection.close()
            if db:
                db.close()


def insert_job(db, event_id, kind, payload):
    with db:
        with db.cursor() as cursor:
            cursor.execute('''INSERT INTO clinic_messaging.jobs(event_id,idempotency_key,kind,payload)
                              VALUES (%s,%s,%s,%s) ON CONFLICT (idempotency_key) DO NOTHING''',
                           (event_id, event_id, kind, json.dumps(payload, sort_keys=True)))
            cursor.execute('SELECT kind,payload FROM clinic_messaging.jobs WHERE event_id=%s', (event_id,))
            existing = cursor.fetchone()
            if existing is None or existing[0] != kind or json.loads(existing[1]) != payload:
                raise ValueError('idempotency_payload_conflict')


def command():
    if sys.argv[1] == 'daemon':
        daemon(); return
    data = json.load(sys.stdin)
    if sys.argv[1] == 'publish-release':
        if not isinstance(data.get('build'), int) or not data.get('release') or len(data['source_commit']) != 40:
            raise ValueError('invalid_release_event')
        kind, event_id = 'release_deployed', 'release-' + str(data['build']) + '-' + data['source_commit']
    elif sys.argv[1] == 'acceptance-job':
        kind, event_id = 'statistics_report', 'check-' + str(uuid.uuid4())
        parse_window(data)
    else:
        raise ValueError('unsupported_command')
    db = connect_db()
    try:
        insert_job(db, event_id, kind, data)
        for _ in range(80):
            with db:
                with db.cursor() as cursor:
                    cursor.execute('SELECT status,attempts,result,last_error FROM clinic_messaging.jobs WHERE event_id=%s', (event_id,))
                    state, attempts, result, error = cursor.fetchone()
            if state in ('success', 'failed'):
                print(json.dumps({'event_id': event_id, 'kind': kind, 'status': state,
                    'attempts': attempts, 'result': json.loads(result) if result else None,
                    'last_error': error, 'worker_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest()}))
                if kind == 'release_deployed' and state != 'success':
                    raise RuntimeError('release_audit_failed')
                return
            time.sleep(1)
        raise RuntimeError('bounded_job_wait_timeout')
    finally:
        db.close()


if __name__ == '__main__':
    command()
