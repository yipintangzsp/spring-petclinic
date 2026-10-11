"""Bounded, append-only visit analysis; no patient names, notes or addresses.

The current Visit controller creates records; no update/delete watermark exists.
If that contract changes, add CDC or updated_at before claiming incremental edits.
"""
import argparse
import datetime as dt
import json
import os
import time

MAX_ROWS = 5000


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
    return {'window_start': str(first), 'window_end': str(last), 'watermark': watermark,
            'counts': counts, 'visits': visits, 'types': types, 'missing_type': missing_type}


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


def publish(batch, run_id):
    from psycopg2.extras import execute_values
    if not run_id or len(run_id) > 200:
        raise ValueError('Invalid analysis run ID')
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
                        VALUES (%s,now(),%s,%s,%s,%s,%s,%s,%s,%s,%s,'success')
                        ON CONFLICT (run_id) DO UPDATE SET generated_at=EXCLUDED.generated_at,
                        owners=EXCLUDED.owners,pets=EXCLUDED.pets,vets=EXCLUDED.vets,visits=EXCLUDED.visits,
                        watermark=EXCLUDED.watermark,input_rows=EXCLUDED.input_rows''',
                        (run_id,batch['window_start'],batch['window_end'],kind,counts['owners'],
                         counts['pets'],counts['vets'],counts['visits'],watermark,len(batch['visits'])))
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


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--from', dest='start', required=True)
    parser.add_argument('--to', dest='end', required=True)
    parser.add_argument('--run-id', required=True)
    args = parser.parse_args()
    publish(quality(extract(args.start, args.end)), args.run_id)
