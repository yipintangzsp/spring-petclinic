"""Submit bounded queries to the existing Trino endpoint and retain real query IDs."""
import argparse,json,time,urllib.request
from pathlib import Path

QUERIES={
 'runtime': 'SELECT version() AS version',
 'daily': '''SELECT d.stat_date,d.visits FROM clinic.petclinic_analytics.daily_visits d
            WHERE d.run_id=(SELECT run_id FROM clinic.petclinic_analytics.runs WHERE status='success' ORDER BY generated_at DESC LIMIT 1)
            ORDER BY d.stat_date LIMIT 367''',
 'totals': '''SELECT run_id,generated_at,window_start,window_end,source_kind,owners,pets,vets,visits,watermark,input_rows
             FROM clinic.petclinic_analytics.runs WHERE status='success' ORDER BY generated_at DESC LIMIT 1''',
 'types': '''SELECT type,pets FROM clinic.petclinic_analytics.pet_types
            WHERE run_id=(SELECT run_id FROM clinic.petclinic_analytics.runs WHERE status='success' ORDER BY generated_at DESC LIMIT 1)
            ORDER BY type LIMIT 65'''
}


def query(base,sql):
    request=urllib.request.Request(base+'/v1/statement',data=sql.encode(),headers={
        'X-Trino-User':'petclinic-reporting','X-Trino-Source':'petclinic-platform-acceptance',
        'X-Trino-Session':'query_max_run_time=30s,query_max_execution_time=30s',
        'Content-Type':'text/plain'})
    start=time.monotonic();response=json.load(urllib.request.urlopen(request,timeout=10));rows=[];columns=[];history=[]
    try:
        while True:
            if response.get('error'):raise RuntimeError(response['error']['message'])
            rows.extend(response.get('data',[]));columns=response.get('columns',columns);history.append(response.get('stats',{}))
            if len(rows)>5000:raise RuntimeError('Trino exceeded bounded result size')
            if not response.get('nextUri'):break
            if time.monotonic()-start>40:raise RuntimeError('Query exceeded acceptance deadline')
            uri=response['nextUri'];response=json.load(urllib.request.urlopen(urllib.request.Request(uri,headers={'X-Trino-User':'petclinic-reporting'}),timeout=10))
            time.sleep(.15)
    except Exception:
        if response.get('nextUri'):
            try:urllib.request.urlopen(urllib.request.Request(response['nextUri'],method='DELETE'),timeout=5).close()
            except Exception:pass
        raise
    return {'queryId':response['id'],'sql':sql,'columns':columns,'rows':rows,'stats':history,'durationSeconds':round(time.monotonic()-start,3)}

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--base',required=True);p.add_argument('--output',required=True);a=p.parse_args()
    result={name:query(a.base,sql) for name,sql in QUERIES.items()};daily=sum(row[1] for row in result['daily']['rows']);types=sum(row[1] for row in result['types']['rows']);total=result['totals']['rows'][0]
    assert types==total[6];assert daily<=total[8];result['reconciliation']={'windowVisits':daily,'pets':types,'sourceVisits':total[8]};Path(a.output).write_text(json.dumps(result,indent=2));print(json.dumps({'queryIds':{k:v['queryId'] for k,v in result.items() if k!='reconciliation'},'reconciliation':result['reconciliation']}))
