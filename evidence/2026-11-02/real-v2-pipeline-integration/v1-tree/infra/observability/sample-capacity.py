"""Continuous read-only samples; JSONL preserves raw evidence and distribution summary."""
import argparse,json,time,statistics,math
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
from importlib.util import spec_from_file_location,module_from_spec
s=spec_from_file_location('audit',Path(__file__).with_name('audit-production.py'));a=module_from_spec(s);s.loader.exec_module(a)
PROM='http://10.43.111.46:9090'
EXPRS={
 'cpu':'rate(container_cpu_usage_seconds_total{namespace="petclinic",container="petclinic"}[1m])',
 'memory':'container_memory_working_set_bytes{namespace="petclinic",container="petclinic"}',
 'rss':'container_memory_rss{namespace="petclinic",container="petclinic"}',
 'heap':'sum by(pod)(jvm_memory_used_bytes{namespace="petclinic",area="heap"})',
 'gc':'sum by(pod)(rate(jvm_gc_pause_seconds_count{namespace="petclinic"}[1m]))',
 'hikari_active':'hikaricp_connections_active{namespace="petclinic"}',
 'hikari_idle':'hikaricp_connections_idle{namespace="petclinic"}',
 'hikari_pending':'hikaricp_connections_pending{namespace="petclinic"}',
 'throttling':'sum by(pod)(rate(container_cpu_cfs_throttled_periods_total{namespace="petclinic",container="petclinic"}[1m])) / sum by(pod)(rate(container_cpu_cfs_periods_total{namespace="petclinic",container="petclinic"}[1m]))',
 'http_rate':'sum(rate(http_server_requests_seconds_count{namespace="petclinic",uri!~"/actuator.*"}[1m]))',
 'http_5xx':'sum(rate(http_server_requests_seconds_count{namespace="petclinic",status=~"5.."}[1m]))',
 'http_p95':'histogram_quantile(0.95,sum by(le)(rate(http_server_requests_seconds_bucket{namespace="petclinic",uri!~"/actuator.*"}[1m])))'
}
def collect():
 r={'time':time.time()}
 tasks={'nodes':lambda:json.loads(a.remote('sudo -n k3s kubectl get --raw /apis/metrics.k8s.io/v1beta1/nodes')),
  'pod_metrics':lambda:json.loads(a.remote('sudo -n k3s kubectl get --raw /apis/metrics.k8s.io/v1beta1/namespaces/petclinic/pods')),
  'pods':lambda:a.kube('-n petclinic get pods -l app=petclinic'),
  'hpa':lambda:a.kube('-n petclinic get hpa'),
  'pdb':lambda:a.kube('-n petclinic get pdb petclinic'),
  'endpoints':lambda:a.kube('-n petclinic get endpointslice -l kubernetes.io/service-name=petclinic'),
  'events':lambda:a.kube('-n petclinic get events'),
  'database':lambda:a.remote("sudo -n k3s kubectl exec -n ns-data deploy/postgresql -- psql -U postgres -d petclinic -Atc \"SELECT state,count(*) FROM pg_stat_activity WHERE datname='petclinic' GROUP BY state; SELECT numbackends,xact_commit,xact_rollback,deadlocks,temp_bytes FROM pg_stat_database WHERE datname='petclinic';\""),
  **{k:lambda e=e:a.query(PROM,'/api/v1/query',{'query':e}) for k,e in EXPRS.items()}}
 with ThreadPoolExecutor(max_workers=6) as pool:
  futures={k:pool.submit(fn) for k,fn in tasks.items()}
  for k,f in futures.items():
   try:r[k]=f.result()
   except Exception as e:r[k]={'error':str(e)}
 return r

def summary(samples):
 values={}
 for r in samples:
  for metric in EXPRS:
   for x in r.get(metric,{}).get('data',{}).get('result',[]):
    v=float(x['value'][1]);key=metric+':'+x['metric'].get('pod','total')
    if math.isfinite(v):values.setdefault(key,[]).append(v)
 out={}
 for k,vs in values.items():
  v=sorted(vs);out[k]={'samples':len(v),'min':min(v),'avg':statistics.mean(v),'p95':v[math.ceil(.95*len(v))-1],'max':max(v)}
 return out
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('output',type=Path);p.add_argument('--seconds',type=int,default=300);p.add_argument('--interval',type=int,default=15);args=p.parse_args();samples=[];end=time.monotonic()+args.seconds
 args.output.parent.mkdir(parents=True,exist_ok=True)
 with args.output.open('w') as f:
  while time.monotonic()<end:
   start=time.monotonic();r=collect();samples.append(r);f.write(json.dumps(r)+'\n');f.flush()
   print(json.dumps({'time':r['time'],'pods':len(r.get('pods',{}).get('items',[])),'cpu':[x['value'][1] for x in r.get('cpu',{}).get('data',{}).get('result',[])],'pending':[x['value'][1] for x in r.get('hikari_pending',{}).get('data',{}).get('result',[])]}),flush=True)
   time.sleep(max(0,args.interval-(time.monotonic()-start)))
 args.output.with_suffix('.summary.json').write_text(json.dumps(summary(samples),indent=2))
