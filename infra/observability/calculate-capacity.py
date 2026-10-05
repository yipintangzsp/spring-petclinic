"""N-1 planning distinguishes scheduler requests from measured memory safety."""
import argparse,json,math
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('inventory',type=Path);p.add_argument('samples',type=Path);p.add_argument('output',type=Path);p.add_argument('--pod-memory-mib',type=int,default=640);p.add_argument('--request-memory-mib',type=int,default=512);args=p.parse_args()
d=json.loads(args.inventory.read_text());samples=[json.loads(x)for x in args.samples.read_text().splitlines()]
def qty(v):
 v=str(v)
 for suffix,factor in [('Gi',1024**3),('Mi',1024**2),('Ki',1024),('n',1e-9),('u',1e-6),('m',.001)]:
  if v.endswith(suffix):return float(v[:-len(suffix)])*factor
 return float(v)
def stats(v):
 v=sorted(v);return {'min':v[0],'avg':sum(v)/len(v),'p95':v[math.ceil(.95*len(v))-1],'max':v[-1]}
result={'assumptions':{'app_request_cpu':.1,'app_request_memory_mib':args.request_memory_mib,'app_planning_memory_mib':args.pod_memory_mib,'headroom_mib':{'devops':2048,'aliyun-worker':256,'ucloud-worker':512},'scope':'Unschedulable node with DB/control/storage still available; not a devops physical outage','reservation':'Explicit planning margin; no kubelet reservation changes'},'nodes':{},'scenarios':{}}
for n in d['nodes']['items']:
 name=n['metadata']['name'];alloc=n['status']['allocatable'];pods=[x for x in d['pods']if x['spec'].get('nodeName')==name and x['phase']not in ['Succeeded','Failed']];totals={}
 for kind in ['requests','limits']:
  totals[kind]={}
  for resource in ['cpu','memory']:
   # Kubernetes effective request is max(sum regular, each init); no native sidecar init in these workloads.
   def amount(x):
    normal=sum(qty(c['resources'].get(kind,{}).get(resource,0))for c in x['spec']['containers']);init=max([qty(c['resources'].get(kind,{}).get(resource,0))for c in x['spec'].get('initContainers',[])]+[0]);return max(normal,init)
   totals[kind][resource]=sum(amount(x)for x in pods)
 apppods=[x for x in pods if x['namespace']=='petclinic' and x['name'].startswith('petclinic-')]
 base_mem_req=totals['requests']['memory']-sum(qty(c['resources'].get('requests',{}).get('memory',0))for x in apppods for c in x['spec']['containers'])
 base_cpu_req=totals['requests']['cpu']-sum(qty(c['resources'].get('requests',{}).get('cpu',0))for x in apppods for c in x['spec']['containers'])
 mem=[];cpu=[];base_actual=[]
 for r in samples:
  for m in r.get('nodes',{}).get('items',[]):
   if m['metadata']['name']==name:
    mem.append(qty(m['usage']['memory'])/1024**2);cpu.append(qty(m['usage']['cpu']))
    app=sum(float(x['value'][1])/1024**2 for x in r.get('memory',{}).get('data',{}).get('result',[])if x['metric'].get('node')==name)
    base_actual.append(max(0,mem[-1]-app))
 if not mem:raise RuntimeError('No real node samples '+name)
 available_mem=qty(alloc['memory'])/1024**2;reserve=result['assumptions']['headroom_mib'][name]
 sched=min(math.floor((qty(alloc['memory'])-base_mem_req)/(args.request_memory_mib*1024**2)),math.floor((qty(alloc['cpu'])-base_cpu_req)/.1))
 safe=max(0,math.floor((available_mem-max(base_actual)-reserve)/args.pod_memory_mib))
 result['nodes'][name]={'allocatable':alloc,'allocated':totals,'pods':len(pods),'conditions':{c['type']:c['status']for c in n['status']['conditions']},'cpu_cores':stats(cpu),'memory_mib':stats(mem),'non_app_actual_peak_mib':max(base_actual),'non_app_memory_request_mib':base_mem_req/1024**2,'scheduler_app_slots':sched,'memory_safe_app_slots':min(safe,sched)}
for lost in result['nodes']:
 remaining=[v for k,v in result['nodes'].items()if k!=lost];sched=sum(v['scheduler_app_slots']for v in remaining);safe=sum(v['memory_safe_app_slots']for v in remaining)
 result['scenarios'][lost]={'scheduler_slots':sched,'safe_slots':safe,'replicas':{str(r):{'scheduler_fits':r<=sched,'memory_safe':r<=safe,'pending_by_requests':max(0,r-sched),'capacity_deficit':max(0,r-safe)}for r in range(3,7)}}
args.output.write_text(json.dumps(result,indent=2));print(json.dumps(result,indent=2))
