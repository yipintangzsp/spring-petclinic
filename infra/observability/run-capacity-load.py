"""Bounded read-only HTTP load. Run on devops with Python stdlib; no image pull."""
import argparse,collections,json,math,threading,time,urllib.request,concurrent.futures,subprocess
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('output');p.add_argument('--stage',action='append',required=True,help='name:qps:seconds');p.add_argument('--workers',type=int,default=6);args=p.parse_args()
assert 1<=args.workers<=8
opener=urllib.request.build_opener(urllib.request.ProxyHandler({})); paths=['/owners?q=Demo&page=1','/owners?q=Demo&page=2','/owners/1000001','/owners/1000001/pets/1000001','/pets?type=cat','/vets.html','/']
stop=threading.Event();results=[]
def request(n):
 start=time.monotonic()
 try:
  req=urllib.request.Request('http://127.0.0.1'+paths[n%len(paths)],headers={'Host':'petclinic.devops.local'})
  with opener.open(req,timeout=10) as r:r.read();code=r.status
 except Exception as e:code=getattr(e,'code','exception')
 return {'status':code,'latency':time.monotonic()-start}
def guard():
 while not stop.wait(15):
  try:
   nodes=json.loads(subprocess.check_output(['sudo','-n','k3s','kubectl','get','nodes','-o','json'],timeout=10))
   metrics=json.loads(subprocess.check_output(['sudo','-n','k3s','kubectl','get','--raw','/apis/metrics.k8s.io/v1beta1/nodes'],timeout=10))
   capacities={n['metadata']['name']:int(n['status']['allocatable']['memory'].rstrip('Ki')) for n in nodes['items']}
   for n in metrics['items']:
    ratio=int(n['usage']['memory'].rstrip('Ki'))/capacities[n['metadata']['name']]
    if ratio>.92:results.append({'guard':'node_memory_above_92_percent','node':n['metadata']['name'],'ratio':ratio,'time':time.time()});stop.set()
  except Exception as e:results.append({'guard_warning':type(e).__name__,'time':time.time()})
threading.Thread(target=guard,daemon=True).start()
for spec in args.stage:
 name,qps,seconds=spec.split(':');qps=float(qps);seconds=int(seconds);assert 0<=qps<=60 and 0<seconds<=900
 begin=time.time();data=[];futures=set();n=0;skipped=0;deadline=time.monotonic()+seconds;next_send=time.monotonic()
 with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as pool:
  while time.monotonic()<deadline and not stop.is_set():
   done={f for f in futures if f.done()}
   for f in done:data.append(f.result())
   futures-=done
   if qps and time.monotonic()>=next_send:
    if len(futures)<args.workers:futures.add(pool.submit(request,n));n+=1
    else:skipped+=1
    next_send+=1/qps
   else:time.sleep(.002 if qps else .2)
  for f in futures:data.append(f.result())
 duration=time.time()-begin;lat=sorted(x['latency'] for x in data)
 result={'stage':name,'start':begin,'end':time.time(),'configured_qps':qps,'actual_qps':len(data)/duration,'requests':len(data),'status':dict(collections.Counter(str(x['status']) for x in data)),'skipped':skipped,'p50':lat[math.ceil(len(lat)*.5)-1] if lat else None,'p95':lat[math.ceil(len(lat)*.95)-1] if lat else None,'max':max(lat) if lat else None,'guard_stopped':stop.is_set()}
 results.append(result);Path(args.output).write_text(json.dumps(results,indent=2));print(json.dumps(result),flush=True)
 if stop.is_set():break
stop.set()
