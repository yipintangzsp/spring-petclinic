import urllib.request,urllib.error,urllib.parse,json,datetime,time
now=lambda:datetime.datetime.now(datetime.timezone.utc).isoformat();op=urllib.request.build_opener(urllib.request.ProxyHandler({}));origin='http://10.43.111.46:9090';start='2026-11-05T02:05:00Z';end='2026-11-05T02:45:00Z';r={'classification':'REAL_READ_ONLY_PROMETHEUS_HISTORY','startedAt':now(),'origin':origin,'start':start,'end':end,'stepSeconds':30,'queries':[],'productionMutations':0}
def get(p,params={}):
 url=origin+p+'?'+urllib.parse.urlencode(params)
 try:
  res=op.open(url,timeout=12);b=res.read(4*1024*1024+1);assert len(b)<=4*1024*1024,'RESPONSE_CAP';return {'httpStatus':res.status,'data':json.loads(b)}
 except Exception as e:return {'errorClass':type(e).__name__,'httpStatus':getattr(e,'code',None)}
names=get('/api/v1/label/__name__/values',{'start':start,'end':end});available=names.get('data',{}).get('data',[]);wanted=[n for n in available if any(s in n for s in ['kube_pod_status_ready','kube_pod_container_status_restarts','kube_pod_container_status_last_terminated','kube_deployment_status_replicas','kube_node_status_condition','node_memory_MemAvailable','node_cpu_seconds','node_pressure','node_load1','node_filesystem_avail','container_cpu_usage','container_memory_working_set','traefik','endpoint','argocd_app'])];r['metricDiscovery']={'httpStatus':names.get('httpStatus'),'errorClass':names.get('errorClass'),'historicalWindowNamesCount':len(available),'relevantNames':wanted}
queries=[
 ('pod-ready','kube_pod_status_ready{kube_pod_status_ready="invalid"}','kube_pod_status_ready{namespace="petclinic",pod=~"petclinic-.*",condition="true"}'),
 ('restart','kube_pod_container_status_restarts_total','kube_pod_container_status_restarts_total{namespace="petclinic",pod=~"petclinic-.*"}'),
 ('last-termination','kube_pod_container_status_last_terminated_reason','kube_pod_container_status_last_terminated_reason{namespace="petclinic",pod=~"petclinic-.*"}'),
 ('deployment-ready','kube_deployment_status_replicas_available','kube_deployment_status_replicas_available{namespace="petclinic",deployment="petclinic"}'),
 ('node-ready-pressure','kube_node_status_condition','kube_node_status_condition{node=~"devops|aliyun-worker|ucloud-worker",condition=~"Ready|MemoryPressure|DiskPressure|PIDPressure",status="true"}'),
 ('node-availability','node_memory_MemAvailable_bytes','node_memory_MemAvailable_bytes'),
 ('node-cpu','node_cpu_seconds_total','sum by (instance, mode) (rate(node_cpu_seconds_total{mode=~"idle|iowait|steal|system|user"}[2m]))'),
 ('node-load','node_load1','node_load1'),
 ('cpu-pressure','node_pressure_cpu_waiting_seconds_total','rate(node_pressure_cpu_waiting_seconds_total[2m])'),
 ('memory-pressure','node_pressure_memory_waiting_seconds_total','rate(node_pressure_memory_waiting_seconds_total[2m])'),
 ('io-pressure','node_pressure_io_waiting_seconds_total','rate(node_pressure_io_waiting_seconds_total[2m])'),
 ('disk-available','node_filesystem_avail_bytes','node_filesystem_avail_bytes{mountpoint="/"}'),
 ('pod-cpu','container_cpu_usage_seconds_total','sum by (pod, node) (rate(container_cpu_usage_seconds_total{namespace="petclinic",pod=~"petclinic-.*",container="petclinic"}[2m]))'),
 ('pod-memory','container_memory_working_set_bytes','container_memory_working_set_bytes{namespace="petclinic",pod=~"petclinic-.*",container="petclinic"}'),
 ('endpoint-available','kube_endpoint_address_available','kube_endpoint_address_available{namespace="petclinic",endpoint="petclinic"}'),
 ('endpoint-unavailable','kube_endpoint_address_not_ready','kube_endpoint_address_not_ready{namespace="petclinic",endpoint="petclinic"}'),
 ('traefik-http','traefik_service_requests_total','sum by (code,service) (increase(traefik_service_requests_total{code=~"5..",service=~".*petclinic.*"}[1m]))'),
 ('argo-health','argocd_app_info','argocd_app_info{name="petclinic"}'),
 ('scrape-up','up','up{job=~".*node-exporter.*|.*kube-state.*|.*kubelet.*|.*petclinic.*|.*argocd.*|.*traefik.*"}')]
for name,metric,q in queries:
 metric='kube_pod_status_ready'if name=='pod-ready'else metric
 if metric not in available:r['queries'].append({'name':name,'metric':metric,'query':q,'status':'METRIC_NOT_DISCOVERED_NOT_ZERO'});continue
 at=now();result=get('/api/v1/query_range',{'query':q,'start':start,'end':end,'step':'30s'});r['queries'].append({'name':name,'metric':metric,'query':q,'requestedAt':at,**result})
r['targets']=get('/api/v1/targets',{'state':'active'})
# Targets may contain private labels or credentials in URLs: retain only public identities.
t=r['targets'].get('data',{}).get('data',{}).get('activeTargets',[]);r['targets']={'activeCount':len(t),'targets':[{'labels':x.get('labels'),'health':x.get('health'),'lastScrape':x.get('lastScrape'),'lastError':x.get('lastError','')[:500]}for x in t],'note':'No scrape URLs or discovered secret-bearing labels exported'}
r['completedAt']=now();print(json.dumps(r))
