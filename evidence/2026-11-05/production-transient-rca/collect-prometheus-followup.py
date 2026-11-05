import urllib.request,urllib.parse,json,datetime
op=urllib.request.build_opener(urllib.request.ProxyHandler({}));origin='http://10.43.111.46:9090';start='2026-11-05T02:05:00Z';end='2026-11-05T02:45:00Z';r={'classification':'READ_ONLY_DISCOVERED_METRIC_FOLLOWUP','start':start,'end':end,'at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'series':[],'queries':[],'productionMutations':0}
def get(path,params):
 try:
  res=op.open(origin+path+'?'+urllib.parse.urlencode(params,doseq=True),timeout=12);b=res.read(3*1024*1024+1);assert len(b)<=3*1024*1024;return {'httpStatus':res.status,'data':json.loads(b)}
 except Exception as e:return {'errorClass':type(e).__name__}
for q in ['traefik_service_requests_total','kube_endpointslice_endpoints{namespace="petclinic"}','kube_node_info{node="devops"}']:
 r['series'].append({'selector':q,**get('/api/v1/series',{'match[]':q,'start':start,'end':end})})
for name,q in [('endpoint-slice-counts','kube_endpointslice_endpoints{namespace="petclinic"}'),('last-exit-code','kube_pod_container_status_last_terminated_exitcode{namespace="petclinic",pod=~"petclinic-.*"}'),('last-exit-time','kube_pod_container_status_last_terminated_timestamp{namespace="petclinic",pod=~"petclinic-.*"}'),('traefik-entrypoint-5xx','sum by (code,entrypoint) (increase(traefik_entrypoint_requests_total{code=~"5.."}[1m]))'),('devops-node-info','kube_node_info{node="devops"}'),('prometheus-restarts','process_start_time_seconds{job=~".*prometheus.*"}')]:
 r['queries'].append({'name':name,'query':q,**get('/api/v1/query_range',{'query':q,'start':start,'end':end,'step':'30s'})})
print(json.dumps(r))
