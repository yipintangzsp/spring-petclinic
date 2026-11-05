import urllib.request,urllib.parse,json,datetime
op=urllib.request.build_opener(urllib.request.ProxyHandler({}));origin='http://10.43.111.46:9090';start='2026-11-05T02:05:00Z';end='2026-11-05T02:45:00Z';r={'classification':'READ_ONLY_FOCUSED_ATTRIBUTION_AND_COVERAGE','start':start,'end':end,'at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'productionMutations':0,'queries':[]}
def get(p,params):
 try:
  res=op.open(origin+p+'?'+urllib.parse.urlencode(params,doseq=True),timeout=12);b=res.read(4*1024*1024+1);assert len(b)<=4*1024*1024;return {'httpStatus':res.status,'data':json.loads(b)}
 except Exception as e:return {'errorClass':type(e).__name__}
s=get('/api/v1/series',{'match[]':'container_cpu_usage_seconds_total{namespace="petclinic",container="petclinic"}','start':start,'end':end});rows=s.get('data',{}).get('data',[]);r['containerCpuSeriesLabels']=rows
scope='node="devops"'if any(x.get('node')=='devops'for x in rows)else'instance="10.0.0.3:10250"'if any(x.get('instance')=='10.0.0.3:10250'for x in rows)else None
r['attributionScope']=scope
if scope:
 q='topk(8, sum by (namespace,pod,node) (rate(container_cpu_usage_seconds_total{'+scope+',container!="",container!="POD",pod!=""}[2m])))'
 r['queries'].append({'name':'top-pod-cpu','query':q,**get('/api/v1/query_range',{'query':q,'start':start,'end':end,'step':'30s'})})
for name,q in [('ready-sample-time','timestamp(kube_pod_status_ready{namespace="petclinic",pod=~"petclinic-.*",condition="true"})'),('load-sample-time','timestamp(node_load1{instance="10.0.0.3:9100"})'),('all-traefik-services','sum by (code,service) (increase(traefik_service_requests_total[1m]))')]:
 r['queries'].append({'name':name,'query':q,**get('/api/v1/query_range',{'query':q,'start':start,'end':end,'step':'30s'})})
print(json.dumps(r))
