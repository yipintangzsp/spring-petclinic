"""Verify one sampled real insights request across Jaeger, ES and Loki (run on VM)."""
import json,pathlib,secrets,time,urllib.request,urllib.parse,subprocess
http=urllib.request.build_opener(urllib.request.ProxyHandler({}))
def request(url,body=None,headers=None):
 h={'Content-Type':'application/json',**(headers or {})}
 with http.open(urllib.request.Request(url,data=None if body is None else json.dumps(body).encode(),headers=h),timeout=12) as r:return r.status,r.read()
def service(ns,name,port):
 x=json.loads(subprocess.check_output(['sudo','-n','kubectl','-n',ns,'get','service',name,'-o','json'],text=True,timeout=10));return 'http'+ '://'+x['spec']['clusterIP']+':'+str(port)
tid=secrets.token_hex(16);sid=secrets.token_hex(8);status,body=request('http'+ '://192.168.1.58/insights',headers={'Host':'petclinic.devops.local','traceparent':'00-'+tid+'-'+sid+'-01'})
assert status==200 and len(body)>1000 # Filtered counts are verified by the real browser, after JavaScript loads.
jaeger=service('monitoring','jaeger',16686);es=service('default','elasticsearch',9200);loki=service('monitoring','loki',3100)
result={'traceId':tid,'parentSpanId':sid,'requestStatus':status}
for _ in range(15):
 try:
  trace=json.loads(request(jaeger+'/api/traces/'+tid)[1]);logs=json.loads(request(es+'/filebeat-*/_search',{'size':2,'_source':['@timestamp','service.version','trace.id','span.id','http.route','http.response.status_code','kubernetes.pod.name'],'query':{'term':{'trace.id':tid}}})[1]);lokilog=json.loads(request(loki+'/loki/api/v1/query_range?'+urllib.parse.urlencode({'query':'{namespace="petclinic"} |= "'+tid+'"','limit':2,'start':str(int((time.time()-300)*1e9)),'end':str(int(time.time()*1e9))}))[1])
  if trace.get('data') and logs['hits']['total']['value']>0 and lokilog.get('data',{}).get('result'):break
 except Exception as error:result['lastPollError']=type(error).__name__
 time.sleep(2)
else:raise RuntimeError('Trace did not correlate in all three stores')
result.update({'jaeger':trace,'elasticsearch':logs,'loki':lokilog});pathlib.Path('/tmp/petclinic-upgrade-trace.json').write_text(json.dumps(result,indent=2))
print(json.dumps({'traceId':tid,'requestStatus':status,'jaegerSpans':len(trace['data'][0]['spans']),'esHits':logs['hits']['total']['value'],'lokiStreams':len(lokilog['data']['result'])}))
