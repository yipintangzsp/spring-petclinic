"""Create an owned upgrade data view/search; verify real version/Pod/time log fields."""
import json,pathlib,subprocess,urllib.request

def kube(args):return json.loads(subprocess.check_output(['sudo','-n','kubectl',*args,'-o','json'],text=True,timeout=15))
def base(name,namespace,port):return 'http'+ '://'+kube(['-n',namespace,'get','service',name])['spec']['clusterIP']+':'+str(port)
http=urllib.request.build_opener(urllib.request.ProxyHandler({}))
def request(url,body=None,method=None):
 req=urllib.request.Request(url,data=None if body is None else json.dumps(body).encode(),method=method,headers={'Content-Type':'application/json','kbn-xsrf':'petclinic-upgrade'})
 with http.open(req,timeout=20) as response:return json.load(response)
kibana=base('kibana-service','default',5601);es=base('elasticsearch','default',9200)
view_id='petclinic-upgrade-20261011';search_id=view_id+'-logs'
view=request(kibana+'/api/data_views/data_view',{'data_view':{'id':view_id,'title':'filebeat-*','name':'Petclinic · 发布与分析日志','timeFieldName':'@timestamp'},'override':True})
search=request(kibana+'/api/saved_objects/search/'+search_id+'?overwrite=true',{'attributes':{'title':'Petclinic · 应用版本、Pod、时间及 Trace','description':'查询真实结构化日志；筛选 service.version、kubernetes.pod.name 和时间。旧 Cook/Petclinic 搜索保留。','columns':['@timestamp','service.version','kubernetes.pod.name','event.action','http.route','http.response.status_code','trace.id'],'sort':[['@timestamp','desc']],'kibanaSavedObjectMeta':{'searchSourceJSON':json.dumps({'indexRefName':'kibanaSavedObjectMeta.searchSourceJSON.index','query':{'language':'kuery','query':'service.name: petclinic'},'filter':[]})}},'references':[{'name':'kibanaSavedObjectMeta.searchSourceJSON.index','type':'index-pattern','id':view_id}]})
logs=request(es+'/filebeat-*/_search',{'size':3,'sort':[{'@timestamp':'desc'}],'_source':['@timestamp','service.version','kubernetes.pod.name','event.action','http.route','http.response.status_code','trace.id'],'query':{'bool':{'filter':[{'term':{'service.name':'petclinic'}},{'range':{'@timestamp':{'gte':'now-1h'}}}]}},'aggs':{'versions':{'terms':{'field':'service.version','size':5}},'pods':{'terms':{'field':'kubernetes.pod.name','size':5}}}})
assert logs['hits']['total']['value']>0
record={'dataViewId':view['data_view']['id'],'searchId':search['id'],'queryResult':logs}
pathlib.Path('/tmp/petclinic-upgrade-kibana.json').write_text(json.dumps(record,indent=2));print(json.dumps({'dataViewId':record['dataViewId'],'searchId':record['searchId'],'realLogCount':logs['hits']['total']['value']}))
