import json,urllib.request,urllib.error
BASE='http://10.43.188.105:5601'
def post(path,value):
 req=urllib.request.Request(BASE+path,data=json.dumps(value).encode(),headers={'Content-Type':'application/json','kbn-xsrf':'petclinic-v09'},method='POST')
 try:
  with urllib.request.urlopen(req,timeout=30) as r:return json.loads(r.read())
 except urllib.error.HTTPError as e:raise RuntimeError(str(e.code)+' '+e.read().decode())
view=post('/api/data_views/data_view',{'data_view':{'id':'petclinic-v09','title':'filebeat-*','name':'Petclinic 0.9 structured telemetry','timeFieldName':'@timestamp','allowNoIndex':True},'override':True})
source={'query':{'language':'kuery','query':'service.name: petclinic'},'filter':[]}
saved=post('/api/saved_objects/search/petclinic-v09-logs?overwrite=true',{'attributes':{'title':'Petclinic 0.9 · Requests and business snapshots','description':'Structured HTTP requests, aggregate database counts and platform snapshots.','columns':['@timestamp','event.action','http.route','http.response.status_code','petclinic.owners','petclinic.pets','petclinic.vets','petclinic.visits','trace.id'],'sort':[['@timestamp','desc']],'kibanaSavedObjectMeta':{'searchSourceJSON':json.dumps({'indexRefName':'kibanaSavedObjectMeta.searchSourceJSON.index',**source})}},'references':[{'name':'kibanaSavedObjectMeta.searchSourceJSON.index','type':'index-pattern','id':'petclinic-v09'}]})
print(json.dumps({'data_view_id':view['data_view']['id'],'saved_search_id':saved['id']}))
