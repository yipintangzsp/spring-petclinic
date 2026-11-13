import pathlib,sys,json,urllib.request,datetime
sys.dont_write_bytecode=True
HERE=pathlib.Path(__file__).resolve().parent;sys.path.insert(0,str(HERE.parent/'grafana-v2-real'));from keychain_store import operation
op=urllib.request.build_opener(urllib.request.ProxyHandler({}));token=operation('get',service='petclinic-security-manager-v2-defectdojo',account='security-manager-v2-demo')
def get(path):
 with op.open(urllib.request.Request('http://192.168.64.11:18095'+path,headers={'Authorization':'Token '+token}),timeout=20)as r:return json.load(r)
tests=get('/api/v2/tests/?limit=100&engagement=4');assert tests['next']is None and len(tests['results'])==1
test= get('/api/v2/tests/'+str(tests['results'][0]['id'])+'/');findings=get('/api/v2/findings/?limit=100&test='+str(test['id']));assert findings['next']is None
expected=json.loads(pathlib.Path('evidence/2026-11-06/dojo-real-delivery/offline-plan.json').read_text())['imports'][0]['payload']['findings']
rows=[]
for f in findings['results']:
 e=next(e for e in expected if e['unique_id_from_tool']==f['unique_id_from_tool'])
 mismatch={k:{'expected':e[k],'actual':f.get(k)}for k in ['title','severity','description','file_path','line','unique_id_from_tool','vuln_id_from_tool','references']if e[k]!=f.get(k)}
 rows.append({'id':f['id'],'test':f['test'],'rule':f.get('vuln_id_from_tool'),'title':f['title'],'severity':f['severity'],'references':f['references'],'uniqueId':f['unique_id_from_tool'],'mismatch':mismatch})
x={'queriedAt':datetime.datetime.now(datetime.timezone.utc).isoformat(),'test':{k:test.get(k)for k in ['id','engagement','title','build_id','version','test_type_name','test_type','branch_tag','commit_hash']},'findingCount':len(rows),'findings':rows}
with(HERE/'query-back.json').open('x')as h:json.dump(x,h,indent=2)
print(json.dumps(x))
