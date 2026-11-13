import pathlib,sys,runpy,shlex,json,datetime
sys.dont_write_bytecode=True
HERE=pathlib.Path(__file__).resolve().parent;sys.path.insert(0,str(HERE.parent/'grafana-v2-real'))
from keychain_store import operation
SERVICE='petclinic-security-manager-v2-defectdojo';ACCOUNT='security-manager-v2-demo'
api=runpy.run_path('evidence/2026-11-05/security-manager-v2-loki/inspect-production.py')
code=r'''
import json,hashlib,datetime,urllib.request,urllib.error
from django.db import transaction
from django.core.serializers.json import DjangoJSONEncoder
from dojo.models import Dojo_User,Product,Product_Type,Engagement,Test,Finding
from rest_framework.authtoken.models import Token
name='Security Manager V2 DEMO NON-PRODUCTION';username='security-manager-v2-demo'
assert not Dojo_User.objects.filter(username=username).exists() and not Product.objects.filter(name=name).exists(),'CONFLICTING_DEMO_IDENTITY_OR_CONTEXT'
def baseline():
 out={}
 for model in [Product,Engagement,Test,Finding]:
  h=hashlib.sha256();count=0
  for row in model.objects.order_by('pk').values().iterator(chunk_size=256):h.update(json.dumps(row,sort_keys=True,cls=DjangoJSONEncoder,default=str).encode()+b'\n');count+=1
  out[model.__name__]={'count':count,'sha256':h.hexdigest()}
 return out
before=baseline()
choices=list(Product_Type.objects.order_by('id').values('id','name'));pt=next((t for t in choices if t['id']==2 and t['name']=='DevSecOps'),None)
assert pt,'NO_EXISTING_NONPRODUCTION_PRODUCT_TYPE'
u=None;p=None
try:
 with transaction.atomic():
  u=Dojo_User.objects.create(username=username,is_staff=False,is_superuser=False,is_active=True);u.set_unusable_password();u.save()
  p=Product.objects.create(name=name,description='DEMO / NON-PRODUCTION. Only controlled Semgrep fixture findings; no production scan or credentials.',prod_type_id=pt['id']);p.authorized_users.add(u)
  token=Token.objects.create(user=u)
 assert not u.is_staff and not u.is_superuser and u.groups.count()==0 and u.user_permissions.count()==0
 assert list(Product.objects.filter(authorized_users=u).values_list('id',flat=True))==[p.id]
 op=urllib.request.build_opener(urllib.request.ProxyHandler({}));requests=[]
 def req(path,method='GET',body=None):
  r=urllib.request.Request('http://192.168.64.11:18095'+path,data=None if body is None else json.dumps(body).encode(),method=method,headers={'Authorization':'Token '+token.key,'Content-Type':'application/json'})
  try:
   with op.open(r,timeout=15)as response:status=response.status;data=json.load(response)
  except urllib.error.HTTPError as e:status=e.code;data={}
  requests.append({'method':method,'path':path,'status':status});return status,data
 status,own=req('/api/v2/products/'+str(p.id)+'/');assert status==200 and own['name']==name
 status,listed=req('/api/v2/products/?limit=100');assert status==200 and listed['next']is None and [x['id']for x in listed['results']]==[p.id]
 for endpoint in ['/api/v2/products/1/','/api/v2/products/2/','/api/v2/engagements/1/','/api/v2/engagements/2/']:
  status,_=req(endpoint);assert status in [403,404],'NONPRODUCTION_SCOPE_NOT_ENFORCED'
 date=datetime.datetime.now(datetime.timezone.utc).date().isoformat()
 ename='Semgrep Controlled Findings DEMO NON-PRODUCTION'
 status,e=req('/api/v2/engagements/','POST',{'name':ename,'product':p.id,'target_start':date,'target_end':date,'status':'In Progress','engagement_type':'CI/CD','description':'DEMO NON-PRODUCTION; genuine archived controlled Semgrep fixture only.'})
 assert status in [200,201]and e['product']==p.id and e['name']==ename,'SCOPED_ENGAGEMENT_CREATE_DENIED'
 status,check=req('/api/v2/engagements/'+str(e['id'])+'/');assert status==200 and check['product']==p.id
 print('SAFE_JSON:'+json.dumps({'user':{'id':u.id,'username':u.username,'isStaff':False,'isSuperuser':False,'groupCount':0,'modelPermissionCount':0,'authorizedProducts':[p.id]},'product':{'id':p.id,'name':p.name,'productType':pt},'engagement':{'id':e['id'],'name':e['name'],'product':p.id},'scopeApiEvidence':requests,'preexistingGovernanceBaseline':before,'shortTermPolicy':'REVOKE_AND_DELETE_KEYCHAIN_AFTER_CONTROLLED_EXECUTION','token':token.key}))
except BaseException:
 if u:Token.objects.filter(user=u).delete()
 if p and not Test.objects.filter(engagement__product=p).exists():p.delete()
 if u:u.delete()
 raise
'''
raw=api['remote']('sudo -n docker exec platform-defectdojo-uwsgi-1 python /app/manage.py shell -c '+shlex.quote(code),timeout=110)
lines=[l for l in raw.splitlines()if l.startswith('SAFE_JSON:')];assert len(lines)==1
x=json.loads(lines[0].split(':',1)[1]);token=x.pop('token');del raw,lines
try:operation('add',service=SERVICE,account=ACCOUNT,secret=token)
except BaseException:
 rollback="from dojo.models import Dojo_User,Product,Test; from rest_framework.authtoken.models import Token; u=Dojo_User.objects.get(pk="+str(x['user']['id'])+"); p=Product.objects.get(pk="+str(x['product']['id'])+"); assert u.username=='security-manager-v2-demo' and p.name=='Security Manager V2 DEMO NON-PRODUCTION' and not Test.objects.filter(engagement__product=p).exists(); Token.objects.filter(user=u).delete(); p.delete(); u.delete(); print('SAFE_ROLLBACK_COMPLETE')"
 api['remote']('sudo -n docker exec platform-defectdojo-uwsgi-1 python /app/manage.py shell -c '+shlex.quote(rollback),timeout=45)
 raise
finally:del token
x['credentialReference']={'store':'macOS Login Keychain','service':SERVICE,'account':ACCOUNT};x['createdAt']=datetime.datetime.now(datetime.timezone.utc).isoformat()
with(HERE/'identity.json').open('x')as f:json.dump(x,f,indent=2)
print(json.dumps(x))
