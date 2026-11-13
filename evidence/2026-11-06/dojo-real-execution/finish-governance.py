import pathlib,sys,json,runpy,urllib.request,shlex,datetime
sys.dont_write_bytecode=True
HERE=pathlib.Path(__file__).resolve().parent;sys.path.insert(0,str(HERE.parent/'grafana-v2-real'));from keychain_store import operation
identity=json.loads((HERE/'identity.json').read_text());q=json.loads((HERE/'query-back.json').read_text());receipt=json.loads((HERE/'delivery-reconciled.json').read_text());idem=json.loads((HERE/'idempotent.json').read_text())
assert receipt['httpDelivery']['deliveryState']=='ACKNOWLEDGED'and idem['httpDelivery']['httpRequestCount']==0
op=urllib.request.build_opener(urllib.request.ProxyHandler({}));token=operation('get',service='petclinic-security-manager-v2-defectdojo',account='security-manager-v2-demo')
def get(path):
 with op.open(urllib.request.Request('http://192.168.64.11:18095'+path,headers={'Authorization':'Token '+token}),timeout=15)as r:return json.load(r)
tests=get('/api/v2/tests/?limit=100&engagement=4');findings=get('/api/v2/findings/?limit=100&test=36');assert tests['count']==1 and findings['count']==2 and findings['next']is None
assert sorted(f['id']for f in findings['results'])==[6628,6629]
for f in findings['results']:
 evidence=json.loads(f['references']);assert evidence['resultDigest']=='a61aead230295688c2070bcce50ac32eacd6c6a0858f581d44074e49f1c35e19'and evidence['sourceSeverity']=='ERROR'and f['severity']=='High'
api=runpy.run_path('evidence/2026-11-05/security-manager-v2-loki/inspect-production.py')
code=r'''
import json,hashlib
from django.core.serializers.json import DjangoJSONEncoder
from dojo.models import Product,Engagement,Test,Finding,Dojo_User
from rest_framework.authtoken.models import Token
u=Dojo_User.objects.get(pk=7);p=Product.objects.get(pk=7);assert u.username=='security-manager-v2-demo'and p.name=='Security Manager V2 DEMO NON-PRODUCTION'
assert not u.is_staff and not u.is_superuser and u.user_permissions.count()==0 and u.groups.count()==0 and list(Product.objects.filter(authorized_users=u).values_list('id',flat=True))==[7]
queries={'Product':Product.objects.exclude(pk=7),'Engagement':Engagement.objects.exclude(product_id=7),'Test':Test.objects.exclude(engagement__product_id=7),'Finding':Finding.objects.exclude(test__engagement__product_id=7)}
checks={}
for name,query in queries.items():
 h=hashlib.sha256();count=0
 for row in query.order_by('pk').values().iterator(chunk_size=256):h.update(json.dumps(row,sort_keys=True,cls=DjangoJSONEncoder,default=str).encode()+b'\n');count+=1
 checks[name]={'count':count,'sha256':h.hexdigest()}
EXPECTED_BASELINE
assert checks==expected,'EXISTING_GOVERNANCE_CHANGED'
assert Finding.objects.filter(test__engagement__product=p).count()==2 and Test.objects.filter(engagement__product=p).count()==1
Token.objects.filter(user=u).delete();assert not Token.objects.filter(user=u).exists()
print('SAFE_JSON:'+json.dumps({'preexistingGovernanceUnchanged':True,'baseline':checks,'tokenRevoked':True,'userRetainedNonAdmin':True,'demoFindings':2,'demoTests':1}))
'''.replace('EXPECTED_BASELINE','expected='+repr(identity['preexistingGovernanceBaseline']))
raw=api['remote']('sudo -n docker exec platform-defectdojo-uwsgi-1 python /app/manage.py shell -c '+shlex.quote(code),timeout=80)
line=next(l for l in raw.splitlines()if l.startswith('SAFE_JSON:'));checks=json.loads(line.split(':',1)[1]);operation('delete',service='petclinic-security-manager-v2-defectdojo',account='security-manager-v2-demo');del token
result={'at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'product':identity['product'],'engagement':identity['engagement'],'user':identity['user'],'testId':36,'findingIds':[6628,6629],'findingCount':2,'runId':'web-042069ea-ae24-4f16-a914-4cbd8117aeaf','resultDigest':'a61aead230295688c2070bcce50ac32eacd6c6a0858f581d44074e49f1c35e19','policyDecision':'FAIL','sourceSeverity':'ERROR','dojoSeverity':'High','queryBack':'VERIFIED','idempotentRedelivery':'VERIFIED_SAME_JOURNAL_ZERO_HTTP','crossJournalExactlyOnce':'NOT_TESTED','governanceChecks':checks,'keychainEntryRemoved':True,'shortTermTokenRevoked':True,'productionGovernanceMutations':0,'newScans':0,'release':0,'rollout':0}
with(HERE/'governance-result.json').open('x')as f:json.dump(result,f,indent=2)
print(json.dumps(result))
