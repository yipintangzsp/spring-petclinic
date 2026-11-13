from pathlib import Path
import json,subprocess,shlex,sys
O=Path('evidence/2026-11-03/runtime-final-three');run=json.load(open(O/'run.json'))['validationRunId'];user=run+'-dojo';product='security-manager-runtime-validation-'+run
SSH=['ssh','-o','BatchMode=yes','-o','ConnectTimeout=6','-o','StrictHostKeyChecking=yes','-o','HostName=192.168.64.11','-o','HostKeyAlias=192.168.1.58','zhang@192.168.1.58']
def manage(code):
 p=subprocess.run(SSH+['sudo -n docker exec platform-defectdojo-uwsgi-1 python /app/manage.py shell -c '+shlex.quote(code)],capture_output=True,text=True,timeout=45)
 if p.returncode:
  last=p.stderr.strip().splitlines()[-1] if p.stderr.strip() else 'no stderr';save('dojo-management-error.json',{'returncode':p.returncode,'error':last[:400]});raise RuntimeError('ISOLATED_DOJO_MANAGEMENT_FAILED; sanitized error retained')
 lines=[x for x in p.stdout.splitlines() if x.startswith('RUNTIME_JSON:')];assert len(lines)==1;return json.loads(lines[0].split(':',1)[1])
def jnode(code,input=None):
 p=subprocess.run(SSH+['sudo -n kubectl exec -i -n ns-devops deploy/jenkins -c jenkins -- node -e '+shlex.quote(code)],input=json.dumps(input).encode() if input is not None else None,capture_output=True,timeout=40);assert p.returncode==0,'ISOLATED_DOJO_TEST_NODE_FAILED';return json.loads(p.stdout)
def save(n,x):(O/n).write_text(json.dumps(x,indent=2)+'\n')
if sys.argv[1]=='prepare':
 assert not (O/'dojo-isolation-ledger.json').exists()
 code=f'''
import json,hashlib
from django.contrib.auth import get_user_model
from django.db import transaction
from django.core.serializers.json import DjangoJSONEncoder
from dojo.models import Product,Product_Type,Dojo_User
from rest_framework.authtoken.models import Token
U=Dojo_User; username={user!r}; name={product!r}
assert not U.objects.filter(username=username).exists() and not Product.objects.filter(name=name).exists()
def baseline():
 rows=list(Product.objects.exclude(name=name).order_by('id').values());b=json.dumps(rows,sort_keys=True,cls=DjangoJSONEncoder).encode();return {{'count':len(rows),'sha256':hashlib.sha256(b).hexdigest()}}
before=baseline()
with transaction.atomic():
 u=U.objects.create(username=username,is_staff=False,is_superuser=False,is_active=True);u.set_unusable_password();u.save()
 p=Product.objects.create(name=name,description='Non-production disposable runtime validation '+{run!r},prod_type=Product_Type.objects.get(pk=2));p.authorized_users.add(u)
 token=Token.objects.create(user=u)
assert before==baseline()
print('RUNTIME_JSON:'+json.dumps({{'validationRunId':{run!r},'userId':u.id,'username':u.username,'isStaff':u.is_staff,'isSuperuser':u.is_superuser,'groups':list(u.groups.values_list('id',flat=True)),'modelPermissionCount':u.user_permissions.count(),'productId':p.id,'productName':p.name,'authorizedProducts':list(Product.objects.filter(authorized_users=u).values_list('id',flat=True)),'normalProductBaseline':before,'token':token.key}}))
'''
 x=manage(code);token=x.pop('token');save('dojo-isolation-ledger.json',x)
 jnode("const fs=require('fs'),x=JSON.parse(fs.readFileSync(0)),p='/tmp/runtime-three-"+run+"';fs.mkdirSync(p,{recursive:true,mode:448});fs.writeFileSync(p+'/dojo.json',JSON.stringify(x),{mode:384});console.log('{}');",{'...':'validation-only','token':token,'metadata':x})
 print('ISOLATED_NONSTAFF_DOJO_IDENTITY_READY')
else:
 x=json.load(open(O/'dojo-isolation-ledger.json'));code=f'''
import json,hashlib
from django.contrib.auth import get_user_model
from django.core.serializers.json import DjangoJSONEncoder
from dojo.models import Product,Engagement,Test,Finding,Dojo_User
from rest_framework.authtoken.models import Token
U=Dojo_User;u=U.objects.get(pk={x['userId']});p=Product.objects.get(pk={x['productId']})
assert u.username=={user!r} and not u.is_staff and not u.is_superuser and p.name=={product!r}
assert list(Product.objects.filter(authorized_users=u).values_list('id',flat=True))==[p.id]
tests=Test.objects.filter(engagement__product=p);findings=Finding.objects.filter(test__engagement__product=p)
counts={{'tests':tests.count(),'findings':findings.count(),'engagements':Engagement.objects.filter(product=p).count()}}
rows=list(Product.objects.exclude(pk=p.id).order_by('id').values());baseline={{'count':len(rows),'sha256':hashlib.sha256(json.dumps(rows,sort_keys=True,cls=DjangoJSONEncoder).encode()).hexdigest()}}
assert baseline=={x['normalProductBaseline']!r}
Token.objects.filter(user=u).delete()
if counts['tests']==0 and counts['findings']==0:
 pid=p.id;uid=u.id;p.delete();u.delete();state='REMOVED';assert not Product.objects.filter(pk=pid).exists() and not U.objects.filter(pk=uid).exists()
else:
 u.is_active=False;u.save(update_fields=['is_active']);state='VALIDATION_RETAINED'
print('RUNTIME_JSON:'+json.dumps({{'state':state,'counts':counts,'tokenRevoked':True,'normalProductBaselineUnchanged':True,'normalProductBaseline':baseline}}))
'''
 state=manage(code);jnode("const fs=require('fs'),p='/tmp/runtime-three-"+run+"/dojo.json';fs.rmSync(p,{force:true});console.log('{}');");save('dojo-isolation-cleanup.json',state);print(json.dumps(state))
