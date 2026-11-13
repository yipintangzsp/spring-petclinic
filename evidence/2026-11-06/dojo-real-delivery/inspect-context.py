"""Read-only identity/context metadata. Never reads Token.key or any credential."""
import runpy,shlex,json,pathlib,datetime,sys
sys.dont_write_bytecode=True
api=runpy.run_path('evidence/2026-11-05/security-manager-v2-loki/inspect-production.py')
code=r'''
import json,hashlib
from django.db import connection
from django.contrib.auth import get_user_model
from dojo.models import Product,Engagement,Dojo_User,Test,Finding
from rest_framework.authtoken.models import Token
U=Dojo_User
# These selects explicitly exclude the Token primary key (the credential itself).
token_users=set(Token.objects.values_list('user_id',flat=True))
users=[]
for u in U.objects.order_by('id')[:30]:
 users.append({'id':u.id,'username':u.username,'active':u.is_active,'isStaff':u.is_staff,'isSuperuser':u.is_superuser,'hasApiToken':u.id in token_users,'groupCount':u.groups.count(),'modelPermissionCount':u.user_permissions.count(),'authorizedProductIds':list(Product.objects.filter(authorized_users=u).values_list('id',flat=True))})
products=[{'id':p.id,'name':p.name,'nonProductionMarker':any(s in p.name.lower()for s in ['demo','test','candidate','validation']),'authorizedUserIds':list(p.authorized_users.values_list('id',flat=True)),'testCount':Test.objects.filter(engagement__product=p).count(),'findingCount':Finding.objects.filter(test__engagement__product=p).count()}for p in Product.objects.order_by('id')[:30]]
engagements=list(Engagement.objects.order_by('id').values('id','name','product_id')[:40])
print('SAFE_JSON:'+json.dumps({'users':users,'products':products,'engagements':engagements,'credentialValuesRead':0,'mutations':0}))
'''
raw=api['remote']('sudo -n docker exec platform-defectdojo-uwsgi-1 python /app/manage.py shell -c '+shlex.quote(code),timeout=60)
lines=[l for l in raw.splitlines()if l.startswith('SAFE_JSON:')];assert len(lines)==1
x=json.loads(lines[0].split(':',1)[1]);x['observedAt']=datetime.datetime.now(datetime.timezone.utc).isoformat()
with pathlib.Path('evidence/2026-11-06/dojo-real-delivery/context.json').open('x')as f:json.dump(x,f,indent=2)
print(json.dumps(x))
