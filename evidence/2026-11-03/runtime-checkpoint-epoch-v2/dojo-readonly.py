from pathlib import Path
import json,subprocess,shlex,sys
O=Path(__file__).resolve().parent;phase=sys.argv[1];assert phase in ['before','after'];run=json.load(open(O/'run.json'))['validationRunId']
S=['ssh','-o','BatchMode=yes','-o','ConnectTimeout=6','-o','StrictHostKeyChecking=yes','-o','HostName=192.168.64.11','-o','HostKeyAlias=192.168.1.58','zhang@192.168.1.58']
code='''import json,hashlib
from dojo.models import Product,Engagement,Test,Finding,Dojo_User
from django.core.serializers.json import DjangoJSONEncoder
def rows(model,fields):
 x=list(model.objects.order_by('id').values(*fields));return {'count':len(x),'ids':[r['id'] for r in x],'sha256':hashlib.sha256(json.dumps(x,sort_keys=True,cls=DjangoJSONEncoder).encode()).hexdigest()}
u=Dojo_User.objects.get(username='jenkins-petclinic')
x={'classification':'REAL_READ_ONLY_DATABASE_METADATA_NOT_API_EXECUTION','products':rows(Product,['id','name','prod_type_id']),'engagements':rows(Engagement,['id','product_id','name']),'tests':rows(Test,['id','engagement_id','title','test_type_id']),'findings':rows(Finding,['id','test_id','severity','active','verified','duplicate','false_p','out_of_scope','risk_accepted','is_mitigated']),'existingIdentity':{'id':u.id,'name':u.username,'isStaff':u.is_staff,'isSuperuser':u.is_superuser,'groupCount':u.groups.count(),'modelPermissionCount':u.user_permissions.count(),'authorizedProducts':list(Product.objects.filter(authorized_users=u).values_list('id',flat=True))},'credentialValuesRead':0,'writes':0}
print('RUNTIME_JSON:'+json.dumps(x))'''
p=subprocess.run(S+['sudo -n docker exec platform-defectdojo-uwsgi-1 python /app/manage.py shell -c '+shlex.quote(code)],capture_output=True,text=True,timeout=45);assert p.returncode==0,p.stderr[-300:];x=json.loads(next(l for l in p.stdout.splitlines() if l.startswith('RUNTIME_JSON:')).split(':',1)[1]);(O/('dojo-governance-'+phase+'.json')).write_text(json.dumps(x,indent=2)+'\n')
node="const fs=require('fs'),root='/var/jenkins_home/workspace/security-runtime-facts-20261102/';const paths=['.devsecops/trivy-audit.json','.devsecops/kubescape-gate.json','.devsecops/gitleaks-native.json','.devsecops/semgrep-native.json','.devsecops/zap-business-report.xml'];console.log(JSON.stringify({workspace:'DEDICATED_VALIDATION_ONLY',reports:paths.map(p=>({path:p,exists:fs.existsSync(root+p)})),reportContentsRead:false}));"
p=subprocess.run(S+['sudo -n kubectl exec -i -n ns-devops deploy/jenkins -c jenkins -- node -e '+shlex.quote(node)],capture_output=True,text=True,timeout=30);assert p.returncode==0;reports=json.loads(p.stdout);(O/('dojo-current-report-prerequisites-'+phase+'.json')).write_text(json.dumps(reports,indent=2)+'\n');print(json.dumps({'phase':phase,'governance':{k:x[k]['count'] for k in ['products','engagements','tests','findings']},'identity':x['existingIdentity'],'reports':reports['reports']}))
