from pathlib import Path
import os,json,subprocess
ROOT=Path.cwd();records=[]
def check(identity,verb,resource,ns,expected):
 args=['kubectl','--request-timeout=20s','auth','can-i',verb,resource,'-n',ns]
 if identity:args+=['--as=system:serviceaccount:devsecops-system:'+identity]
 r=subprocess.run(args,capture_output=True,text=True,timeout=25);answer=r.stdout.strip()
 records.append({'identity':identity or 'security-fixture-executor','verb':verb,'resource':resource,'namespace':ns,'expectedAllowed':expected,'observed':answer,'exitCode':r.returncode})
 if r.returncode not in (0,1) or answer!=('yes' if expected else 'no'):raise RuntimeError('RBAC_SCOPE_MISMATCH_STOP')
for ns,name in [('petclinic','petclinic-db'),('petclinic','rabbitmq-client'),('petclinic','petclinic-harbor-pull'),('devsecops-system','kyverno-registry-pull')]:
 for v in ['get','patch']:check('platform-secret-reconciler',v,'secret/'+name,ns,True)
for v,res,ns in [('get','secret/unrelated-secret','devsecops-system'),('list','secrets','devsecops-system'),('create','secrets','devsecops-system'),('get','secret/unrelated-secret','petclinic'),('create','secrets','petclinic'),('list','secrets','petclinic'),('get','secret/rabbitmq-auth','data-infra')]:check('platform-secret-reconciler',v,res,ns,False)
check('kyverno-admission-controller','get','secret/kyverno-registry-pull','devsecops-system',True)
for v,res in [('get','secret/petclinic-harbor-pull'),('get','secret/petclinic-db'),('list','secrets'),('patch','secret/petclinic-db')]:check('kyverno-admission-controller',v,res,'petclinic',False)
check(None,'get','lease/platform-heavy','data-infra',True)
for v,res,ns in [('get','secret/petclinic-db','petclinic'),('list','secrets','petclinic'),('create','secrets','petclinic'),('delete','secrets','petclinic'),('get','nodes','default'),('create','namespaces','default')]:check(None,v,res,ns,False)
(ROOT/'evidence/rbac-verification.json').write_text(json.dumps({'checks':records,'allMatched':True,'secretValueReads':0},indent=2))
