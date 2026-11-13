"""Authorized fixture manager; every API operation reuses approved explicit guard identity.
No Gate/Policy imports, no default context. Outputs only safe owned-object metadata.
"""
from pathlib import Path
import sys,json,tempfile,ssl,http.client,hashlib,base64,importlib.util,datetime
import yaml
sys.path.insert(0,str(Path('infra/security/testing').resolve()))
import isolated_sops_executor as g
OUT=Path('evidence/2026-11-02/sops-authoritative-baseline-02').resolve();ROOT=Path(json.loads((OUT/'root-reference.json').read_text())['root'])
spec=importlib.util.spec_from_file_location('explicit_legacy',Path('infra/security/testing/test_isolated_sops_executor.py'));m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
PROFILE=g.profile_from_document(m.guard.profile_document(m.LEGACY_PROFILE))
DESIGN=Path('evidence/2026-11-02/sops-preparation-blocker-closure');INV=json.loads((DESIGN/'fixture-inventory-amendment.json').read_text());RB=json.loads((DESIGN/'rbac-design-amendment.json').read_text());LEDGER=[];REQUESTS=0
RUN='sm-sops-20261102-02'

def api(method,path,obj=None):
 global REQUESTS
 assert path.startswith(('/api/v1/','/apis/rbac.authorization.k8s.io/v1/','/apis/coordination.k8s.io/v1/'))
 v=g.validate(str(PROFILE.binding.path),{'KUBECONFIG':str(PROFILE.binding.path)},profile=PROFILE)
 with tempfile.TemporaryDirectory(dir=PROFILE.temp_parent) as tmp:
  tmp=Path(tmp);a=g.Audit();g.verify_live(v,tmp,a,PROFILE);REQUESTS+=a.api_attempts
  g.write_private(tmp/'crt',v.cert);g.write_private(tmp/'key',v.key)
  ctx=ssl.create_default_context(cadata=v.ca);ctx.load_cert_chain(tmp/'crt',tmp/'key')
  conn=http.client.HTTPSConnection('127.0.0.1',59645,context=ctx,timeout=15)
  conn.request(method,path,body=json.dumps(obj) if obj else None,headers={'Accept':'application/json','Content-Type':'application/json'})
  res=conn.getresponse();data=json.loads(res.read());conn.close();REQUESTS+=1
  if res.status not in (200,201,404):raise RuntimeError('ISOLATED_API_ERROR '+str(res.status)+' '+data.get('reason',''))
  (OUT/'request-count.json').write_text(json.dumps({'isolatedApiRequests':REQUESTS,'productionApiRequests':0}))
  return res.status,data

def save(o):
 meta=o['metadata'];v={'apiVersion':o['apiVersion'],'kind':o['kind'],'namespace':meta.get('namespace'),'name':meta['name'],'uid':meta['uid'],'creationTimestamp':meta.get('creationTimestamp'),'resourceVersion':meta['resourceVersion'],'labels':meta.get('labels',{}),'annotations':meta.get('annotations',{})}
 if o['kind']=='Secret':v.update(type=o['type'],keyNames=sorted(o['data']),dataSha256=hashlib.sha256(json.dumps(o['data'],sort_keys=True,separators=(',',':')).encode()).hexdigest())
 if o['kind']=='Lease':v['holderIdentity']=o['spec']['holderIdentity']
 if o['kind'] in ('Role','ClusterRole'):v['rules']=o['rules']
 if o['kind'] in ('RoleBinding','ClusterRoleBinding'):v.update(roleRef=o['roleRef'],subjects=o['subjects'])
 LEDGER.append(v);(OUT/'object-ledger.json').write_text(json.dumps(LEDGER,indent=2))

def create(kind,name,ns=None,**fields):
 group='v1';plural={'Namespace':'namespaces','ServiceAccount':'serviceaccounts','Secret':'secrets','Role':'roles','RoleBinding':'rolebindings','ClusterRole':'clusterroles','ClusterRoleBinding':'clusterrolebindings','Lease':'leases'}[kind]
 if kind in ('Role','RoleBinding','ClusterRole','ClusterRoleBinding'):group='rbac.authorization.k8s.io/v1'
 if kind=='Lease':group='coordination.k8s.io/v1'
 collection=('/api/v1' if group=='v1' else '/apis/'+group)+('/namespaces/'+ns if ns else '')+'/'+plural
 status,_=api('GET',collection+'/'+name)
 if status!=404:raise RuntimeError('PREEXISTING_OBJECT_STOP '+kind+'/'+name)
 meta={'name':name,'labels':{'security-manager.test/run-id':RUN,'security-manager.test/purpose':'sops-controlled-compat'},'annotations':{'security-manager.test/kube-system-uid':PROFILE.binding.uid}}
 if ns:meta['namespace']=ns
 status,o=api('POST',collection,{'apiVersion':group,'kind':kind,'metadata':meta,**fields});assert status==201;save(o);return o

def main():
 # All official binaries must already match pins before any Kubernetes creation.
 plan=json.loads(Path('evidence/2026-11-02/sops-fixture-final-design/toolchain-plan.json').read_text())
 for name,sha in plan['frozenIndividualSha256'].items():assert hashlib.sha256((ROOT/'tools'/name).read_bytes()).hexdigest()==sha
 # Preflight all approved namespace names before the first mutation.
 for ns in ['petclinic','devsecops-system','data-infra']:
  code,_=api('GET','/api/v1/namespaces/'+ns)
  if code!=404:raise RuntimeError('PREEXISTING_NAMESPACE_STOP '+ns)
 for ns in ['petclinic','devsecops-system','data-infra']:create('Namespace',ns)
 for name in ['platform-secret-reconciler','kyverno-admission-controller','security-fixture-executor']:create('ServiceAccount',name,'devsecops-system',automountServiceAccountToken=False)
 for role in RB['roles']:
  create('Role',role['name'],role['namespace'],rules=role['rules'])
  create('RoleBinding',role['name']+'-binding',role['namespace'],roleRef={'apiGroup':'rbac.authorization.k8s.io','kind':'Role','name':role['name']},subjects=[role['subject']])
 cr=RB['clusterIdentityRole'];create('ClusterRole',cr['name'],rules=cr['rules']);create('ClusterRoleBinding',cr['name']+'-binding',roleRef={'apiGroup':'rbac.authorization.k8s.io','kind':'ClusterRole','name':cr['name']},subjects=cr['subjects'])
 code,t=api('POST','/api/v1/namespaces/devsecops-system/serviceaccounts/security-fixture-executor/token',{'apiVersion':'authentication.k8s.io/v1','kind':'TokenRequest','spec':{'expirationSeconds':3600}});assert code==201
 token=t['status']['token'];parts=token.split('.');claims=json.loads(base64.urlsafe_b64decode(parts[1]+'='*(-len(parts[1])%4)));assert len(claims['aud'])==1
 cfg=yaml.safe_load(PROFILE.binding.path.read_bytes());cfg['users'][0]['user']={'token':token}
 path=ROOT/'metadata/executor.kubeconfig';g.write_private(path,yaml.safe_dump(cfg).encode(),0o600)
 ns=next(o for o in LEDGER if o['kind']=='Namespace' and o['name']=='devsecops-system');sa=next(o for o in LEDGER if o['kind']=='ServiceAccount' and o['name']=='security-fixture-executor')
 p=g.Profile(name='MIN_RBAC_EXECUTOR',binding=g.replace(PROFILE.binding,path=path,config_sha=hashlib.sha256(path.read_bytes()).hexdigest()),identity='system:serviceaccount:devsecops-system:security-fixture-executor',groups=('system:serviceaccounts','system:serviceaccounts:devsecops-system','system:authenticated'),real_kubectl=PROFILE.real_kubectl,kubectl_sha=PROFILE.kubectl_sha,temp_parent=ROOT/'metadata',allowed_cwds=(ROOT,),service_account_namespace='devsecops-system',service_account_name='security-fixture-executor',service_account_uid=sa['uid'],namespace_uid=ns['uid'],token_issuer=claims['iss'],token_audience=claims['aud'][0])
 g.write_private(ROOT/'metadata/executor-profile.json',json.dumps(g.profile_document(p)).encode(),0o600)
 g.execute(str(path),{'KUBECONFIG':str(path)},profile=p,mode='check')
 (OUT/'min-identity.json').write_text(json.dumps({'status':'AUTHENTICATED','username':p.identity,'saUid':sa['uid'],'namespaceUid':ns['uid'],'issuer':claims['iss'],'audience':claims['aud'],'expirationTimestamp':t['status']['expirationTimestamp'],'configPath':str(path),'configSha256':p.binding.config_sha},indent=2))
 # RBAC checks run actual kubectl auth can-i only inside the approved min child boundary.
 g.execute(str(path),{'KUBECONFIG':str(path)},profile=p,mode='child',child_command=[sys.executable,str(OUT/'verify_rbac.py')],child_cwd=ROOT)
 import shutil;shutil.copyfile(ROOT/'evidence/rbac-verification.json',OUT/'rbac-verification.json')
 create('Lease','platform-heavy','data-infra',spec={'holderIdentity':RUN,'leaseDurationSeconds':3600,'renewTime':datetime.datetime.now(datetime.timezone.utc).isoformat().replace('+00:00','Z')})
 for o in INV['objects']:
  if o['kind']!='Secret':continue
  f=o['requiredFieldsDesign'];typ=o['type'];model=dict(f['dataKeysAndUnencodedValueDesign'])
  if typ=='kubernetes.io/dockerconfigjson':
   user,password=('FIXTURE_ONLY_PULL_USER','FIXTURE_ONLY_PULL_PASSWORD_A') if o['name']=='petclinic-harbor-pull' else ('FIXTURE_ONLY_VERIFY_USER','FIXTURE_ONLY_VERIFY_PASSWORD_A')
   model={'.dockerconfigjson':json.dumps({'auths':{'registry.fixture.invalid':{'username':user,'password':password}}},separators=(',',':'))}
  data={k:base64.b64encode((v if isinstance(v,str) else json.dumps(v,separators=(',',':'))).encode()).decode() for k,v in model.items()}
  desired={'apiVersion':'v1','kind':'Secret','metadata':{'name':o['name'],'namespace':o['namespace']},'type':typ,'data':data}
  plaintext=ROOT/'plaintext'/(o['name']+'.json');g.write_private(plaintext,json.dumps(desired,separators=(',',':')).encode(),0o600)
  created=create('Secret',o['name'],o['namespace'],type=typ,data=data)
  assert created['data']==data and created['type']==typ
 print('FIXTURE_KUBERNETES_BASELINE_CREATED')
if __name__=='__main__':main()
