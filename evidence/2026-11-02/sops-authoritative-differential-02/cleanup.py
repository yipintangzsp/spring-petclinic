"""Exact-name/UID, run-owned fixture cleanup after immutable evidence acceptance."""
from pathlib import Path
import sys,json,importlib.util,hashlib,shutil,time,ssl,http.client,subprocess
repo=Path.cwd();out=repo/'evidence/2026-11-02/sops-authoritative-differential-02';prior=repo/'evidence/2026-11-02/sops-authoritative-baseline-02'
sys.path.insert(0,str(repo/'infra/security/testing'));import isolated_sops_executor as g
spec=importlib.util.spec_from_file_location('cleanup_admin',prior/'create_fixture.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);m.OUT=out;m.REQUESTS=0
b=json.loads((prior/'authoritative-baseline.json').read_text());root=Path(b['root']);final=json.loads((out/'final-clean-state.json').read_text());objects=b['objects'];currentUids={(o['kind'],o['namespace'],o['name']):o['uid'] for o in final['objects']};log=[]
assert json.loads((out/'precleanup-acceptance.json').read_text())['status']=='PASS'
index=json.loads((out/'precleanup-evidence-index.json').read_text())
for n,h in index['files'].items():assert hashlib.sha256((out/n).read_bytes()).hexdigest()==h
def persist(status='IN_PROGRESS'):(out/'cleanup-result.json').write_text(json.dumps({'status':status,'operations':log,'kindClusterDeleted':False,'productionApiAccess':0},indent=2))
def path(o):
 plural={'Namespace':'namespaces','ServiceAccount':'serviceaccounts','Secret':'secrets','Role':'roles','RoleBinding':'rolebindings','ClusterRole':'clusterroles','ClusterRoleBinding':'clusterrolebindings','Lease':'leases'}[o['kind']]
 return ('/api/v1' if o['apiVersion']=='v1' else '/apis/'+o['apiVersion'])+('/namespaces/'+o['namespace'] if o['namespace'] else '')+'/'+plural+'/'+o['name']
for o in objects:
 code,c=m.api('GET',path(o));assert code==200 and c['metadata']['uid']==currentUids[(o['kind'],o['namespace'],o['name'])] and c['metadata']['labels'].get('security-manager.test/run-id')=='sm-sops-20261102-02'
for ns in ['petclinic','devsecops-system','data-infra']:
 for resource in ['pods','persistentvolumeclaims','services','replicationcontrollers','configmaps','serviceaccounts','secrets']:
  code,listing=m.api('GET','/api/v1/namespaces/'+ns+'/'+resource);assert code==200
  for item in listing['items']:
   name=item['metadata']['name'];known=any(o['namespace']==ns and o['name']==name and currentUids[(o['kind'],o['namespace'],o['name'])]==item['metadata']['uid'] for o in objects)
   automatic=(resource=='configmaps' and name=='kube-root-ca.crt') or (resource=='serviceaccounts' and name=='default')
   assert known or automatic,'FOREIGN_RESOURCE_STOP '+ns+'/'+resource+'/'+name
log.append({'kind':'PreCleanupOwnershipAndForeignWorkloadCheck','status':'PASS','objects':23});persist()
profile=g.profile_from_document(json.loads((root/'metadata/executor-profile.json').read_text()));validated=g.validate(str(profile.binding.path),{'KUBECONFIG':str(profile.binding.path)},profile=profile)
order=['Lease','RoleBinding','ClusterRoleBinding','Role','ClusterRole','ServiceAccount','Secret','Namespace']
for kind in order:
 for o in [x for x in objects if x['kind']==kind]:
  uid=currentUids[(kind,o['namespace'],o['name'])];u=path(o);code,c=m.api('GET',u);assert code==200 and c['metadata']['uid']==uid
  m.api('DELETE',u,{'apiVersion':'v1','kind':'DeleteOptions','preconditions':{'uid':uid}})
  for _ in range(80):
   code,_body=m.api('GET',u)
   if code==404:break
   time.sleep(.25)
  assert code==404,'DELETE_NOT_COMPLETE'
  log.append({'kind':kind,'namespace':o['namespace'],'name':o['name'],'uid':uid,'absent':True});persist()
# Negative auth probe with the same token after SA deletion: real pinned TLS, no admin fallback.
conn=http.client.HTTPSConnection('127.0.0.1',59645,context=ssl.create_default_context(cadata=validated.ca),timeout=10)
conn.request('POST','/apis/authentication.k8s.io/v1/selfsubjectreviews',body=json.dumps({'apiVersion':'authentication.k8s.io/v1','kind':'SelfSubjectReview'}),headers={'Authorization':'Bearer '+validated.token,'Content-Type':'application/json'})
res=conn.getresponse();status=res.status;res.read();conn.close();assert status==401
log.append({'kind':'DeletedServiceAccountTokenInvalidation','httpStatus':status,'status':'PASS'});persist()
for file in b['crypto']['files']:
 p=root/file['path'];copy=out/'encrypted-evidence'/p.name;assert hashlib.sha256(copy.read_bytes()).hexdigest()==file['encryptedSha256'];assert hashlib.sha256(p.read_bytes()).hexdigest()==file['encryptedSha256']
for name in ['baseline.agekey','negative-wrong-key.agekey']:
 p=root/'keys'/name;assert not p.is_symlink() and p.stat().st_mode&0o777==0o600;p.unlink();assert not p.exists();log.append({'kind':'AgePrivateKey','name':name,'removed':True});persist()
for name in ['executor.kubeconfig','executor-profile.json']:
 p=root/'metadata'/name;assert not p.is_symlink();p.unlink();log.append({'kind':'ExecutorCredentialMaterial','name':name,'removed':True});persist()
docker=['/opt/homebrew/bin/docker','--host','unix:///Users/zhangsir/.colima/security-test/docker.sock']
remaining=subprocess.check_output(docker+['ps','-a','--format','{{.Names}}'],text=True).splitlines();assert not any(n.startswith('sm-sops-diff-') for n in remaining)
assert 'security-test-sops-control-plane' in remaining
log.append({'kind':'DisposableExecutors','remaining':0,'kindRetained':True});persist()
assert str(root).startswith('/private/tmp/sm-sops-20261102-02-') and root.is_dir() and not root.is_symlink();shutil.rmtree(root);assert not root.exists()
log.append({'kind':'PrivateTestRoot','removed':True,'privateKeysOrTokensArchived':False,'temporaryDecryptedFilesRemaining':0});persist('COMPLETE')
print('FIXTURE_CLEANUP_COMPLETE: 23 owned objects removed, token HTTP 401, keys/config removed, kind retained')
