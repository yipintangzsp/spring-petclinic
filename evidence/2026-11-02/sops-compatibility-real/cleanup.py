from pathlib import Path
import sys,json,importlib.util,hashlib,shutil,time,os,stat
repo=Path.cwd();out=repo/'evidence/2026-11-02/sops-compatibility-real';prior=repo/'evidence/2026-11-02/sops-fixture-instance';manifest=json.loads((prior/'fixture-identity-manifest.json').read_text());root=Path(manifest['fixtureRoot'])
spec=importlib.util.spec_from_file_location('fixture_management_cleanup',prior/'create_fixture.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);m.OUT=out;m.REQUESTS=0
objects=manifest['objects'];log=[]
def persist(): (out/'cleanup-result.json').write_text(json.dumps({'operations':log,'kindClusterDeleted':False},indent=2))
def path(o):
 plural={'Namespace':'namespaces','ServiceAccount':'serviceaccounts','Secret':'secrets','Role':'roles','RoleBinding':'rolebindings','ClusterRole':'clusterroles','ClusterRoleBinding':'clusterrolebindings','Lease':'leases'}[o['kind']]
 return ('/api/v1' if o['apiVersion']=='v1' else '/apis/'+o['apiVersion'])+('/namespaces/'+o['namespace'] if o['namespace'] else '')+'/'+plural+'/'+o['name']
# All resource identities must still match before any deletion.
for o in objects:
 code,current=m.api('GET',path(o));assert code==200 and current['metadata']['uid']==o['uid'] and current['metadata']['labels'].get('security-manager.test/run-id')=='sm-sops-20261102-01'
# No foreign workload/storage is allowed to be swept by namespace deletion.
for ns in ['petclinic','devsecops-system','data-infra']:
 for resource in ['pods','persistentvolumeclaims','services','replicationcontrollers','configmaps','serviceaccounts','secrets']:
  code,listing=m.api('GET','/api/v1/namespaces/'+ns+'/'+resource);assert code==200
  for item in listing['items']:
   name=item['metadata']['name'];kind=item['kind'] if 'kind' in item else {'configmaps':'ConfigMap','serviceaccounts':'ServiceAccount','secrets':'Secret'}.get(resource,'UNKNOWN')
   known=any(o['namespace']==ns and o['name']==name and o['uid']==item['metadata']['uid'] for o in objects)
   auto=(resource=='configmaps' and name=='kube-root-ca.crt') or (resource=='serviceaccounts' and name=='default')
   if not (known or auto):raise RuntimeError('FOREIGN_RESOURCE_STOP '+ns+'/'+resource+'/'+name)
# Preserve ciphertext evidence and immutable public metadata, never private keys.
(out/'encrypted-evidence').mkdir(exist_ok=False)
for file in manifest['crypto']['files']:
 p=root/file['path'];assert hashlib.sha256(p.read_bytes()).hexdigest()==file['encryptedSha256'];shutil.copyfile(p,out/'encrypted-evidence'/p.name);p.unlink()
 log.append({'kind':'EncryptedRuntimeCopy','name':p.name,'removed':True,'safeEvidenceCopyRetained':True});persist()
for name in ['baseline','negative-wrong-key']:
 key=root/'keys'/(name+'.agekey');assert not key.is_symlink() and stat.S_IMODE(key.stat().st_mode)==0o600
 key.unlink();assert not key.exists();log.append({'kind':'AgePrivateKey','purpose':name,'removed':True});persist()
 pub=root/'keys'/(name+'.recipient');pub.unlink()
for name in ['executor.kubeconfig','executor-profile.json']:
 p=root/'metadata'/name
 if p.exists():assert not p.is_symlink();p.unlink()
# Deletes are exact-name and UID-preconditioned through the same pinned admin guard.
order=['Lease','RoleBinding','ClusterRoleBinding','Role','ClusterRole','ServiceAccount','Secret','Namespace']
for kind in order:
 for o in [x for x in objects if x['kind']==kind]:
  url=path(o);code,current=m.api('GET',url);assert code==200 and current['metadata']['uid']==o['uid']
  code,result=m.api('DELETE',url,{'apiVersion':'v1','kind':'DeleteOptions','preconditions':{'uid':o['uid']}})
  for _ in range(40):
   code,_body=m.api('GET',url)
   if code==404:break
   time.sleep(.25)
  assert code==404,'DELETE_NOT_COMPLETE'
  log.append({'kind':kind,'namespace':o['namespace'],'name':o['name'],'uid':o['uid'],'absent':True});persist()
# Retained binaries are not needed after stopped compatibility run; remove only owned test scope.
assert str(root).startswith('/private/tmp/sops-fixture-sm-sops-20261102-01-') and not root.is_symlink()
shutil.rmtree(root);assert not root.exists()
log.append({'kind':'PrivateTestRoot','removed':True,'privateKeysOrTokensArchived':False});persist()
print('EXACT_FIXTURE_CLEANUP_COMPLETE; kind retained')
