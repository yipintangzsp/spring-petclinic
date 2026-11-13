from pathlib import Path
import importlib.util,json,hashlib,sys,stat,shutil
out=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('fixture_manager',out/'create_fixture.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
m.REQUESTS=json.loads((out/'request-count.json').read_text())['isolatedApiRequests']
root=m.ROOT;created=json.loads((out/'object-ledger.json').read_text());crypto=json.loads((out/'crypto-evidence.json').read_text());snapshot=[]
for entry in created:
 kind,name,ns=entry['kind'],entry['name'],entry['namespace'];plural={'Namespace':'namespaces','ServiceAccount':'serviceaccounts','Secret':'secrets','Role':'roles','RoleBinding':'rolebindings','ClusterRole':'clusterroles','ClusterRoleBinding':'clusterrolebindings','Lease':'leases'}[kind]
 group='/api/v1' if entry['apiVersion']=='v1' else '/apis/'+entry['apiVersion'];path=group+('/namespaces/'+ns if ns else '')+'/'+plural+'/'+name
 status,obj=m.api('GET',path);assert status==200 and obj['metadata']['uid']==entry['uid']
 if kind=='Secret':
  digest=hashlib.sha256(json.dumps(obj['data'],sort_keys=True,separators=(',',':')).encode()).hexdigest()
  assert digest==entry['dataSha256']==next(x['dataSha256'] for x in crypto['files'] if x['name']==name)
 if kind in ['Role','ClusterRole']:assert obj['rules']==entry['rules']
 if kind in ['RoleBinding','ClusterRoleBinding']:assert obj['roleRef']==entry['roleRef'] and obj['subjects']==entry['subjects']
 if kind=='Lease':assert obj['spec']['holderIdentity']=='sm-sops-20261102-02'
 snapshot.append({**entry,'snapshotSha256':hashlib.sha256(json.dumps(obj,sort_keys=True,separators=(',',':')).encode()).hexdigest(),'observedResourceVersion':obj['metadata']['resourceVersion']})
for result in crypto['files']:
 assert hashlib.sha256((root/result['path']).read_bytes()).hexdigest()==result['encryptedSha256']
for name in ['baseline','negative-wrong-key']:
 assert stat.S_IMODE((root/'keys'/(name+'.agekey')).stat().st_mode)==0o600
assert stat.S_IMODE((root/'keys').stat().st_mode)==0o700
manifest={'classification':'REAL_ISOLATED_FIXTURE_BASELINE_NOT_GATE_COMPATIBILITY','fixtureRoot':str(root),'cluster':{'name':'security-test-sops','dockerEndpoint':'unix:///Users/zhangsir/.colima/security-test/docker.sock','server':m.PROFILE.binding.server,'kubeSystemUid':m.PROFILE.binding.uid,'caSha256':m.PROFILE.binding.ca_sha,'dedicatedKubeconfigPath':str(m.PROFILE.binding.path),'kubeconfigSha256':m.PROFILE.binding.config_sha,'architecture':'arm64'},'objects':snapshot,'crypto':crypto,'tools':json.loads((out/'toolchain-download.json').read_text()),'minExecutorIdentity':json.loads((out/'min-identity.json').read_text()),'rbac':json.loads((out/'rbac-verification.json').read_text()),'productionApiAccess':0,'productionSecretCredentialValueReads':0,'productionAgeKeyReads':0,'gateExecutions':0,'policyCompatibilityCasesAdded':0}
(out/'fixture-identity-manifest.json').write_text(json.dumps(manifest,indent=2));(root/'evidence/fixture-identity-manifest.json').write_text(json.dumps(manifest,indent=2))
# Metadata captured before deletion; encrypted fixtures and both keys retained.
plain=[]
for file in (root/'plaintext').glob('*.json'):
 plain.append({'name':file.name,'sha256':hashlib.sha256(file.read_bytes()).hexdigest(),'removed':True});file.unlink()
(out/'plaintext-cleanup.json').write_text(json.dumps({'files':plain,'remaining':len(list((root/'plaintext').iterdir()))},indent=2))
(out/'baseline-snapshot.json').write_text(json.dumps({'objects':snapshot,'encryptedFiles':crypto['files'],'publicKeyFingerprints':crypto['recipients'],'tools':manifest['tools'],'exactUidAndFingerprintMatch':True,'privateKeysRetainedMode':'0600','plaintextCopiesRemoved':len(plain)},indent=2))
print(json.dumps({'snapshotObjects':len(snapshot),'sameUIDs':True,'secretFingerprintsMatchDecryption':True,'positiveDecrypt':len(crypto['files']),'wrongKeyExit':crypto['wrongKey']['exitCode'],'plaintextRemoved':len(plain)}))
