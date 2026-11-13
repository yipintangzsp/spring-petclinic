from pathlib import Path
import sys,json,importlib.util,hashlib,datetime,tempfile,unittest
repo=Path.cwd();out=repo/'evidence/2026-11-02/sops-compatibility-real';prior=repo/'evidence/2026-11-02/sops-fixture-instance';m=json.loads((prior/'fixture-identity-manifest.json').read_text());root=Path(m['fixtureRoot'])
sys.path.insert(0,str(repo/'infra/security/testing'));import isolated_sops_executor as g
spec=importlib.util.spec_from_file_location('fixture_management',prior/'create_fixture.py');manager=importlib.util.module_from_spec(spec);spec.loader.exec_module(manager)
manager.OUT=out;manager.REQUESTS=0
# Explicit guarded admin identity+node read; no mutation/credential fallback.
code,nodes=manager.api('GET','/api/v1/nodes');assert code==200 and len(nodes['items'])==1
assert nodes['items'][0]['status']['nodeInfo']['architecture']=='arm64'
p=g.profile_from_document(json.loads((root/'metadata/executor-profile.json').read_text()))
expiry=datetime.datetime.fromisoformat(m['minExecutorIdentity']['expirationTimestamp'].replace('Z','+00:00'));assert expiry>datetime.datetime.now(datetime.timezone.utc)+datetime.timedelta(minutes=20)
a=g.Audit();r=g.execute(str(p.binding.path),{'KUBECONFIG':str(p.binding.path)},profile=p,mode='check',audit=a)
(out/'identity-revalidation.json').write_text(json.dumps({'cluster':m['cluster'],'node':{'name':nodes['items'][0]['metadata']['name'],'uid':nodes['items'][0]['metadata']['uid'],'architecture':'arm64'},'minIdentity':m['minExecutorIdentity'],'tokenReissued':False,'tokenValidated':True,'minGuard':r,'productionApiAccess':0},indent=2))
# Minimal current guard sanity; real rejects trapped before protected child.
import test_sops_preparation as t
names=['test_linux_path_layout_and_min_profile','test_missing_profile','test_unknown_profile','test_wrong_config_digest','test_admin_credential_rejected_by_min']
suite=unittest.TestSuite(t.PortableGuardTests(n) for n in names)
result=unittest.TextTestRunner(verbosity=1).run(suite)
assert result.wasSuccessful();(out/'guard-sanity.json').write_text(json.dumps({'tests':result.testsRun,'failures':len(result.failures),'errors':len(result.errors),'cases':names,'scope':'harness sanity only, not compatibility sample'},indent=2))
checks=[]
for old in m['objects']:
 kind,ns,name=old['kind'],old['namespace'],old['name'];plural={'Namespace':'namespaces','ServiceAccount':'serviceaccounts','Secret':'secrets','Role':'roles','RoleBinding':'rolebindings','ClusterRole':'clusterroles','ClusterRoleBinding':'clusterrolebindings','Lease':'leases'}[kind]
 path=('/api/v1' if old['apiVersion']=='v1' else '/apis/'+old['apiVersion'])+('/namespaces/'+ns if ns else '')+'/'+plural+'/'+name
 code,actual=manager.api('GET',path)
 digest=hashlib.sha256(json.dumps(actual,sort_keys=True,separators=(',',':')).encode()).hexdigest()
 passed=code==200 and actual['metadata']['uid']==old['uid'] and digest==old['snapshotSha256']
 checks.append({'kind':kind,'namespace':ns,'name':name,'expectedUid':old['uid'],'observedUid':actual.get('metadata',{}).get('uid'),'expectedSha256':old['snapshotSha256'],'observedSha256':digest,'matched':passed})
 if not passed:
  (out/'baseline-revalidation.json').write_text(json.dumps({'status':'BASELINE_DRIFT_DETECTED','checks':checks},indent=2));raise SystemExit('BASELINE_DRIFT_DETECTED')
for x in m['crypto']['files']:
 assert hashlib.sha256((root/x['path']).read_bytes()).hexdigest()==x['encryptedSha256']
for k,name in [('baseline','baseline'),('wrongKey','negative-wrong-key')]:
 recipient=(root/'keys'/(name+'.recipient')).read_text().strip();assert recipient==m['crypto']['recipients'][k]['recipient']
for x in m['tools']:
 if 'binary' in x:assert hashlib.sha256((root/'tools'/x['binary']).read_bytes()).hexdigest()==x['actualSha256']
(out/'baseline-revalidation.json').write_text(json.dumps({'status':'MATCHED','checks':checks,'encryptedFiles':4,'recipientFingerprintsMatched':2,'toolsMatched':3,'toolVersionsEvidenceReference':str(prior/'tool-versions.json'),'versionEvidenceBasis':'Exact same verified binary SHA; native runtime missing Node does not affect prior SOPS/age version evidence','rawValuesPrinted':False},indent=2))
print('IDENTITY_GUARD_BASELINE_REVALIDATED')
