from pathlib import Path
import sys,json,importlib.util,base64,hashlib,os,tempfile,unittest
repo=Path.cwd();out=repo/'evidence/2026-11-02/sops-authoritative-differential-02';prior=repo/'evidence/2026-11-02/sops-authoritative-baseline-02'
sys.path.insert(0,str(repo/'infra/security/testing'));import isolated_sops_executor as g
spec=importlib.util.spec_from_file_location('fixture_admin',prior/'create_fixture.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);m.OUT=out;m.REQUESTS=0
baseline=json.loads((prior/'authoritative-baseline.json').read_text());root=Path(baseline['root']);profilepath=root/'metadata/executor-profile.json';old=g.profile_from_document(json.loads(profilepath.read_text()))
# New token for exact SAME serviceaccount, no RBAC mutation.
status,token=m.api('POST','/api/v1/namespaces/devsecops-system/serviceaccounts/security-fixture-executor/token',{'apiVersion':'authentication.k8s.io/v1','kind':'TokenRequest','spec':{'expirationSeconds':3600}});assert status==201
import yaml
cfg=yaml.safe_load(old.binding.path.read_bytes());cfg['users'][0]['user']={'token':token['status']['token']};claims=json.loads(base64.urlsafe_b64decode(token['status']['token'].split('.')[1]+'=='));assert claims['sub']==old.identity and claims['kubernetes.io']['serviceaccount']['uid']==old.service_account_uid
raw=yaml.safe_dump(cfg).encode();tmp=old.binding.path.with_suffix('.rotated');g.write_private(tmp,raw,0o600);os.replace(tmp,old.binding.path)
p=g.replace(old,binding=g.replace(old.binding,config_sha=hashlib.sha256(raw).hexdigest()));tmp=profilepath.with_suffix('.rotated');g.write_private(tmp,json.dumps(g.profile_document(p)).encode(),0o600);os.replace(tmp,profilepath)
result=g.execute(str(p.binding.path),{'KUBECONFIG':str(p.binding.path)},profile=p,mode='check')
(out/'token-refresh.json').write_text(json.dumps({'sameSA':p.identity,'sameSAUid':p.service_account_uid,'sameRbac':True,'issuer':p.token_issuer,'audience':p.token_audience,'iat':claims['iat'],'exp':claims['exp'],'expiry':token['status']['expirationTimestamp'],'configShaBefore':old.binding.config_sha,'configShaAfter':p.binding.config_sha,'oldTokenDiscarded':True,'authentication':result},indent=2))
g.execute(str(p.binding.path),{'KUBECONFIG':str(p.binding.path)},profile=p,mode='child',child_command=[sys.executable,str(prior/'verify_rbac.py')],child_cwd=root)
import shutil;shutil.copyfile(root/'evidence/rbac-verification.json',out/'auth-recheck.json')
import test_sops_preparation as t
names=['test_linux_path_layout_and_min_profile','test_missing_profile','test_unknown_profile','test_wrong_config_digest','test_admin_credential_rejected_by_min'];res=unittest.TextTestRunner().run(unittest.TestSuite(t.PortableGuardTests(n) for n in names));assert res.wasSuccessful();(out/'guard-sanity.json').write_text(json.dumps({'tests':res.testsRun,'failures':len(res.failures),'errors':len(res.errors)},indent=2))
checks=[]
for o in baseline['objects']:
 plural={'Namespace':'namespaces','ServiceAccount':'serviceaccounts','Secret':'secrets','Lease':'leases','Role':'roles','RoleBinding':'rolebindings','ClusterRole':'clusterroles','ClusterRoleBinding':'clusterrolebindings'}[o['kind']]
 url=('/api/v1' if o['apiVersion']=='v1' else '/apis/'+o['apiVersion'])+('/namespaces/'+o['namespace'] if o['namespace'] else '')+'/'+plural+'/'+o['name'];code,obj=m.api('GET',url);digest=hashlib.sha256(json.dumps(obj,sort_keys=True,separators=(',',':')).encode()).hexdigest();ok=code==200 and obj['metadata']['uid']==o['uid'] and digest==o['snapshotSha256'];checks.append({'kind':o['kind'],'name':o['name'],'uid':o['uid'],'hashMatches':ok})
 if not ok:(out/'precheck.json').write_text(json.dumps({'status':'BASELINE_DRIFT_DETECTED','checks':checks},indent=2));raise SystemExit('BASELINE_DRIFT_DETECTED')
for n,h in baseline['frozenSourceSha256'].items():assert hashlib.sha256((repo/n).read_bytes()).hexdigest()==h
for x in baseline['crypto']['files']:assert hashlib.sha256((root/x['path']).read_bytes()).hexdigest()==x['encryptedSha256']
for name,rec in [('baseline','baseline'),('negative-wrong-key','wrongKey')]:assert (root/'keys'/(name+'.recipient')).read_text().strip()==baseline['crypto']['recipients'][rec]['recipient']
for x in baseline['toolchain']:
 if 'binary' in x:assert hashlib.sha256((root/'tools'/x['binary']).read_bytes()).hexdigest()==x['actualSha256']
nodeprior=repo/'evidence/2026-11-02/node-executor';nroot=Path(json.loads((nodeprior/'runtime-root.json').read_text())['path']);nh=json.loads((nodeprior/'verified-node.json').read_text());assert hashlib.sha256((nroot/'runtime/bin/node').read_bytes()).hexdigest()==nh['binarySha256']
(out/'precheck.json').write_text(json.dumps({'status':'MATCHED','objects':checks,'frozenSources':baseline['frozenSourceSha256'],'toolsAndCiphertextsMatched':True,'tokenRotationOnlyExpectedChange':True},indent=2));print('NEW_TOKEN_REAL_AUTH_27CHECKS_BASELINE_MATCHED')
