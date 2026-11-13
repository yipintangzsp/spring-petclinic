"""Harness tests only; fake auth/TLS responses are explicit and never compatibility evidence.

Real subprocess/signal/timeout tests use harmless Python sentinels. No SOPS, Gate,
Kubernetes objects, actual API, or Policy evaluation. Runs on macOS and Linux.
"""
import base64
import copy
from dataclasses import replace
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import signal
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

import yaml

ROOT = Path(__file__).resolve().parent

def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    m = importlib.util.module_from_spec(spec)
    sys.modules[name] = m
    spec.loader.exec_module(m)
    return m

g = load('portable_boundary', ROOT/'isolated_sops_executor.py')
o = load('observations', ROOT/'sops_observation.py')
RECORDS = []


def jwt(identity='system:serviceaccount:devsecops-system:security-fixture-executor', *, age=0, uid='synthetic-sa-uid', alg='RS256'):
    now = int(time.time())
    def enc(obj):return base64.urlsafe_b64encode(json.dumps(obj).encode()).decode().rstrip('=')
    return '.'.join([enc({'alg':alg,'typ':'JWT'}), enc({'sub':identity,'iss':'https://synthetic-issuer.invalid',
                    'aud':['synthetic-test-api'],'iat':now-10+age,'nbf':now-10+age,'exp':now+3500+age,
                    'kubernetes.io':{'namespace':'devsecops-system','serviceaccount':{'name':'security-fixture-executor','uid':uid}}}), 'SYNTHETIC_SIGNATURE_NOT_AUTHENTICATED'])


class Setup(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='portable-harness-')
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve()
        self.work = self.root/'linux-layout'/'fixture'/'work'
        self.work.mkdir(parents=True, mode=0o700)
        self.kubectl = self.root/'kubectl'
        self.kubectl.write_text('#!'+sys.executable+'\nprint("HARMLESS_KUBECTL_SENTINEL_NO_API")\n')
        self.kubectl.chmod(0o500)
        self.ca = b'-----BEGIN CERTIFICATE-----\nYWJj\n-----END CERTIFICATE-----\n'  # Offline-only DER placeholder, never trusted as TLS.
        self.config = self.root/'executor-kubeconfig'
        self.config.write_text(yaml.safe_dump(self.config_obj({'token':jwt()})))
        self.config.chmod(0o600)
        b = g.Binding(path=self.config, context='isolated-test', cluster='isolated-test',
            server='https://127.0.0.1:16443', uid='synthetic-cluster-uid', ca_sha=hashlib.sha256(b'abc').hexdigest(),
            config_sha=hashlib.sha256(self.config.read_bytes()).hexdigest())
        self.profile = g.Profile(name='MIN_RBAC_EXECUTOR',binding=b,
            identity='system:serviceaccount:devsecops-system:security-fixture-executor',
            groups=('system:serviceaccounts','system:serviceaccounts:devsecops-system','system:authenticated'),
            real_kubectl=self.kubectl,kubectl_sha=hashlib.sha256(self.kubectl.read_bytes()).hexdigest(),
            temp_parent=self.root,allowed_cwds=(self.work,),service_account_namespace='devsecops-system',
            service_account_name='security-fixture-executor',service_account_uid='synthetic-sa-uid',
            namespace_uid='synthetic-namespace-uid',token_issuer='https://synthetic-issuer.invalid',token_audience='synthetic-test-api')
        self.env = {'KUBECONFIG':str(self.config),'HOME':'/UNTRUSTED_HOME','AWS_PROFILE':'DO_NOT_INHERIT','SSH_AUTH_SOCK':'DO_NOT_INHERIT','LANG':'C.UTF-8'}

    def config_obj(self, auth):
        return {'kind':'Config','apiVersion':'v1','current-context':'isolated-test',
            'contexts':[{'name':'isolated-test','context':{'cluster':'isolated-test','user':'isolated-test'}}],
            'clusters':[{'name':'isolated-test','cluster':{'server':'https://127.0.0.1:16443','certificate-authority-data':base64.b64encode(self.ca).decode()}}],
            'users':[{'name':'isolated-test','user':auth}]}

    def rewrite(self, obj, profile=None):
        self.config.chmod(0o600)
        self.config.write_text(yaml.safe_dump(obj))
        p=profile or self.profile
        return replace(p,binding=replace(p.binding,config_sha=hashlib.sha256(self.config.read_bytes()).hexdigest()))

    def rejected(self, profile, reason=None, env=None):
        audit=g.Audit()
        with patch('socket.create_connection',side_effect=AssertionError('NO_NETWORK')) as network, \
             patch.object(g.subprocess,'run',side_effect=AssertionError('NO_PROTECTED_CHILD')) as child:
            with self.assertRaises(g.BoundaryError) as err:
                g.execute(str(self.config),self.env if env is None else env,profile=profile,audit=audit)
            if reason:self.assertEqual(str(err.exception),reason)
            self.assertEqual(network.call_count,0);self.assertEqual(child.call_count,0)
        self.assertEqual(vars(audit),{'api_attempts':0,'kubectl_invocations':0,'child_executions':0})
        RECORDS.append({'test':self.id(),'classification':'OFFLINE_NEGATIVE_GUARD_TEST','reason':str(err.exception),'actualApiRequests':0,'protectedChildren':0})

    def boundary_env(self):
        root=self.root/'boundary';root.mkdir(mode=0o700)
        for n in ('home','bin','tmp','cache'):(root/n).mkdir(mode=0o700)
        g.write_private(root/'kubeconfig',self.config.read_bytes())
        g.write_private(root/'context.json',json.dumps(g.profile_document(self.profile)).encode())
        return g.child_environment(root,self.env,self.profile)

    def ssr(self, profile=None):
        p=profile or self.profile
        return {'kind':'SelfSubjectReview','status':{'userInfo':{'username':p.identity,'uid':p.service_account_uid,'groups':list(p.groups)}}}


class PortableGuardTests(Setup):
    def test_linux_path_layout_and_min_profile(self):
        v=g.validate(str(self.config),self.env,profile=self.profile)
        self.assertTrue(v.token);self.assertFalse(v.cert)
        doc=g.profile_document(self.profile)
        self.assertEqual(g.profile_from_document(doc),self.profile)
        self.assertNotIn('/Users/',json.dumps(doc));self.assertNotIn('/opt/homebrew',json.dumps(doc))

    def test_missing_profile(self):self.rejected(None,'PROFILE_REQUIRED')
    def test_unknown_profile(self):self.rejected(replace(self.profile,name='auto'),'UNKNOWN_PROFILE')
    def test_wrong_sa_identity(self):self.rejected(replace(self.profile,service_account_name='wrong'),'SERVICE_ACCOUNT_IDENTITY_MISMATCH')
    def test_wrong_ca(self):self.rejected(replace(self.profile,binding=replace(self.profile.binding,ca_sha='0'*64)),'CA_IDENTITY_MISMATCH')
    def test_wrong_server(self):self.rejected(replace(self.profile,binding=replace(self.profile.binding,server='https://192.0.2.1:16443')),'SERVER_MISMATCH')
    def test_wrong_config_digest(self):self.rejected(replace(self.profile,binding=replace(self.profile.binding,config_sha='0'*64)),'CONFIG_DIGEST_MISMATCH')

    def test_admin_credential_rejected_by_min(self):
        p=self.rewrite(self.config_obj({'client-certificate-data':base64.b64encode(b'SYNTHETIC_ADMIN_CERT').decode(),'client-key-data':base64.b64encode(b'SYNTHETIC_ADMIN_KEY_NOT_KEY_MATERIAL').decode()}))
        self.rejected(p,'EXTERNAL_AUTH_FORBIDDEN')

    def test_min_credential_rejected_by_admin(self):
        p=replace(self.profile,name='ADMIN_VALIDATION',identity='synthetic-admin',groups=('system:authenticated',))
        self.rejected(p,'EXTERNAL_AUTH_FORBIDDEN')

    def test_no_implicit_profile_or_binding_fallback(self):
        with self.assertRaises(g.BoundaryError):g.validate(str(self.config),self.env,binding=self.profile.binding)

    def test_expired_token(self):
        p=self.rewrite(self.config_obj({'token':jwt(age=-4000)}))
        self.rejected(p,'TOKEN_EXPIRED_OR_LIFETIME_INVALID')

    def test_token_wrong_sa_uid(self):
        p=self.rewrite(self.config_obj({'token':jwt(uid='wrong')}));self.rejected(p,'TOKEN_SERVICE_ACCOUNT_MISMATCH')

    def test_token_none_algorithm(self):
        p=self.rewrite(self.config_obj({'token':jwt(alg='none')}));self.rejected(p,'TOKEN_ALGORITHM_FORBIDDEN')

    def test_live_wrong_identity(self):
        obj=self.ssr();obj['status']['userInfo']['username']='kubernetes-admin'
        with self.assertRaisesRegex(g.BoundaryError,'LIVE_AUTH_IDENTITY_MISMATCH'):g.check_identity_response(obj,self.profile)

    def test_live_wrong_sa_uid(self):
        obj=self.ssr();obj['status']['userInfo']['uid']='wrong'
        with self.assertRaisesRegex(g.BoundaryError,'LIVE_SERVICE_ACCOUNT_UID_MISMATCH'):g.check_identity_response(obj,self.profile)

    def test_live_unexpected_group(self):
        obj=self.ssr();obj['status']['userInfo']['groups'].append('system:masters')
        with self.assertRaisesRegex(g.BoundaryError,'LIVE_AUTH_IDENTITY_MISMATCH'):g.check_identity_response(obj,self.profile)

    def fake_https(self, wrong_uid=False):
        test=self;calls=[]
        class Response:
            status=201
            def __init__(self,obj):self.obj=obj
            def read(self,n):return json.dumps(self.obj).encode()
        class Connection:
            def __init__(self,host,port,**kw):
                test.assertEqual((host,port),('127.0.0.1',16443))
            def request(self,method,path,body=None,headers=None):
                calls.append((method,path));self.path=path
                test.assertTrue(headers['Authorization'].startswith('Bearer '))
            def getresponse(self):
                if self.path.endswith('selfsubjectreviews'):return Response(test.ssr())
                name=self.path.split('/')[-1]
                uid=test.profile.binding.uid if name=='kube-system' else test.profile.namespace_uid
                return Response({'kind':'Namespace','metadata':{'name':name,'uid':'WRONG' if wrong_uid else uid}})
            def close(self):pass
        return Connection,calls

    def test_authenticated_live_validation_logic_synthetic_transport(self):
        conn,calls=self.fake_https()
        v=g.validate(str(self.config),self.env,profile=self.profile)
        with patch.object(g.ssl,'create_default_context'),patch.object(g.http.client,'HTTPSConnection',conn):
            g.verify_live(v,self.root,g.Audit(),self.profile)
        self.assertEqual(len(calls),3)
        RECORDS.append({'test':self.id(),'classification':'SYNTHETIC_HTTPS_RESPONSE_UNIT_TEST','actualApiRequests':0})

    def test_wrong_uid_blocks_protected_child(self):
        conn,_=self.fake_https(wrong_uid=True);audit=g.Audit()
        with patch.object(g.ssl,'create_default_context'),patch.object(g.http.client,'HTTPSConnection',conn),patch.object(g.subprocess,'run') as child:
            with self.assertRaisesRegex(g.BoundaryError,'LIVE_NAMESPACE_UID_MISMATCH'):
                g.execute(str(self.config),self.env,mode='sentinel',profile=self.profile,audit=audit)
            self.assertEqual(child.call_count,0)
        self.assertEqual(audit.child_executions,0)
        self.assertFalse(list(self.root.glob('isolated-sops-boundary-*')))

    def test_real_sentinel_clean_home_and_cleanup(self):
        with patch.object(g,'verify_live') as identity:
            r=g.execute(str(self.config),self.env,mode='sentinel',profile=self.profile)
        self.assertTrue(r['temporaryDirectoryRemoved']);self.assertEqual(r['audit']['child_executions'],1)
        self.assertNotIn('AWS_PROFILE',r['environment']['explicitlySet']);self.assertEqual(identity.call_count,1)
        RECORDS.append({'test':self.id(),'classification':'REAL_SENTINEL_SYNTHETIC_IDENTITY_VALIDATION','actualApiRequests':0,'protectedChildren':1})

    def test_home_override_and_default_kubeconfig(self):
        env=self.boundary_env()
        fake=self.root/'fake-home';(fake/'.kube').mkdir(parents=True);(fake/'.kube/config').write_text('MUST_NOT_READ')
        env['HOME']=str(fake)
        with self.assertRaisesRegex(g.BoundaryError,'CHILD_ENVIRONMENT_CHANGED'):g.proxy_argv(['get','nodes'],env)

    def test_proxy_rejects_connection_flags(self):
        env=self.boundary_env()
        for args in [['--server=x'],['-shttps://example.invalid'],['--kubeconfig=x'],['--user=x'],['--insecure-skip-tls-verify'],['apply','-f=https://example.invalid']]:
            with self.subTest(args=args),self.assertRaises(g.BoundaryError):g.proxy_argv(args,env)

    def test_proxy_honors_explicit_linux_kubectl_and_actual_no_api_shim(self):
        env=self.boundary_env()
        argv=g.proxy_argv(['get','sentinel'],env)
        self.assertEqual(argv[0],str(self.kubectl))
        r=o.observe_child(argv,env=env,cwd=self.work,identity=self.profile.identity,evidence_ref='memory://proxy-sentinel')
        self.assertEqual(r['exit']['code'],0);self.assertGreater(r['stdout']['bytes'],0)
        RECORDS.append(r)

    def test_proxy_rejects_changed_snapshot(self):
        env=self.boundary_env();p=Path(env['KUBECONFIG']);p.chmod(0o600);p.write_text('kind: wrong')
        with self.assertRaises(g.BoundaryError):g.proxy_argv(['get','nodes'],env)

    def test_wrong_binary_digest(self):
        self.rejected(replace(self.profile,kubectl_sha='0'*64),'KUBECTL_DIGEST_MISMATCH')

    def test_allowed_workdir_and_admin_child_exclusion(self):
        with patch.object(g,'verify_live'):
            r=g.execute(str(self.config),self.env,mode='child',profile=self.profile,
                        child_command=[sys.executable,'-c','print("HARMLESS")'],child_cwd=self.work)
        self.assertEqual(r['trustedChild']['exit'],0)
        bad=self.root/'not-allowed';bad.mkdir(mode=0o700)
        with self.assertRaisesRegex(g.BoundaryError,'WORKING_DIRECTORY_FORBIDDEN'):
            g.execute(str(self.config),self.env,mode='child',profile=self.profile,child_command=[sys.executable],child_cwd=bad)
        with self.assertRaisesRegex(g.BoundaryError,'ADMIN_CHILD_FORBIDDEN'):
            g.execute(str(self.config),self.env,mode='child',profile=replace(self.profile,name='ADMIN_VALIDATION',identity='admin'),child_command=[sys.executable],child_cwd=self.work)

    def test_guarded_collector_preserves_negative_exit_metadata(self):
        file=self.work/'observed.json'
        code=("import json,sys,os;sys.path.insert(0,"+repr(str(ROOT))+");import sops_observation as o;"
              "r=o.observe_child([sys.executable,'-c','raise SystemExit(7)'],env=dict(os.environ),cwd="+repr(str(self.work))+
              ",identity='synthetic-only',evidence_ref='memory://guarded-collector');"
              "open("+repr(str(file))+",'w').write(json.dumps(r))")
        with patch.object(g,'verify_live'):
            r=g.execute(str(self.config),self.env,mode='child',profile=self.profile,
                        child_command=[sys.executable,'-c',code],child_cwd=self.work)
        observed=json.loads(file.read_text());self.assertEqual(r['trustedChild']['exit'],0)
        self.assertEqual(observed['exit']['code'],7);self.assertEqual(observed['errorClass'],'NONZERO_EXIT')
        RECORDS.append(observed)

    def test_typed_fixture_environment_no_keys_generated(self):
        root=self.root/'synthetic-input';root.mkdir(mode=0o700)
        file=root/'sentinel-input.txt';file.write_text('NOT_AN_AGE_KEY');file.chmod(0o600)
        p=replace(self.profile,fixture_input_root=str(root),fixture_age_file=str(file),heavy_holder='synthetic-run',read_only=False)
        env=g.child_environment(self.root,self.env,p)
        self.assertEqual(env['BUSINESS_AGE_FILE'],str(file));self.assertEqual(env['HEAVY_HOLDER'],'synthetic-run')
        self.assertNotIn('AWS_PROFILE',env);self.assertNotIn('SOPS_AGE_KEY_FILE',env)

    def test_fixture_path_escape_rejected(self):
        root=self.root/'input';root.mkdir(mode=0o700)
        p=replace(self.profile,fixture_input_root=str(root),fixture_age_file=str(self.config),heavy_holder='test',read_only=False)
        with self.assertRaisesRegex(g.BoundaryError,'FIXTURE_INPUT_PATH_FORBIDDEN'):g.fixture_environment(p)

    def test_proxy_executed_under_sanitized_environment(self):
        # Run the real shim -> same guard CLI -> explicit fake kubectl; no alternate API entry.
        command=[sys.executable,'-c',"import subprocess; r=subprocess.run(['kubectl','get','sentinel'],capture_output=True); assert r.returncode==0"]
        with patch.object(g,'verify_live'):
            result=g.execute(str(self.config),self.env,mode='child',profile=self.profile,child_command=command,child_cwd=self.work)
        self.assertEqual(result['trustedChild']['exit'],0)


class ObservationTests(Setup):
    def child(self,code,timeout=2):
        r=o.observe_child([sys.executable,'-c',code],env=self.boundary_env(),cwd=self.work,
                          identity=self.profile.identity,evidence_ref='memory://'+self.id(),timeout=timeout)
        o.validate_record(r);RECORDS.append(r);return r

    def test_exit_zero(self):self.assertEqual(self.child('pass')['exit']['code'],0)
    def test_nonzero_normal_exit(self):self.assertEqual(self.child('raise SystemExit(7)')['exit']['code'],7)
    def test_signal_termination(self):
        r=self.child('import os,signal;os.kill(os.getpid(),signal.SIGTERM)')
        self.assertEqual(r['exit']['signal'],signal.SIGTERM);self.assertIsNone(r['exit']['code'])
    def test_timeout(self):
        r=self.child('import time;time.sleep(30)',timeout=0.15)
        self.assertTrue(r['exit']['timedOut']);self.assertEqual(r['errorClass'],'TIMEOUT')
    def test_stdout_stderr_metadata_no_content(self):
        r=self.child('import sys;print("SYNTHETIC_STDOUT");print("SYNTHETIC_STDERR",file=sys.stderr)')
        self.assertGreater(r['stdout']['bytes'],0);self.assertGreater(r['stderr']['bytes'],0)
        self.assertNotIn('SYNTHETIC_STDOUT',json.dumps(r));self.assertNotIn('SYNTHETIC_STDERR',json.dumps(r))
    def test_no_output_failure(self):
        r=self.child('raise SystemExit(9)');self.assertEqual(r['stdout']['bytes'],0);self.assertEqual(r['stderr']['bytes'],0)
    def test_output_limit(self):
        r=o.observe_child([sys.executable,'-c','import sys;sys.stdout.write("x"*2000000);sys.stdout.flush()'],env=self.boundary_env(),cwd=self.work,identity='test',evidence_ref='memory://limit',max_output=4096)
        self.assertTrue(r['exit']['outputLimitExceeded']);self.assertEqual(r['errorClass'],'OUTPUT_LIMIT');RECORDS.append(r)
    def test_observer_cannot_bypass_guard_with_forged_environment(self):
        env=self.boundary_env();env['ISOLATED_BOUNDARY_CONTEXT']=str(self.root/'absent.json')
        with patch.object(o.subprocess,'Popen',side_effect=AssertionError('NO_PROTECTED_CHILD')) as child:
            with self.assertRaisesRegex(ValueError,'GUARDED_ENVIRONMENT_REJECTED'):
                o.observe_child([sys.executable,'-c','pass'],env=env,cwd=self.work,identity='test',evidence_ref='memory://reject')
            self.assertEqual(child.call_count,0)

    def test_missing_binary_execution(self):
        r=o.observe_child([str(self.root/'absent')],env=self.boundary_env(),cwd=self.work,identity='test',evidence_ref='memory://spawn-error')
        self.assertIsNone(r['exit']['code']);self.assertEqual(r['errorClass'],'FileNotFoundError');RECORDS.append(r)

    def prereq(self,kind,**kwargs):
        r=o.observe_prerequisite(kind,identity='test-only',target={'namespace':'synthetic','name':'target'},evidence_ref='memory://'+self.id(),**kwargs)
        RECORDS.append(r);return r
    def test_required_binary_missing(self):self.assertEqual(self.prereq('binary',path=self.root/'missing')['errorClass'],'FileNotFoundError')
    def test_required_binary_not_executable(self):
        p=self.root/'not-bin';p.write_text('sentinel');p.chmod(0o600)
        self.assertEqual(self.prereq('binary',path=p)['status'],'UNAVAILABLE')
    def test_required_kubeconfig_missing(self):self.assertEqual(self.prereq('kubeconfig-file',path=self.root/'missing')['status'],'UNAVAILABLE')
    def test_required_kubeconfig_rejected(self):
        r=self.prereq('kubeconfig-boundary',check=lambda:g.validate(str(self.config),{},profile=self.profile))
        self.assertEqual(r['errorClass'],'BoundaryError')
    def test_required_kubeconfig_validated(self):
        r=self.prereq('kubeconfig-boundary',check=lambda:g.validate(str(self.config),self.env,profile=self.profile))
        self.assertTrue(r['observation']['accepted'])
    def test_object_unavailable(self):self.assertEqual(self.prereq('object',check=lambda:None)['errorClass'],'OBJECT_UNAVAILABLE')
    def test_lease_mismatch(self):
        r=self.prereq('lease',check=lambda:{'metadata':{'name':'platform-heavy'},'spec':{'holderIdentity':'other'}},expected_holder='run')
        self.assertEqual(r['errorClass'],'LEASE_HOLDER_MISMATCH')
    def test_lease_missing_holder(self):self.assertEqual(self.prereq('lease',check=lambda:{},expected_holder='run')['errorClass'],'LEASE_HOLDER_UNAVAILABLE')
    def test_rbac_denied(self):self.assertEqual(self.prereq('rbac',check=lambda:False)['status'],'DENIED')
    def test_rbac_allowed(self):self.assertIs(self.prereq('rbac',check=lambda:True)['observation']['allowed'],True)
    def test_rbac_exception(self):
        def denied():raise PermissionError('SYNTHETIC_ONLY')
        r=self.prereq('object',check=denied);self.assertEqual(r['errorClass'],'PermissionError');self.assertNotIn('SYNTHETIC_ONLY',json.dumps(r))

    def obj(self):return {'metadata':{'namespace':'petclinic','name':'petclinic-db','uid':'LOCAL_SYNTHETIC_UID_A'},'type':'Opaque','data':{'password':'SYNTHETIC_ONLY_NOT_A_CREDENTIAL'}}
    def compare(self,mutate):
        b=self.obj();a=copy.deepcopy(b);mutate(a)
        saved=copy.deepcopy((b,a));r=o.observe_uid_values(b,a,identity='test-only',target={'namespace':'petclinic','name':'petclinic-db'},evidence_ref='memory://'+self.id())
        self.assertEqual(saved,(b,a));self.assertTrue(r['rawUnchanged']);RECORDS.append(r);return r
    def test_same_uid_and_value(self):
        r=self.compare(lambda a:None);self.assertTrue(r['uid']['equal']);self.assertTrue(r['values']['equal'])
    def test_changed_uid(self):self.assertFalse(self.compare(lambda a:a['metadata'].update(uid='LOCAL_SYNTHETIC_UID_B'))['uid']['equal'])
    def test_changed_value(self):self.assertFalse(self.compare(lambda a:a['data'].update(password='SYNTHETIC_CHANGED'))['values']['equal'])
    def test_missing_value(self):
        r=self.compare(lambda a:a.pop('data'));self.assertIsNone(r['values']['equal']);self.assertIn('VALUE_MISSING',r['errorClass'])
    def test_malformed_value(self):
        r=self.compare(lambda a:a.update(data='MALFORMED_SYNTHETIC'));self.assertIn('VALUE_MALFORMED',r['errorClass'])
    def test_json_boolean_not_number(self):self.assertFalse(o.strict_json_equal({'v':True},{'v':1}))
    def test_missing_value_not_empty_map(self):self.assertFalse(o.strict_json_equal(None,{}))
    def test_schema_rejects_policy_fields(self):
        r=copy.deepcopy(self.compare(lambda a:None));r['policyDecision']='PASS'
        with self.assertRaisesRegex(ValueError,'POLICY_DECISION_IN_RAW_FACT'):o.validate_record(r)
    def test_schema_rejects_missing_field(self):
        r=copy.deepcopy(self.compare(lambda a:None));r.pop('observedTarget')
        with self.assertRaises(ValueError):o.validate_record(r)
    def test_schema_rejects_invalid_exit(self):
        r=copy.deepcopy(self.child('pass'));r['exit']['code']=-1
        with self.assertRaises(ValueError):o.validate_record(r)
    def test_schema_rejects_policy_status_as_fact(self):
        r=copy.deepcopy(self.compare(lambda a:None));r['status']='PASS'
        with self.assertRaisesRegex(ValueError,'FACT_STATUS_INVALID'):o.validate_record(r)
    def test_schema_rejects_missing_prerequisite_observation(self):
        r=copy.deepcopy(self.prereq('object',check=lambda:None));r.pop('observation')
        with self.assertRaisesRegex(ValueError,'PREREQUISITE_SCHEMA_INVALID'):o.validate_record(r)
    def test_records_contain_no_policy_decisions(self):
        self.assertTrue(all(o.validate_record(r) for r in RECORDS if 'schemaVersion' in r))


class PreparationContractTests(unittest.TestCase):
    def design(self, name):
        local = ROOT / name
        path = local if local.exists() else ROOT.parents[2]/'evidence/2026-11-02/sops-preparation-blocker-closure'/name
        return json.loads(path.read_text())

    def test_all_recorded_observations_remain_raw_facts(self):
        self.assertTrue(all(o.validate_record(r) for r in RECORDS if 'schemaVersion' in r))

    def test_second_pair_lifecycle_consistency(self):
        d=self.design('age-key-lifecycle.json')
        self.assertEqual(d['totalFutureKeypairs'],2);self.assertEqual(d['generationThisRound'],0)
        self.assertNotEqual(d['baseline']['privateFile'],d['wrongKey']['privateFile'])
        self.assertEqual(d['wrongKey']['uses'],['WRONG_AGE_KEY'])
        for entry in [d['baseline'],d['wrongKey']]:
            self.assertEqual(entry['privateMode'],'0600');self.assertEqual(entry['executorMountMode'],'0400')
            self.assertFalse(entry['productionPathAllowed']);self.assertFalse(entry['committed']);self.assertFalse(entry['reuseOutsideRun'])

    def test_min_rbac_identity_design_has_no_admin_execution_credential(self):
        d=self.design('minimum-rbac-identity-design.json')
        self.assertEqual(d['username'],'system:serviceaccount:'+d['namespace']+':'+d['serviceAccount'])
        self.assertFalse(d['credential']['tokenInEvidence']);self.assertEqual(d['credential']['expirationSeconds'],3600)
        for rule in d['directRules']+d['clusterRules']:
            self.assertNotIn('*',rule['resources']);self.assertNotIn('*',rule['verbs'])
        self.assertFalse(any('secrets' in rule['resources'] for rule in d['directRules']+d['clusterRules']))

    def test_wrong_key_semantics_not_policy_override(self):
        d=self.design('age-key-lifecycle.json')
        self.assertEqual(d['semantics']['encryptedRecipient'],'BASELINE_AGE_KEYPAIR recipient')
        self.assertEqual(d['semantics']['decryptIdentity'],'WRONG_KEY_NEGATIVE_KEYPAIR private identity')
        self.assertNotIn('policyDecision',d['semantics'])


if __name__=='__main__':
    result=unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromModule(sys.modules[__name__]))
    output=os.environ.get('PREPARATION_TEST_REPORT')
    if output:Path(output).write_text(json.dumps({'classification':'HARNESS_ONLY_NOT_POLICY_COMPATIBILITY','tests':result.testsRun,'failures':len(result.failures),'errors':len(result.errors),'actualKubernetesApiRequests':0,'policyCompatibilityTestsAdded':0,'records':RECORDS},indent=2)+'\n')
    sys.exit(not result.wasSuccessful())
