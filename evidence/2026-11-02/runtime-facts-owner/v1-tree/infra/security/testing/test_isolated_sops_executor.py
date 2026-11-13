"""Guard-only negative tests. Every rejected input is independently blocked from sockets/children.

Temporary config samples are explicitly authorized boundary tests, not SOPS/Kubernetes fixtures.
Semantic-invalid cases rebind ONLY expected file location to an owned temporary file, leaving
server/CA/UID/digest pins unchanged. Production CLI has no path-binding override.
"""
from dataclasses import replace
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest.mock import patch
import shutil

import yaml

SPEC = importlib.util.spec_from_file_location('isolated_boundary', Path(__file__).with_name('isolated_sops_executor.py'))
guard = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = guard
SPEC.loader.exec_module(guard)
RECORDS = []
# Explicit legacy test profile only. The guard has no default/auto-discovered profile.
LEGACY_BINDING = guard.Binding(
    path=Path('/private/tmp/security-manager-kind-gdasvx1h/kubeconfig'),
    context='kind-security-test-sops', cluster='kind-security-test-sops',
    server='https://127.0.0.1:59645', uid='54f300a4-5f1b-4e1e-86a1-d173e5a402d8',
    ca_sha='90507a6f34d0b4e9b31cf862d74b7c2694b465c2e959f99bb45705ef0c8a46d8',
    config_sha='ce4f1a493632c692bc23bf7470460dbea17af70247d13f9a0c9c0bbf553946d9')
TEST_KUBECTL = Path(shutil.which('kubectl')).resolve()
TEST_PARENT = tempfile.TemporaryDirectory(prefix='legacy-explicit-profile-')
LEGACY_PROFILE = guard.Profile(
    name='ADMIN_VALIDATION', binding=LEGACY_BINDING,
    identity='kubernetes-admin', groups=('kubeadm:cluster-admins', 'system:authenticated'),
    real_kubectl=TEST_KUBECTL, kubectl_sha=hashlib.sha256(TEST_KUBECTL.read_bytes()).hexdigest(),
    temp_parent=Path(TEST_PARENT.name).resolve())


class BoundaryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.original = LEGACY_BINDING.path.read_bytes()  # Dedicated disposable test config only.
        assert hashlib.sha256(cls.original).hexdigest() == LEGACY_BINDING.config_sha

    def reject_input(self, case, argument, env, reason, binding=None):
        audit = guard.Audit()
        with patch.object(guard.socket if hasattr(guard, 'socket') else __import__('socket'), 'create_connection', side_effect=AssertionError('NO_SOCKET_ALLOWED')) as socket_call, \
             patch.object(guard.subprocess, 'run', side_effect=AssertionError('NO_CHILD_ALLOWED')) as spawn, \
             patch.object(guard.subprocess, 'Popen', side_effect=AssertionError('NO_CHILD_ALLOWED')) as popen:
            with self.assertRaises(guard.BoundaryError) as error:
                guard.execute(argument, env, audit=audit, profile=replace(LEGACY_PROFILE, binding=binding or LEGACY_BINDING))
            self.assertEqual(str(error.exception), reason)
            self.assertEqual(socket_call.call_count, 0)
            self.assertEqual(spawn.call_count, 0)
            self.assertEqual(popen.call_count, 0)
        self.assertEqual(vars(audit), {'api_attempts': 0, 'kubectl_invocations': 0, 'child_executions': 0})
        RECORDS.append({'case': case, 'reason': reason, 'status': 'PASS', 'actualNetworkAttempts': 0,
                        'kubectlInvocations': 0, 'childExecutions': 0,
                        'classification': 'REAL_GUARD_VALIDATION_WITH_NETWORK_AND_CHILD_TRAPS',
                        'temporaryFileBindingUsed': binding is not None})

    def modified(self, case, change, reason, mode=0o600):
        with tempfile.TemporaryDirectory(prefix='boundary-negative-') as root:
            path = Path(root) / 'kubeconfig'
            obj = yaml.safe_load(self.original)
            change(obj)
            path.write_text(yaml.safe_dump(obj))
            path.chmod(mode)
            self.reject_input(case, str(path), {'KUBECONFIG': str(path)}, reason,
                              replace(LEGACY_BINDING, path=path))

    def test_01_unset(self):
        self.reject_input('unset', str(LEGACY_BINDING.path), {}, 'KUBECONFIG_UNSET')

    def test_02_empty(self):
        self.reject_input('empty', str(LEGACY_BINDING.path), {'KUBECONFIG': '   '}, 'KUBECONFIG_EMPTY')

    def test_03_nonexistent(self):
        with tempfile.TemporaryDirectory() as root:
            path = str(Path(root) / 'absent')
            self.reject_input('nonexistent', path, {'KUBECONFIG': path}, 'CONFIG_FILE_MISSING')

    def test_04_directory(self):
        with tempfile.TemporaryDirectory() as path:
            self.reject_input('directory', path, {'KUBECONFIG': path}, 'CONFIG_NOT_REGULAR_FILE')

    def test_05_malformed(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / 'kubeconfig'
            path.write_text('kind: [broken')
            path.chmod(0o600)
            self.reject_input('malformed', str(path), {'KUBECONFIG': str(path)}, 'MALFORMED_CONFIG', replace(LEGACY_BINDING, path=path))

    def test_06_wrong_server(self):
        self.modified('wrong-server', lambda c: c['clusters'][0]['cluster'].update(server='https://192.0.2.1:65535'), 'SERVER_MISMATCH')

    def test_07_wrong_cluster(self):
        self.modified('wrong-cluster', lambda c: c['clusters'][0].update(name='not-approved-cluster'), 'CLUSTER_IDENTITY_MISMATCH')

    def test_08_real_default_available_dedicated_missing(self):
        # Check existence only. Never open user's real default configuration.
        home = Path.home()
        self.assertTrue((home / '.kube/config').exists())
        self.reject_input('real-default-available-dedicated-missing', str(LEGACY_BINDING.path), {'HOME': str(home)}, 'KUBECONFIG_UNSET')
        with tempfile.TemporaryDirectory() as root:
            missing = str(Path(root) / 'absent')
            self.reject_input('real-default-available-explicit-file-missing', missing,
                              {'HOME': str(home), 'KUBECONFIG': missing}, 'CONFIG_FILE_MISSING')

    def test_09_fake_default(self):
        with tempfile.TemporaryDirectory() as root:
            home = Path(root)
            (home / '.kube').mkdir()
            (home / '.kube/config').write_text('DO_NOT_READ_FAKE_DEFAULT_CONFIG')
            self.reject_input('fake-home-dedicated-unset', str(LEGACY_BINDING.path), {'HOME': root}, 'KUBECONFIG_UNSET')
            missing = str(home / 'absent')
            self.reject_input('fake-home-dedicated-path-missing', missing, {'HOME': root, 'KUBECONFIG': missing}, 'CONFIG_FILE_MISSING')

    def test_10_multiple(self):
        self.reject_input('multiple-files', str(LEGACY_BINDING.path), {'KUBECONFIG': str(LEGACY_BINDING.path) + ':/tmp/another'}, 'MULTIPLE_KUBECONFIG_FILES')

    def test_11_unsafe_permissions(self):
        self.modified('unsafe-permissions', lambda c: None, 'CONFIG_PERMISSIONS_UNSAFE', 0o644)

    def test_12_default_context(self):
        self.modified('wrong-current-context', lambda c: c.update({'current-context': 'orbstack'}), 'CONTEXT_IDENTITY_MISMATCH')

    def test_13_auth_plugin(self):
        self.modified('external-auth-plugin', lambda c: c['users'][0]['user'].update(exec={'command': 'MUST_NOT_EXECUTE'}), 'EXTERNAL_AUTH_FORBIDDEN')

    def test_14_wrong_ca(self):
        # Valid-looking PEM with different DER; never reaches TLS/parser network functions.
        import base64
        self.modified('wrong-ca', lambda c: c['clusters'][0]['cluster'].update({'certificate-authority-data': base64.b64encode(b'-----BEGIN CERTIFICATE-----\nYWJj\n-----END CERTIFICATE-----\n').decode()}), 'CA_IDENTITY_MISMATCH')

    def test_15_duplicate_yaml(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / 'kubeconfig'
            path.write_text('kind: Config\nkind: Config\n')
            path.chmod(0o600)
            self.reject_input('duplicate-yaml', str(path), {'KUBECONFIG': str(path)}, 'MALFORMED_CONFIG', replace(LEGACY_BINDING, path=path))

    def test_16_proxy_and_environment(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in ('home', 'bin', 'tmp', 'cache'):
                (root / name).mkdir(mode=0o700)
            guard.write_private(root / 'kubeconfig', self.original)
            guard.write_private(root / 'context.json', json.dumps(guard.profile_document(LEGACY_PROFILE)).encode())
            inherited = {k: 'SYNTHETIC_UNRELATED' for k in ['KUBECONFIG', 'KUBERNETES_SERVICE_HOST', 'AWS_PROFILE', 'SOPS_AGE_KEY_FILE', 'AGE_IDENTITY', 'SSH_AUTH_SOCK', 'DOCKER_HOST', 'HTTP_PROXY', 'BUSINESS_AGE_FILE', 'GOOGLE_APPLICATION_CREDENTIALS', 'AZURE_CONFIG_DIR', 'PATH', 'HOME']}
            env = guard.child_environment(root, inherited, LEGACY_PROFILE)
            self.assertFalse(set(inherited) & set(env) - {'KUBECONFIG', 'HOME', 'PATH'})
            argv = guard.proxy_argv(['--request-timeout=20s', '-n', 'data-infra', 'get', 'lease', 'platform-heavy'], env)
            self.assertEqual(argv[:5], [str(TEST_KUBECTL), '--kubeconfig', str(root / 'kubeconfig'), '--context', LEGACY_BINDING.context])
            for args in [['--server=https://192.0.2.1'], ['--context=orbstack'], ['--kubeconfig=/tmp/default'], ['get', '--raw=https://192.0.2.1'], ['apply', '--filename=https://192.0.2.1']]:
                with self.assertRaises(guard.BoundaryError):
                    guard.proxy_argv(args, env)
            env.pop('KUBECONFIG')
            with self.assertRaises(guard.BoundaryError):
                guard.proxy_argv(['get', 'nodes'], env)
            RECORDS.append({'case': 'sanitized-env-and-explicit-kubectl-prefix', 'status': 'PASS', 'actualNetworkAttempts': 0, 'childExecutions': 0, 'classification': 'PURE_PROXY_PREPARATION_NO_EXEC'})

    def test_17_empty_config_file(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / 'kubeconfig'
            path.write_bytes(b'')
            path.chmod(0o600)
            self.reject_input('empty-config-file', str(path), {'KUBECONFIG': str(path)},
                              'CONFIG_SIZE_INVALID', replace(LEGACY_BINDING, path=path))

    def test_18_explicit_argument_required(self):
        self.reject_input('explicit-argument-absent', None,
                          {'KUBECONFIG': str(LEGACY_BINDING.path)}, 'EXPLICIT_ARGUMENT_REQUIRED')


if __name__ == '__main__':
    result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(BoundaryTests))
    output = os.environ.get('BOUNDARY_TEST_REPORT')
    if output:
        Path(output).write_text(json.dumps({'tests': result.testsRun, 'failures': len(result.failures), 'errors': len(result.errors), 'records': RECORDS}, indent=2))
    sys.exit(not result.wasSuccessful())
