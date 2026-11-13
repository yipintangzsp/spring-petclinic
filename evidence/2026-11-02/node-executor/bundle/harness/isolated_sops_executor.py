"""Test-only fail-closed boundary; explicit trusted profile, never config discovery.

No production imports. CLI permits check/sentinel only. Profile configuration is a
trusted harness input (not an untrusted-child sandbox or a privilege grant).
"""
import argparse
import base64
import hashlib
import http.client
import json
import math
import os
from pathlib import Path
import re
import ssl
import stat
import subprocess
import sys
import tempfile
import time
from urllib.parse import urlsplit
from dataclasses import dataclass, field, asdict, replace

import yaml

PROFILES = {'ADMIN_VALIDATION', 'MIN_RBAC_EXECUTOR'}


class BoundaryError(Exception):
    """Only stable reason codes, never credential/parser contents."""


def reject(condition, reason):
    if not condition:
        raise BoundaryError(reason)


@dataclass(frozen=True)
class Binding:
    path: Path
    context: str
    cluster: str
    server: str
    uid: str
    ca_sha: str
    config_sha: str


@dataclass(frozen=True)
class Profile:
    name: str
    binding: Binding
    identity: str
    groups: tuple
    real_kubectl: Path
    kubectl_sha: str
    temp_parent: Path
    allowed_cwds: tuple = ()
    service_account_namespace: str = ''
    service_account_name: str = ''
    service_account_uid: str = ''
    namespace_uid: str = ''
    token_issuer: str = ''
    token_audience: str = ''
    fixture_input_root: str = ''
    fixture_age_file: str = ''
    heavy_holder: str = ''
    read_only: object = None


@dataclass
class Audit:
    api_attempts: int = 0
    kubectl_invocations: int = 0
    child_executions: int = 0


@dataclass(repr=False)
class Validated:
    raw: bytes = field(repr=False)
    ca: str = field(repr=False)
    cert: bytes = field(default=b'', repr=False)
    key: bytes = field(default=b'', repr=False)
    token: str = field(default='', repr=False)


class UniqueLoader(yaml.SafeLoader):
    pass


def unique_map(loader, node, deep=False):
    result = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if not isinstance(key, str) or key in result:
            raise BoundaryError('MALFORMED_CONFIG')
        result[key] = loader.construct_object(value_node, deep=deep)
    return result


UniqueLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, unique_map)


def decode(value):
    reject(isinstance(value, str) and 0 < len(value) < 131072, 'INVALID_EMBEDDED_CERTIFICATE')
    try:
        return base64.b64decode(value, validate=True)
    except Exception:
        raise BoundaryError('INVALID_EMBEDDED_CERTIFICATE') from None


def private_dir(path):
    p = Path(path)
    reject(p.is_absolute() and not p.is_symlink(), 'PRIVATE_DIRECTORY_REQUIRED')
    info = p.stat()
    reject(stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid() and
           stat.S_IMODE(info.st_mode) & 0o077 == 0, 'PRIVATE_DIRECTORY_REQUIRED')
    reject(p.resolve() == p, 'PRIVATE_DIRECTORY_SYMLINK')
    return p


def validate_profile(profile):
    reject(isinstance(profile, Profile), 'PROFILE_REQUIRED')
    reject(profile.name in PROFILES, 'UNKNOWN_PROFILE')
    b = profile.binding
    reject(isinstance(b, Binding) and all(isinstance(x, str) and x for x in
           (b.context, b.cluster, b.server, b.uid, b.ca_sha, b.config_sha, profile.identity)), 'PROFILE_INCOMPLETE')
    reject(all(re.fullmatch('[0-9a-f]{64}', v) for v in (b.ca_sha, b.config_sha, profile.kubectl_sha)), 'PROFILE_DIGEST_INVALID')
    server = urlsplit(b.server)
    reject(server.scheme == 'https' and server.hostname and not server.username and not server.password and
           not server.query and not server.fragment and server.path in ('', '/') and server.port, 'PROFILE_SERVER_INVALID')
    reject(Path(b.path).is_absolute() and Path(profile.real_kubectl).is_absolute(), 'PROFILE_ABSOLUTE_PATH_REQUIRED')
    reject(isinstance(profile.groups, tuple) and all(isinstance(x, str) for x in profile.groups), 'PROFILE_GROUPS_INVALID')
    private_dir(profile.temp_parent)
    for path in profile.allowed_cwds:
        private_dir(path)
    if profile.name == 'MIN_RBAC_EXECUTOR':
        ns, name = profile.service_account_namespace, profile.service_account_name
        reject(all(re.fullmatch('[a-z0-9]([a-z0-9.-]*[a-z0-9])?', v or '') for v in (ns, name)), 'SERVICE_ACCOUNT_NAME_INVALID')
        reject(ns != 'kube-system' or profile.namespace_uid == b.uid, 'PROFILE_NAMESPACE_UID_MISMATCH')
        reject(bool(ns and name and profile.service_account_uid and profile.namespace_uid and
                    profile.token_issuer and profile.token_audience), 'SERVICE_ACCOUNT_PROFILE_INCOMPLETE')
        reject(profile.identity == 'system:serviceaccount:' + ns + ':' + name, 'SERVICE_ACCOUNT_IDENTITY_MISMATCH')
        reject(set(profile.groups) == {'system:serviceaccounts', 'system:serviceaccounts:' + ns, 'system:authenticated'}, 'SERVICE_ACCOUNT_GROUPS_MISMATCH')
    else:
        reject(not profile.identity.startswith('system:serviceaccount:') and not any((profile.fixture_age_file, profile.heavy_holder, profile.fixture_input_root)) and profile.read_only is None, 'ADMIN_PROFILE_EXECUTION_INPUT_FORBIDDEN')
    return profile


def jwt_claims(token, profile):
    """Offline structure/identity/expiry check; signature verified by API, not guessed locally.

    Whole kubeconfig is independently SHA pinned to the trusted issuance snapshot.
    """
    try:
        reject(isinstance(token, str) and 0 < len(token) < 65536, 'TOKEN_INVALID')
        parts = token.split('.')
        reject(len(parts) == 3 and all(parts), 'TOKEN_INVALID')
        header = json.loads(base64.urlsafe_b64decode(parts[0] + '=' * (-len(parts[0]) % 4)))
        claims = json.loads(base64.urlsafe_b64decode(parts[1] + '=' * (-len(parts[1]) % 4)))
        reject(header.get('alg') in ('RS256', 'ES256', 'ES384', 'EdDSA'), 'TOKEN_ALGORITHM_FORBIDDEN')
        reject(claims.get('sub') == profile.identity and claims.get('iss') == profile.token_issuer, 'TOKEN_IDENTITY_MISMATCH')
        audiences = claims.get('aud')
        reject(isinstance(audiences, list) and audiences == [profile.token_audience], 'TOKEN_AUDIENCE_MISMATCH')
        for k in ('exp', 'iat', 'nbf'):
            v = claims.get(k)
            reject(isinstance(v, (int, float)) and not isinstance(v, bool) and math.isfinite(v), 'TOKEN_TIME_INVALID')
        now = time.time()
        reject(claims['nbf'] <= now and claims['iat'] <= now < claims['exp'] and
               0 < claims['exp'] - claims['iat'] <= 3600, 'TOKEN_EXPIRED_OR_LIFETIME_INVALID')
        k = claims.get('kubernetes.io', {})
        sa = k.get('serviceaccount', {})
        reject(k.get('namespace') == profile.service_account_namespace and sa.get('name') == profile.service_account_name and
               sa.get('uid') == profile.service_account_uid, 'TOKEN_SERVICE_ACCOUNT_MISMATCH')
        return claims
    except BoundaryError:
        raise
    except Exception:
        raise BoundaryError('TOKEN_INVALID') from None


def validate(argument, environ, binding=None, profile=None):
    """Offline configuration/credential checks. No API or child before this succeeds."""
    profile = validate_profile(profile)
    reject(binding is None or binding == profile.binding, 'BINDING_PROFILE_MISMATCH')
    binding = profile.binding
    reject('KUBECONFIG' in environ, 'KUBECONFIG_UNSET')
    value = environ['KUBECONFIG'].strip()
    reject(bool(value), 'KUBECONFIG_EMPTY')
    reject(os.pathsep not in value, 'MULTIPLE_KUBECONFIG_FILES')
    reject(isinstance(argument, str) and bool(argument.strip()), 'EXPLICIT_ARGUMENT_REQUIRED')
    reject(os.pathsep not in argument, 'MULTIPLE_KUBECONFIG_FILES')
    reject(Path(value).is_absolute() and Path(argument).is_absolute(), 'ABSOLUTE_PATH_REQUIRED')
    path = Path(value)
    try:
        resolved = path.resolve(strict=True)
        arg_resolved = Path(argument).resolve(strict=True)
    except (OSError, RuntimeError, ValueError):
        raise BoundaryError('CONFIG_FILE_MISSING') from None
    reject(resolved == arg_resolved, 'ARGUMENT_ENV_PATH_MISMATCH')
    try:
        info = resolved.stat()
    except OSError:
        raise BoundaryError('CONFIG_FILE_UNAVAILABLE') from None
    reject(stat.S_ISREG(info.st_mode), 'CONFIG_NOT_REGULAR_FILE')
    reject(not path.is_symlink() and resolved == binding.path.resolve(), 'UNEXPECTED_CONFIG_PATH')
    reject(info.st_uid == os.getuid(), 'CONFIG_OWNER_MISMATCH')
    reject(stat.S_IMODE(info.st_mode) in (0o400, 0o600), 'CONFIG_PERMISSIONS_UNSAFE')
    reject(0 < info.st_size <= 262144, 'CONFIG_SIZE_INVALID')
    try:
        fd = os.open(resolved, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, 'rb') as source:
            current = os.fstat(source.fileno())
            reject((current.st_dev, current.st_ino, current.st_mode, current.st_uid) ==
                   (info.st_dev, info.st_ino, info.st_mode, info.st_uid), 'CONFIG_CHANGED_DURING_READ')
            raw = source.read(262145)
        reject(0 < len(raw) <= 262144, 'CONFIG_SIZE_INVALID')
        reject(not any(isinstance(t, (yaml.tokens.AliasToken, yaml.tokens.AnchorToken)) for t in yaml.scan(raw)), 'MALFORMED_CONFIG')
        config = yaml.load(raw, Loader=UniqueLoader)
    except BoundaryError:
        raise
    except Exception:
        raise BoundaryError('MALFORMED_CONFIG') from None
    reject(isinstance(config, dict) and config.get('kind') == 'Config' and config.get('apiVersion') == 'v1', 'MALFORMED_CONFIG')
    reject(config.get('current-context') == binding.context, 'CONTEXT_IDENTITY_MISMATCH')
    for collection in ('contexts', 'clusters', 'users'):
        reject(isinstance(config.get(collection), list) and len(config[collection]) == 1, 'SINGLE_CONFIG_IDENTITY_REQUIRED')
    try:
        context, cluster, user = config['contexts'][0], config['clusters'][0], config['users'][0]
        reject(context['name'] == binding.context and context['context']['cluster'] == binding.cluster and
               cluster['name'] == binding.cluster and context['context']['user'] == user['name'] == binding.context,
               'CLUSTER_IDENTITY_MISMATCH')
        data = cluster['cluster']
        reject(data.get('server') == binding.server, 'SERVER_MISMATCH')
        reject(set(data) == {'server', 'certificate-authority-data'}, 'CLUSTER_CONNECTION_OVERRIDE_FORBIDDEN')
        auth = user['user']
        expected = {'token'} if profile.name == 'MIN_RBAC_EXECUTOR' else {'client-certificate-data', 'client-key-data'}
        reject(set(auth) == expected, 'EXTERNAL_AUTH_FORBIDDEN')
        ca = decode(data['certificate-authority-data']).decode('ascii')
        reject(hashlib.sha256(ssl.PEM_cert_to_DER_cert(ca)).hexdigest() == binding.ca_sha, 'CA_IDENTITY_MISMATCH')
        if profile.name == 'MIN_RBAC_EXECUTOR':
            jwt_claims(auth['token'], profile)
            validated = Validated(raw, ca, token=auth['token'])
        else:
            validated = Validated(raw, ca, decode(auth['client-certificate-data']), decode(auth['client-key-data']))
    except BoundaryError:
        raise
    except Exception:
        raise BoundaryError('MALFORMED_CONFIG') from None
    reject(hashlib.sha256(raw).hexdigest() == binding.config_sha, 'CONFIG_DIGEST_MISMATCH')
    return validated


def write_private(path, data, mode=0o400):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    with os.fdopen(fd, 'wb') as target:
        target.write(data)


def check_identity_response(obj, profile):
    reject(obj.get('kind') == 'SelfSubjectReview', 'AUTH_IDENTITY_RESPONSE_INVALID')
    info = obj.get('status', {}).get('userInfo', {})
    reject(info.get('username') == profile.identity and set(info.get('groups', [])) == set(profile.groups), 'LIVE_AUTH_IDENTITY_MISMATCH')
    if profile.name == 'MIN_RBAC_EXECUTOR':
        reject(info.get('uid') == profile.service_account_uid, 'LIVE_SERVICE_ACCOUNT_UID_MISMATCH')


def verify_live(validated, root, audit, profile):
    """Pinned HTTPS, real authenticated identity + cluster/namespace UID, no redirects/proxy."""
    b = profile.binding
    server = urlsplit(b.server)
    cert, key = root / 'client.crt', root / 'client.key'
    try:
        context = ssl.create_default_context(cadata=validated.ca)
        headers = {'Accept': 'application/json'}
        if profile.name == 'ADMIN_VALIDATION':
            write_private(cert, validated.cert)
            write_private(key, validated.key)
            context.load_cert_chain(cert, key)
        else:
            headers['Authorization'] = 'Bearer ' + validated.token
        connection = http.client.HTTPSConnection(server.hostname, server.port, context=context, timeout=10)
        def request(method, path, body=None):
            audit.api_attempts += 1
            connection.request(method, path, body=body, headers={**headers, 'Content-Type': 'application/json'})
            response = connection.getresponse()
            reject(response.status in (200, 201), 'IDENTITY_HTTP_ERROR')
            data = response.read(1048577)
            reject(len(data) <= 1048576, 'IDENTITY_RESPONSE_TOO_LARGE')
            return json.loads(data)
        try:
            obj = request('POST', '/apis/authentication.k8s.io/v1/selfsubjectreviews',
                          json.dumps({'apiVersion': 'authentication.k8s.io/v1', 'kind': 'SelfSubjectReview'}))
            check_identity_response(obj, profile)
            namespaces = [('kube-system', b.uid)]
            if profile.name == 'MIN_RBAC_EXECUTOR' and profile.service_account_namespace != 'kube-system':
                namespaces.append((profile.service_account_namespace, profile.namespace_uid))
            for name, uid in namespaces:
                obj = request('GET', '/api/v1/namespaces/' + name)
                reject(obj.get('kind') == 'Namespace' and obj.get('metadata', {}).get('name') == name and
                       obj['metadata'].get('uid') == uid, 'LIVE_NAMESPACE_UID_MISMATCH')
        finally:
            connection.close()
    except BoundaryError:
        raise
    except Exception:
        raise BoundaryError('IDENTITY_TLS_OR_NETWORK_FAILED') from None
    finally:
        cert.unlink(missing_ok=True)
        key.unlink(missing_ok=True)


def profile_document(profile):
    obj = asdict(profile)
    for key in ('real_kubectl', 'temp_parent'):
        obj[key] = str(obj[key])
    obj['binding']['path'] = str(obj['binding']['path'])
    obj['allowed_cwds'] = [str(p) for p in profile.allowed_cwds]
    return obj


def profile_from_document(obj):
    try:
        obj = dict(obj)
        obj['binding'] = Binding(**{**obj['binding'], 'path': Path(obj['binding']['path'])})
        for key in ('real_kubectl', 'temp_parent'):
            obj[key] = Path(obj[key])
        obj['allowed_cwds'] = tuple(Path(p) for p in obj['allowed_cwds'])
        obj['groups'] = tuple(obj['groups'])
        return validate_profile(Profile(**obj))
    except BoundaryError:
        raise
    except Exception:
        raise BoundaryError('PROFILE_MALFORMED') from None


def fixture_environment(profile):
    if not any((profile.fixture_age_file, profile.fixture_input_root, profile.heavy_holder)) and profile.read_only is None:
        return {}
    reject(profile.name == 'MIN_RBAC_EXECUTOR' and profile.fixture_age_file and profile.fixture_input_root and
           profile.heavy_holder and isinstance(profile.read_only, bool), 'FIXTURE_INPUT_INCOMPLETE')
    root = private_dir(profile.fixture_input_root)
    path = Path(profile.fixture_age_file)
    reject(path.is_absolute() and not path.is_symlink() and path.resolve().is_relative_to(root), 'FIXTURE_INPUT_PATH_FORBIDDEN')
    info = path.stat()
    reject(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) in (0o400, 0o600), 'FIXTURE_INPUT_UNSAFE')
    reject(re.fullmatch('[a-zA-Z0-9._-]{1,100}', profile.heavy_holder), 'FIXTURE_HOLDER_INVALID')
    return {'BUSINESS_AGE_FILE': str(path), 'HEAVY_HOLDER': profile.heavy_holder,
            'DEVSECOPS_READ_ONLY': str(profile.read_only).lower()}


def child_environment(root, inherited, profile):
    env = {k: inherited[k] for k in ('LANG', 'LC_ALL', 'TZ') if k in inherited}
    env.update(HOME=str(root / 'home'), KUBECONFIG=str(root / 'kubeconfig'),
               PATH=str(root / 'bin') + ':/usr/bin:/bin', TMPDIR=str(root / 'tmp'),
               XDG_CACHE_HOME=str(root / 'cache'), PYTHONDONTWRITEBYTECODE='1',
               ISOLATED_BOUNDARY_CONTEXT=str(root / 'context.json'))
    env.update(fixture_environment(profile))
    return env


DENIED_FLAGS = {'--kubeconfig', '--context', '--cluster', '--user', '--server', '-s', '--token',
                '--username', '--password', '--client-certificate', '--client-key', '--certificate-authority',
                '--insecure-skip-tls-verify', '--tls-server-name', '--proxy-url', '--cache-dir'}


def verify_kubectl(profile):
    p = profile.real_kubectl
    info = p.stat()
    reject(p.is_absolute() and stat.S_ISREG(info.st_mode) and info.st_mode & 0o111 and not info.st_mode & 0o022,
           'KUBECTL_EXECUTABLE_UNSAFE')
    reject(hashlib.sha256(p.read_bytes()).hexdigest() == profile.kubectl_sha, 'KUBECTL_DIGEST_MISMATCH')


def validate_execution_environment(env):
    """Reuse the same snapshot/profile checks for observers; never an API client."""
    path = Path(env.get('ISOLATED_BOUNDARY_CONTEXT', ''))
    reject(path.is_absolute() and path.name == 'context.json', 'BOUNDARY_CONTEXT_MISSING')
    info = path.stat()
    reject(not path.is_symlink() and info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o400, 'BOUNDARY_CONTEXT_INVALID')
    profile = profile_from_document(json.loads(path.read_text()))
    root = path.parent
    expected_env = child_environment(root, {}, profile)
    reject(all(env.get(k) == v for k, v in expected_env.items()), 'CHILD_ENVIRONMENT_CHANGED')
    snapshot_profile = replace(profile, binding=replace(profile.binding, path=root / 'kubeconfig'))
    validate(str(root / 'kubeconfig'), env, profile=snapshot_profile)
    verify_kubectl(profile)
    return profile


def proxy_argv(args, env):
    profile = validate_execution_environment(env)
    for arg in args:
        reject(arg.split('=', 1)[0] not in DENIED_FLAGS and not (arg.startswith('-s') and not arg.startswith('--')), 'CONNECTION_OVERRIDE_FORBIDDEN')
        value = arg.partition('=')[2] if '=' in arg else arg
        reject(not value.startswith(('https://', 'http://')), 'EXTERNAL_URL_FORBIDDEN')
    return [str(profile.real_kubectl), '--kubeconfig', env['KUBECONFIG'], '--context', profile.binding.context, *args]


SENTINEL = r'''
import json,os,pathlib
home=pathlib.Path(os.environ['HOME']);config=pathlib.Path(os.environ['KUBECONFIG'])
assert not (home/'.kube').exists()
assert home.parent==config.parent and config.is_file()
assert os.environ['PATH'].split(':')[0]==str(home.parent/'bin')
assert not any(k.startswith(('AWS_','AGE','SOPS_','SSH_')) or (k.startswith('KUBE') and k!='KUBECONFIG') or k in ['DOCKER_HOST','BUSINESS_AGE_FILE','HTTP_PROXY','HTTPS_PROXY','http_proxy','https_proxy'] for k in os.environ)
print('ISOLATED_KUBECONFIG_SENTINEL_OK')
print(json.dumps({'explicitKubeconfig':True,'privateSnapshot':True,'cleanHome':True,'sanitizedEnvironment':True,'envNames':sorted(os.environ)}))
'''


def execute(argument, environ, mode='check', audit=None, binding=None, profile=None, child_command=None, child_cwd=None):
    audit = audit or Audit()
    profile = validate_profile(profile)
    reject(binding is None or binding == profile.binding, 'BINDING_PROFILE_MISMATCH')
    reject(mode in ('check', 'sentinel', 'child'), 'INVALID_EXECUTION_MODE')
    if mode == 'child':
        reject(profile.name == 'MIN_RBAC_EXECUTOR', 'ADMIN_CHILD_FORBIDDEN')
        reject(isinstance(child_command, (list, tuple)) and bool(child_command) and
               all(isinstance(a, str) and '\x00' not in a for a in child_command) and
               Path(child_command[0]).is_absolute(), 'EXPLICIT_TRUSTED_CHILD_REQUIRED')
        reject(child_cwd is not None and Path(child_cwd).is_absolute(), 'EXPLICIT_PRIVATE_CHILD_CWD_REQUIRED')
        cwd = private_dir(child_cwd)
        reject(any(cwd == Path(p) or cwd.is_relative_to(Path(p)) for p in profile.allowed_cwds), 'WORKING_DIRECTORY_FORBIDDEN')
    else:
        reject(child_command is None and child_cwd is None, 'UNEXPECTED_CHILD_COMMAND')
    validated = validate(argument, environ, profile=profile)
    verify_kubectl(profile)
    fixture_environment(profile)
    result = {'status': 'ACCEPTED', 'profile': profile.name, 'server': profile.binding.server,
              'kubeSystemUID': profile.binding.uid, 'wouldPermitChild': False, 'gateExecuted': False}
    with tempfile.TemporaryDirectory(prefix='isolated-sops-boundary-', dir=profile.temp_parent) as directory:
        root = Path(directory)
        for name in ('home', 'bin', 'tmp', 'cache'):
            (root / name).mkdir(mode=0o700)
        write_private(root / 'kubeconfig', validated.raw)
        write_private(root / 'context.json', json.dumps(profile_document(profile)).encode())
        shim = '#!' + sys.executable + '\nimport os,sys\nos.execve(' + repr(sys.executable) + ',[' + repr(sys.executable) + ',' + repr(str(Path(__file__).resolve())) + ',"--kubectl-proxy",*sys.argv[1:]],dict(os.environ))\n'
        write_private(root / 'bin' / 'kubectl', shim.encode(), 0o500)
        verify_live(validated, root, audit, profile)
        result['wouldPermitChild'] = True
        env = child_environment(root, environ, profile)
        result['environment'] = {'preserved': sorted(set(env) & {'LANG', 'LC_ALL', 'TZ'}),
                                 'explicitlySet': sorted(set(env) - {'LANG', 'LC_ALL', 'TZ'}),
                                 'removedInheritedNames': sorted(set(environ) - set(env)),
                                 'sourceAndSnapshotBytesIdentical': True, 'defaultKubeconfigAbsent': True}
        if mode in ('sentinel', 'child'):
            audit.child_executions += 1
            command = [sys.executable, '-I', '-c', SENTINEL] if mode == 'sentinel' else list(child_command)
            child = subprocess.run(command, env=env, cwd=root / 'home' if mode == 'sentinel' else child_cwd,
                                   capture_output=True, text=True, timeout=15 if mode == 'sentinel' else None)
            reject(child.returncode == 0, 'CHILD_FAILED')
            if mode == 'sentinel':
                reject('ISOLATED_KUBECONFIG_SENTINEL_OK' in child.stdout, 'SENTINEL_FAILED')
                result['sentinel'] = {'exit': child.returncode, 'stdout': child.stdout}
            else:
                result['trustedChild'] = {'exit': child.returncode, 'outputSuppressed': True}
        result['temporaryDirectory'] = str(root)
    result['temporaryDirectoryRemoved'] = not root.exists()
    result['audit'] = vars(audit)
    return result


def main():
    if len(sys.argv) > 1 and sys.argv[1] == '--kubectl-proxy':
        try:
            argv = proxy_argv(sys.argv[2:], os.environ)
            os.execve(argv[0], argv, dict(os.environ))
        except Exception:
            print('BOUNDARY_KUBECTL_REJECTED', file=sys.stderr)
            return 42
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--kubeconfig', required=True)
    parser.add_argument('--profile', required=True, help='Explicit owned 0400/0600 trusted test profile JSON')
    parser.add_argument('--mode', choices=('check', 'sentinel'), default='check')
    options = parser.parse_args()
    audit = Audit()
    try:
        p = Path(options.profile)
        reject(p.is_absolute() and not p.is_symlink(), 'PROFILE_PATH_INVALID')
        info = p.stat()
        reject(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) in (0o400, 0o600), 'PROFILE_FILE_UNSAFE')
        profile = profile_from_document(json.loads(p.read_text()))
        result = execute(options.kubeconfig, os.environ, options.mode, audit, profile=profile)
        print(json.dumps(result))
        return 0
    except BoundaryError as error:
        print(json.dumps({'status': 'REJECTED', 'reason': str(error), 'audit': vars(audit), 'gateExecuted': False}))
        return 42
    except Exception:
        print(json.dumps({'status': 'REJECTED', 'reason': 'BOUNDARY_INTERNAL_ERROR', 'audit': vars(audit), 'gateExecuted': False}))
        return 42


if __name__ == '__main__':
    sys.exit(main())
