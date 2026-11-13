"""TEST ONLY: observable facts, no Policy or Gate decisions and no Kubernetes client.

Callers supply guarded commands/readers. This module does not provide a second
Kubernetes execution entry. Stdout/stderr content is never returned or logged.
"""
import base64
import copy
import hashlib
import json
import os
from pathlib import Path
import selectors
import signal
import stat
import subprocess
import time

from isolated_sops_executor import validate_execution_environment

SCHEMA_VERSION = 'sops-observation-v1'
FAMILIES = {'PREREQUISITE_FACT', 'CHILD_EXIT_FACT', 'UID_VALUE_FACT'}


def record(kind, source, identity, expected_target, observed_target, status, error_class, evidence_ref, **fields):
    value = dict(schemaVersion=SCHEMA_VERSION, factType=kind, source=source, identity=identity,
                 expectedTarget=expected_target, observedTarget=observed_target, status=status,
                 errorClass=error_class, evidenceRef=evidence_ref, **fields)
    validate_record(value)
    return value


def validate_record(value):
    required = {'schemaVersion', 'factType', 'source', 'identity', 'expectedTarget', 'observedTarget',
                'status', 'errorClass', 'evidenceRef'}
    if not isinstance(value, dict) or not required.issubset(value) or value['schemaVersion'] != SCHEMA_VERSION or value['factType'] not in FAMILIES:
        raise ValueError('RAW_FACT_SCHEMA_INVALID')
    def visit(obj):
        if isinstance(obj, dict):
            for key, val in obj.items():
                if key.lower() in {'decision', 'policydecision', 'olddecision', 'expectedgatedecision', 'severity', 'blocking', 'pass', 'fail'}:
                    raise ValueError('POLICY_DECISION_IN_RAW_FACT')
                visit(val)
        elif isinstance(obj, list):
            for val in obj:
                visit(val)
    visit(value)
    if any(not isinstance(value[k], str) or not value[k] for k in ['source', 'identity', 'status', 'evidenceRef']):
        raise ValueError('RAW_FACT_SCHEMA_INVALID')
    if value['status'] not in {'OBSERVED', 'EXECUTION_ERROR', 'UNAVAILABLE', 'MISMATCH', 'DENIED', 'INCOMPLETE'}:
        raise ValueError('FACT_STATUS_INVALID')
    if value['errorClass'] is not None and not isinstance(value['errorClass'], str):
        raise ValueError('RAW_FACT_SCHEMA_INVALID')
    if value['factType'] == 'PREREQUISITE_FACT':
        if not isinstance(value.get('prerequisite'), str) or not isinstance(value.get('observation'), dict):
            raise ValueError('PREREQUISITE_SCHEMA_INVALID')
    if value['factType'] == 'CHILD_EXIT_FACT':
        exit_meta = value.get('exit')
        if not isinstance(exit_meta, dict) or not {'code', 'signal', 'timedOut', 'outputLimitExceeded'}.issubset(exit_meta):
            raise ValueError('EXIT_SCHEMA_INVALID')
        if not isinstance(exit_meta['timedOut'], bool) or not isinstance(exit_meta['outputLimitExceeded'], bool):
            raise ValueError('EXIT_SCHEMA_INVALID')
        if exit_meta['code'] is not None and (not isinstance(exit_meta['code'], int) or isinstance(exit_meta['code'], bool) or exit_meta['code'] < 0):
            raise ValueError('EXIT_SCHEMA_INVALID')
        if exit_meta['signal'] is not None and (not isinstance(exit_meta['signal'], int) or exit_meta['signal'] <= 0):
            raise ValueError('EXIT_SCHEMA_INVALID')
        for name in ['stdout', 'stderr']:
            meta = value.get(name)
            if not isinstance(meta, dict) or set(meta) != {'bytes', 'sha256', 'contentStored'} or meta['contentStored'] is not False or not isinstance(meta['bytes'], int):
                raise ValueError('OUTPUT_SCHEMA_INVALID')
    if value['factType'] == 'UID_VALUE_FACT':
        if not all(k in value for k in ['uid', 'values', 'typeEqual', 'rawUnchanged']):
            raise ValueError('UID_VALUE_SCHEMA_INVALID')
        if not all(isinstance(value[k], dict) for k in ['uid', 'values']):
            raise ValueError('UID_VALUE_SCHEMA_INVALID')
        if not {'before', 'after', 'equal'}.issubset(value['uid']) or not {'beforePresent', 'afterPresent', 'beforeShape', 'afterShape', 'equal'}.issubset(value['values']):
            raise ValueError('UID_VALUE_SCHEMA_INVALID')
        if not all(isinstance(value[k], bool) for k in ['typeEqual', 'rawUnchanged']):
            raise ValueError('UID_VALUE_SCHEMA_INVALID')
    return True


def observe_child(command, *, env, cwd, identity, evidence_ref, timeout=2.0, max_output=1024*1024):
    """Actual process return/signal/timeout, bounded streaming metadata in memory.

    Runs under an already guarded parent environment. No shell, no inheriting host
    HOME/env, no key/Secret/stdout files. A process-group kill reaps descendants.
    """
    if not command or not Path(command[0]).is_absolute() or not isinstance(timeout, (int, float)) or timeout <= 0 or max_output <= 0:
        raise ValueError('EXPLICIT_BOUNDED_COMMAND_REQUIRED')
    home, config = Path(env.get('HOME', '')), Path(env.get('KUBECONFIG', ''))
    if not home.is_absolute() or not config.is_absolute() or not env.get('ISOLATED_BOUNDARY_CONTEXT'):
        raise ValueError('GUARDED_ENVIRONMENT_REQUIRED')
    try:
        profile = validate_execution_environment(env)
        if profile.name != 'MIN_RBAC_EXECUTOR':
            raise ValueError('MIN_RBAC_EXECUTOR_REQUIRED')
    except Exception:
        raise ValueError('GUARDED_ENVIRONMENT_REJECTED') from None
    h = {name: hashlib.sha256() for name in ('stdout', 'stderr')}
    counts = {'stdout': 0, 'stderr': 0}
    timed_out = limited = False
    code = sig = None
    error = None
    process = None
    start = time.monotonic()
    try:
        process = subprocess.Popen(command, env=env, cwd=cwd, stdin=subprocess.DEVNULL,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
        with selectors.DefaultSelector() as sel:
            for name in ('stdout', 'stderr'):
                pipe = getattr(process, name)
                os.set_blocking(pipe.fileno(), False)
                sel.register(pipe, selectors.EVENT_READ, name)
            killed = False
            while sel.get_map() or process.poll() is None:
                if not killed and time.monotonic() - start >= timeout:
                    timed_out = True
                    try: os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError: pass
                    killed = True
                for key, _ in sel.select(0.02):
                    chunk = os.read(key.fileobj.fileno(), 65536)
                    if not chunk:
                        sel.unregister(key.fileobj)
                        key.fileobj.close()
                        continue
                    counts[key.data] += len(chunk)
                    h[key.data].update(chunk)
                    if not killed and sum(counts.values()) > max_output:
                        limited = True
                        try: os.killpg(process.pid, signal.SIGKILL)
                        except ProcessLookupError: pass
                        killed = True
                # Bound even inherited pipes held by a detached descendant.
                if killed and time.monotonic() - start > timeout + 1:
                    break
            ret = process.wait(timeout=1)
            code, sig = (ret, None) if ret >= 0 else (None, -ret)
        if limited: error = 'OUTPUT_LIMIT'
        elif timed_out: error = 'TIMEOUT'
        elif sig is not None: error = 'SIGNAL_TERMINATION'
        elif code != 0: error = 'NONZERO_EXIT'
    except OSError as exc:
        error = type(exc).__name__  # No path/stderr/exception text.
    finally:
        if process is not None:
            if process.poll() is None:
                try: os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError: pass
                process.wait()
            for pipe in (process.stdout, process.stderr):
                if pipe and not pipe.closed: pipe.close()
    return record('CHILD_EXIT_FACT', 'real-local-subprocess', identity,
                  {'executable': str(command[0])}, {'executable': str(command[0])},
                  'OBSERVED' if error is None else 'EXECUTION_ERROR', error, evidence_ref,
                  commandIdentity={'executable': str(command[0]), 'argvSha256': hashlib.sha256(json.dumps(command).encode()).hexdigest()},
                  exit={'code': code, 'signal': sig, 'timedOut': timed_out, 'outputLimitExceeded': limited},
                  **{name: {'bytes': counts[name], 'sha256': h[name].hexdigest(), 'contentStored': False} for name in counts})


def observe_prerequisite(kind, *, identity, target, evidence_ref, path=None, check=None, expected_holder=None):
    """Observe an actual filesystem operation or supplied guarded read/check callable.

    A sentinel reader is labeled by the caller; never masquerades as a real API.
    check may raise actual FileNotFoundError/PermissionError/BoundaryError. Missing
    result is not a success and expected PASS/FAIL is never an input.
    """
    error = None
    observed = None
    status = 'OBSERVED'
    details = {}
    source = 'local-filesystem' if kind in ('binary', 'kubeconfig-file') else 'supplied-check-callable'
    try:
        if kind in ('binary', 'kubeconfig-file'):
            info = Path(path).stat()
            details = {'exists': True, 'regularFile': stat.S_ISREG(info.st_mode)}
            if kind == 'binary': details['executable'] = bool(info.st_mode & 0o111)
            if not details['regularFile'] or (kind == 'binary' and not details['executable']):
                error, status = 'UNAVAILABLE', 'UNAVAILABLE'
            observed = {'path': str(path)}
        else:
            obj = check()
            if obj is None:
                error, status = 'OBJECT_UNAVAILABLE', 'UNAVAILABLE'
            elif kind == 'kubeconfig-boundary':
                details = {'accepted': True}
                observed = target
            elif kind == 'lease':
                observed = {'name': obj.get('metadata', {}).get('name'), 'namespace': obj.get('metadata', {}).get('namespace')}
                holder = obj.get('spec', {}).get('holderIdentity')
                details = {'holderPresent': holder is not None, 'holderMatches': holder == expected_holder}
                if holder is None: error, status = 'LEASE_HOLDER_UNAVAILABLE', 'UNAVAILABLE'
                elif holder != expected_holder: error, status = 'LEASE_HOLDER_MISMATCH', 'MISMATCH'
            elif kind == 'rbac':
                if not isinstance(obj, bool): raise ValueError('RBAC_RESULT_MALFORMED')
                details = {'allowed': obj}
                observed = target
                if not obj: error, status = 'RBAC_DENIED', 'DENIED'
            else:
                observed = {'name': obj.get('metadata', {}).get('name'), 'namespace': obj.get('metadata', {}).get('namespace')}
    except Exception as exc:
        error, status = type(exc).__name__, 'UNAVAILABLE'
    return record('PREREQUISITE_FACT', source, identity, target, observed, status, error,
                  evidence_ref, prerequisite=kind, observation=details)


def strict_json_equal(a, b):
    # JSON.parse / isDeepStrictEqual compatibility for JSON-domain values.
    if isinstance(a, bool) or isinstance(b, bool):
        return type(a) is type(b) and a == b
    if isinstance(a, (int, float)) and isinstance(b, (int, float)):
        return a == b
    if type(a) is not type(b):
        return False
    if isinstance(a, dict):
        return set(a) == set(b) and all(strict_json_equal(a[k], b[k]) for k in a)
    if isinstance(a, list):
        return len(a) == len(b) and all(strict_json_equal(x, y) for x, y in zip(a, b))
    return a == b


def observe_uid_values(before, after, *, identity, target, evidence_ref):
    """Exact SOPS consumed fields only; in-memory synthetic comparison, no Gate decision.

    `dataShape` is descriptive (not an extra production validation rule). Equality
    is Python structural equality for the dictionary/string schemas used here;
    raw inputs are not normalized, mutated or serialized into the evidence.
    """
    saved = copy.deepcopy((before, after))
    def fields(obj):
        if not isinstance(obj, dict):
            return None, None, False, None, 'MALFORMED_OBJECT'
        meta = obj.get('metadata')
        uid = meta.get('uid') if isinstance(meta, dict) else None
        present = 'data' in obj
        data = obj.get('data')
        shape = 'MISSING' if not present else ('MAP' if isinstance(data, dict) else 'MALFORMED')
        return uid, data, present, obj.get('type'), shape
    buid, bdata, bpresent, btype, bshape = fields(before)
    auid, adata, apresent, atype, ashape = fields(after)
    errors = []
    if buid is None or auid is None: errors.append('UID_MISSING')
    if not bpresent or not apresent: errors.append('VALUE_MISSING')
    if 'MALFORMED' in (bshape, ashape) or 'MALFORMED_OBJECT' in (bshape, ashape): errors.append('VALUE_MALFORMED')
    return record('UID_VALUE_FACT', 'synthetic-local-object-comparison', identity, target,
                  {'before': {k: before.get('metadata', {}).get(k) for k in ('namespace', 'name')} if isinstance(before, dict) and isinstance(before.get('metadata'), dict) else None,
                   'after': {k: after.get('metadata', {}).get(k) for k in ('namespace', 'name')} if isinstance(after, dict) and isinstance(after.get('metadata'), dict) else None},
                  'OBSERVED' if not errors else 'INCOMPLETE', ','.join(errors) if errors else None, evidence_ref,
                  uid={'before': buid, 'after': auid, 'equal': buid == auid if buid is not None and auid is not None else None},
                  values={'beforePresent': bpresent, 'afterPresent': apresent, 'beforeShape': bshape, 'afterShape': ashape,
                          'equal': strict_json_equal(bdata, adata) if bpresent and apresent else None},
                  typeEqual=btype == atype, rawUnchanged=(saved == (before, after)))
