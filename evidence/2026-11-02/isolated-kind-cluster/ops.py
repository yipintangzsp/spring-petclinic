"""Explicit isolated runtime / dedicated kubeconfig environment. No default credentials."""
import json
import os
from pathlib import Path
import subprocess
import time

ROOT = Path(__file__).resolve().parent
BEFORE = json.loads((ROOT / 'pre-protection.json').read_text())
WORK = Path(BEFORE['workspace'])
KUBECONFIG = WORK / 'kubeconfig'
ENV = {k: v for k, v in os.environ.items() if k in {
    'PATH', 'USER', 'LOGNAME', 'SHELL', 'TMPDIR', 'LANG', 'LC_ALL', '__CF_USER_TEXT_ENCODING'
}}
ENV.update(HOME=str(WORK / 'home'), DOCKER_CONFIG=str(WORK / 'docker-config'),
           DOCKER_HOST=BEFORE['endpoint'], KUBECONFIG=str(KUBECONFIG),
           KIND_EXPERIMENTAL_PROVIDER='docker', XDG_CACHE_HOME=str(WORK / 'cache'))
DOCKER = ['/opt/homebrew/bin/docker', '--host', BEFORE['endpoint']]
KIND = ['/opt/homebrew/bin/kind']
KUBECTL = ['/opt/homebrew/bin/kubectl', '--kubeconfig', str(KUBECONFIG),
           '--context', 'kind-security-test-sops', '--request-timeout=20s']
IMAGE = 'docker.io/kindest/node:v1.35.0@sha256:452d707d4862f52530247495d180205e029056831160e22870e37e3f6c1ac31f'


def run(args, timeout=40, input=None):
    start = time.monotonic()
    proc = subprocess.run(args, env=ENV, input=input, capture_output=True,
                          text=True, timeout=timeout)
    return {'command': args, 'exit': proc.returncode, 'stdout': proc.stdout,
            'stderr': proc.stderr, 'seconds': round(time.monotonic() - start, 3)}


def save(name, value):
    (ROOT / name).write_text(json.dumps(value, indent=2))


def assert_runtime():
    result = run(DOCKER + ['info', '--format', '{{.ID}}|{{.Name}}|{{.Architecture}}|{{.CgroupVersion}}|{{.MemTotal}}|{{.DockerRootDir}}'])
    assert result['exit'] == 0, result
    fields = result['stdout'].strip().split('|')
    assert fields[0] == 'f0a9c4bb-ef14-4087-b0b1-7d5f02aa1ff8' and fields[1] == 'security-test', fields
    return result
