"""Warm Trivy through the existing local registry using a verified official OCI DB.

The caller supplies an official manifest and its completely verified layer archive.
Trivy installs it normally and writes its own DownloadedAt; upstream updates stay on.
"""
import argparse
import base64
import datetime as dt
import hashlib
import json
import shlex
import subprocess
import sys
import tarfile
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'analytics'))
from controlled import HeavyRun, kube, remote


def warm(manifest_path, archive_path, evidence_path):
    evidence = Path(evidence_path); evidence.mkdir(exist_ok=True, parents=True)
    archive = Path(archive_path)
    manifest_bytes = Path(manifest_path).read_bytes()
    manifest = json.loads(manifest_bytes)
    layer, = manifest['layers']
    if layer['mediaType'] != 'application/vnd.aquasec.trivy.db.layer.v1.tar+gzip':
        raise ValueError('Expected the official Trivy vulnerability DB layer')
    if archive.stat().st_size != layer['size'] or 'sha256:' + hashlib.file_digest(archive.open('rb'), 'sha256').hexdigest() != layer['digest']:
        raise ValueError('Official vulnerability DB archive failed size/SHA256 verification')
    with tarfile.open(archive, 'r:gz') as packed:
        member = next(item for item in packed.getmembers() if item.name.removeprefix('./') == 'metadata.json')
        upstream_metadata = json.load(packed.extractfile(member))
    if dt.datetime.fromisoformat(upstream_metadata['NextUpdate'].replace('Z', '+00:00')) <= dt.datetime.now(dt.timezone.utc):
        raise RuntimeError('Official artifact is expired; fetch a fresh upstream manifest first')
    config = base64.b64decode(manifest['config']['data'])
    if 'sha256:' + hashlib.sha256(config).hexdigest() != manifest['config']['digest']:
        raise ValueError('OCI config digest mismatch')
    base = 'http' + '://192.168.1.58:30050'
    repository = '/v2/platform-cache/trivy-db'
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

    def request(path, method='GET', data=None, headers=None):
        return opener.open(urllib.request.Request(base + path, data=data, method=method, headers=headers or {}), timeout=30)

    def upload(path, digest):
        try:
            with request(repository + '/blobs/' + digest, 'HEAD'):
                return
        except urllib.error.HTTPError as problem:
            if problem.code != 404:
                raise
        with request(repository + '/blobs/uploads/', 'POST', b'') as response:
            location = urllib.parse.urlsplit(response.headers['Location'])
        query = urllib.parse.parse_qsl(location.query) + [('digest', digest)]
        destination = base + location.path + '?' + urllib.parse.urlencode(query)
        subprocess.run(['curl', '--noproxy', '*', '-fsS', '--connect-timeout', '8', '--max-time', '120',
                        '-X', 'PUT', '-H', 'Content-Type: application/octet-stream',
                        '--upload-file', str(path), destination], check=True, timeout=130, capture_output=True)

    with HeavyRun('trivy-db-warm', 1536, evidence) as guard:
        previous = kube(['-n', 'harbor', 'exec', 'harbor-trivy-0', '--',
                         'cat', '/home/scanner/.cache/trivy/db/metadata.json'])
        (evidence / 'before-metadata.json').write_text(json.dumps(previous, indent=2))
        # No competing scanner CLI may still be running after a failed build.
        processes = str(kube(['-n', 'harbor', 'exec', 'harbor-trivy-0', '--', 'ps', '-o', 'comm']))
        if any(line.strip() == 'trivy' for line in processes.splitlines()):
            raise RuntimeError('A previous scanner CLI is still active; preserve it for inspection')
        config_path = evidence / 'oci-config.json'; config_path.write_bytes(config)
        upload(config_path, manifest['config']['digest']); guard.check()
        upload(archive, layer['digest']); guard.check()
        with request(repository + '/manifests/2', 'PUT', manifest_bytes,
                     {'Content-Type': manifest['mediaType']}) as response:
            manifest_digest = response.headers['Docker-Content-Digest']
        if manifest_digest != 'sha256:' + hashlib.sha256(manifest_bytes).hexdigest():
            raise RuntimeError('Local OCI manifest digest mismatch')
        (evidence / 'oci-proof.json').write_text(json.dumps({'layer': layer, 'manifest_digest': manifest_digest}, indent=2))
        pidfile = '/tmp/petclinic-db-warm-' + dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dT%H%M%S') + '.pid'
        cli = ['env', 'HTTP_PROXY=', 'HTTPS_PROXY=', 'ALL_PROXY=', 'NO_PROXY=192.168.1.58,localhost,127.0.0.1',
               'trivy', 'image', '--download-db-only', '--db-repository',
               '192.168.1.58:30050/platform-cache/trivy-db:2', '--insecure',
               '--cache-dir', '/home/scanner/.cache/trivy', '--timeout', '3m', '--no-progress']
        script = 'set -e; test ! -e ' + shlex.quote(pidfile) + '; echo $$ >' + shlex.quote(pidfile) + '; exec ' + shlex.join(cli)
        command = shlex.join(['sudo', '-n', 'kubectl', '-n', 'harbor', 'exec', 'harbor-trivy-0', '--', 'sh', '-c', script])
        guard.compute_stopped = False
        process = None
        try:
            with (evidence / 'normal-trivy-download.log').open('w') as log:
                process = subprocess.Popen(['ssh', '-o', 'BatchMode=yes', '192.168.1.58', command], stdout=log, stderr=log)
                deadline = time.monotonic() + 210
                while process.poll() is None:
                    guard.check()
                    if time.monotonic() > deadline:
                        raise TimeoutError('Local OCI database warm exceeded its bounded deadline')
                    time.sleep(3)
                if process.returncode:
                    raise RuntimeError('Normal Trivy download failed; inspect private log')
            guard.compute_stopped = True
            metadata = kube(['-n', 'harbor', 'exec', 'harbor-trivy-0', '--',
                             'cat', '/home/scanner/.cache/trivy/db/metadata.json'])
            now = dt.datetime.now(dt.timezone.utc)
            if dt.datetime.fromisoformat(metadata['NextUpdate'].replace('Z', '+00:00')) <= now:
                raise RuntimeError('Official DB is already expired; do not release with stale data')
            (evidence / 'normal-trivy-metadata.json').write_text(json.dumps(metadata, indent=2))
            print(json.dumps({'normal_trivy_download': True, 'metadata': metadata, 'layer_digest': layer['digest']}), flush=True)
        finally:
            if process is None:
                guard.compute_stopped = True
            if process is not None and not guard.compute_stopped:
                # A unique file records this invocation's exec PID; never kill
                # another CLI or the scanner adapter main process.
                stop = ('if [ -f ' + shlex.quote(pidfile) + ' ]; then pid=$(cat ' + shlex.quote(pidfile) + '); '
                        'if [ -e /proc/$pid/comm ] && [ "$(cat /proc/$pid/comm)" = trivy ]; then '
                        'kill -TERM "$pid"; fi; fi')
                kube(['-n', 'harbor', 'exec', 'harbor-trivy-0', '--', 'sh', '-c', stop])
                process.wait(timeout=20)
                check = ('if [ -f ' + shlex.quote(pidfile) + ' ]; then pid=$(cat ' + shlex.quote(pidfile)
                         + '); test ! -e /proc/$pid/comm || test "$(cat /proc/$pid/comm)" != trivy; fi')
                kube(['-n', 'harbor', 'exec', 'harbor-trivy-0', '--', 'sh', '-c', check])
                guard.compute_stopped = True
            if guard.compute_stopped:
                kube(['-n', 'harbor', 'exec', 'harbor-trivy-0', '--', 'rm', '-f', pidfile])


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--manifest', required=True)
    parser.add_argument('--archive', required=True)
    parser.add_argument('--evidence', required=True)
    args = parser.parse_args()
    warm(args.manifest, args.archive, args.evidence)
