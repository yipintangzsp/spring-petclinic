"""Extract only a digest-verified public build input into an owned directory."""
import argparse
import hashlib
from pathlib import Path, PurePosixPath
import tarfile

p = argparse.ArgumentParser()
p.add_argument('archive')
p.add_argument('destination')
p.add_argument('sha256')
a = p.parse_args()
archive = Path(a.archive)
with archive.open('rb') as f:
    if hashlib.file_digest(f, 'sha256').hexdigest() != a.sha256:
        raise SystemExit('Build input digest mismatch')
with tarfile.open(archive) as t:
    for m in t.getmembers():
        path = PurePosixPath(m.name)
        if path.is_absolute() or '..' in path.parts or not (m.isfile() or m.isdir()):
            raise SystemExit('Unexpected build input member: ' + m.name)
    t.extractall(a.destination, filter='data')
