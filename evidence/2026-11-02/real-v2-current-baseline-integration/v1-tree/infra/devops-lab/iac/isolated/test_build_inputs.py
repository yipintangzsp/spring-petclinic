import hashlib
import io
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import unittest

SCRIPT = Path(__file__).parent / 'security' / 'extract.py'


class BuildInputExtraction(unittest.TestCase):
    def run_archive(self, name='safe/file', symlink=False, wrong_digest=False):
        root = tempfile.TemporaryDirectory()
        self.addCleanup(root.cleanup)
        directory = Path(root.name)
        archive = directory / 'input.tar.gz'
        out = directory / 'output'
        out.mkdir()
        with tarfile.open(archive, 'w:gz') as t:
            member = tarfile.TarInfo(name)
            if symlink:
                member.type = tarfile.SYMTYPE
                member.linkname = '/outside'
                t.addfile(member)
            else:
                member.size = 2
                t.addfile(member, io.BytesIO(b'ok'))
        digest = hashlib.sha256(archive.read_bytes()).hexdigest()
        result = subprocess.run([sys.executable, str(SCRIPT), str(archive), str(out),
                                 '0' * 64 if wrong_digest else digest],
                                capture_output=True, timeout=10)
        return result, out

    def test_verified_public_file_extracts(self):
        result, out = self.run_archive()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((out / 'safe/file').read_bytes(), b'ok')

    def test_traversal_rejected_before_extracting(self):
        result, out = self.run_archive('../outside')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(list(out.iterdir()), [])

    def test_links_rejected(self):
        result, out = self.run_archive('unsafe', symlink=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(list(out.iterdir()), [])

    def test_digest_mismatch_rejected(self):
        result, out = self.run_archive(wrong_digest=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(list(out.iterdir()), [])
