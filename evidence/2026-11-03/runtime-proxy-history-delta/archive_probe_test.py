import unittest,tempfile,tarfile,io,json
from pathlib import Path
from archive_probe import inspect_archive
class ArchiveTests(unittest.TestCase):
 def archive(self,p,mode='w',files=None):
  with tarfile.open(p,mode) as z:
   for name,b in files or [('binConfigs/config.json',b'{"synthetic":true}')]:
    e=tarfile.TarInfo(name);e.size=len(b);e.mtime=1;z.addfile(e,io.BytesIO(b))
 def test_plain_tar_metadata(self):
  with tempfile.TemporaryDirectory() as d:
   p=Path(d)/'a.tar';self.archive(p);r=inspect_archive(p);self.assertEqual(r['status'],'ARCHIVE_END_REACHED');self.assertEqual(len(r['candidates']),1)
 def test_gzip_metadata(self):
  with tempfile.TemporaryDirectory() as d:
   p=Path(d)/'a.tar.gz';self.archive(p,'w:gz');self.assertEqual(inspect_archive(p)['status'],'ARCHIVE_END_REACHED')
 def test_no_extraction_even_traversal_name(self):
  with tempfile.TemporaryDirectory() as d:
   p=Path(d)/'a.tar';self.archive(p,files=[('../escaped/config.json',b'{}')]);inspect_archive(p);self.assertEqual(list(Path(d).iterdir()),[p])
 def test_header_time_not_trust(self):
  with tempfile.TemporaryDirectory() as d:
   p=Path(d)/'a.tar';self.archive(p);self.assertEqual(inspect_archive(p)['candidates'][0]['trustLevel'],'UNTRUSTED')
 def test_no_content_in_output(self):
  with tempfile.TemporaryDirectory() as d:
   p=Path(d)/'a.tar';self.archive(p,files=[('config.json',b'SYNTHETIC_PRIVATE_VALUE')]);self.assertNotIn('SYNTHETIC_PRIVATE_VALUE',json.dumps(inspect_archive(p)))
 def test_gzip_read_bound(self):
  with tempfile.TemporaryDirectory() as d:
   p=Path(d)/'a.tar.gz';self.archive(p,'w:gz',files=[('blob',b'x'*100000)]);self.assertEqual(inspect_archive(p,byte_limit=10240)['status'],'DECOMPRESSED_READ_BOUND')
 def test_entry_bound(self):
  with tempfile.TemporaryDirectory() as d:
   p=Path(d)/'a.tar';self.archive(p);self.assertEqual(inspect_archive(p,entry_limit=0)['status'],'ENTRY_BOUND')
 def test_bad_archive_never_passes(self):
  with tempfile.TemporaryDirectory() as d:
   p=Path(d)/'a.tar';p.write_bytes(b'not an archive');self.assertEqual(inspect_archive(p)['status'],'READ_ERROR')
if __name__=='__main__':unittest.main(verbosity=2)
