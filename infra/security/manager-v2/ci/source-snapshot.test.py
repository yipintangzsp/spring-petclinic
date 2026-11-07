import importlib.util,pathlib,tempfile,tarfile,io,unittest
p=pathlib.Path(__file__).with_name('source-snapshot.py');spec=importlib.util.spec_from_file_location('source_snapshot',p);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
limits={'files':16,'archiveBytes':65536,'expandedBytes':65536,'fileBytes':32768}
def archive(name='root/main.py',data=b'print("demo")\n',kind=tarfile.REGTYPE):
 out=io.BytesIO()
 with tarfile.open(fileobj=out,mode='w:gz')as t:
  x=tarfile.TarInfo(name);x.type=kind;x.size=len(data)if kind==tarfile.REGTYPE else 0;x.linkname='/etc/passwd'if kind==tarfile.SYMTYPE else '';t.addfile(x,io.BytesIO(data)if x.size else None)
 return out.getvalue()
class SnapshotTest(unittest.TestCase):
 def setUp(self):self.tmp=tempfile.TemporaryDirectory();self.dest=pathlib.Path(self.tmp.name).resolve()/'source';self.tree={'main.py':{'mode':'100644','oid':m.blob_oid(b'print("demo")\n')}}
 def tearDown(self):self.tmp.cleanup()
 def test_real_bytes_match_git_blob(self):
  r=m.materialize_verified_archive(archive(),self.tree,self.dest,limits);self.assertEqual(r['fileCount'],1);self.assertEqual((self.dest/'main.py').read_bytes(),b'print("demo")\n')
 def test_canonical_git_bytes_preserve_line_endings_and_reject_corruption(self):
  data=b'@echo off\r\n';e={'mvnw.cmd':{'mode':'100644','oid':m.blob_oid(data)}};batch=(e['mvnw.cmd']['oid']+' blob '+str(len(data))+'\n').encode()+data+b'\n'
  a=m.canonical_blob_archive(e,batch,limits);r=m.materialize_verified_archive(a,e,self.dest,limits);self.assertEqual((self.dest/'mvnw.cmd').read_bytes(),data);self.assertEqual(r['fileCount'],1)
  with self.assertRaisesRegex(ValueError,'BLOB_MISMATCH'):m.canonical_blob_archive(e,batch[:-2]+b'X\n',limits)
 def test_traversal_rejected(self):
  with self.assertRaisesRegex(ValueError,'PATH_REJECTED'):m.materialize_verified_archive(archive('root/../outside'),self.tree,self.dest,limits)
  self.assertFalse(self.dest.exists())
 def test_symlink_rejected(self):
  with self.assertRaisesRegex(ValueError,'LINK_OR_TYPE'):m.materialize_verified_archive(archive(kind=tarfile.SYMTYPE),self.tree,self.dest,limits)
 def test_wrong_commit_content_rejected(self):
  with self.assertRaisesRegex(ValueError,'BLOB_MISMATCH'):m.materialize_verified_archive(archive(data=b'changed'),self.tree,self.dest,limits)
 def test_incomplete_tree_rejected(self):
  self.tree['missing.py']={'mode':'100644','oid':m.blob_oid(b'missing')}
  with self.assertRaisesRegex(ValueError,'INCOMPLETE_TREE'):m.materialize_verified_archive(archive(),self.tree,self.dest,limits)
 def test_existing_history_not_overwritten(self):
  self.dest.mkdir();(self.dest/'history').write_text('keep')
  with self.assertRaisesRegex(ValueError,'DESTINATION_REJECTED'):m.materialize_verified_archive(archive(),self.tree,self.dest,limits)
  self.assertEqual((self.dest/'history').read_text(),'keep')
if __name__=='__main__':unittest.main()
