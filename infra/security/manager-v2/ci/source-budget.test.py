import pathlib,importlib.util,json,unittest
p=pathlib.Path(__file__).with_name('source-snapshot.py');s=importlib.util.spec_from_file_location('s',p);m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
cfg=json.loads(p.with_name('source-projects.json').read_text());sha='a'*40
class BudgetTest(unittest.TestCase):
 def test_project_and_commit_scoped_exception_default_unchanged(self):
  a=m.project_limits(cfg,'python-fixture',sha,{'projectId':'python-fixture','commitSha':sha});b=m.project_limits(cfg,'other-project',sha,{})
  self.assertEqual(a['fileBytes'],4194304);self.assertEqual(m.file_limit(a,'infra/security/controller.json'),8388608);self.assertEqual(m.file_limit(a,'other.json'),4194304);self.assertEqual(m.file_limit(b,'infra/security/controller.json'),4194304)
  for scope in [{},{'projectId':'other-project','commitSha':sha},{'projectId':'python-fixture','commitSha':'b'*40}]:
   with self.assertRaisesRegex(ValueError,'SCOPE_REJECTED'):m.project_limits(cfg,'python-fixture',sha,scope)
 def test_oversize_rejected_before_materialization(self):
  e={'other.json':{'mode':'100644','oid':'a'*40}}
  with self.assertRaisesRegex(ValueError,'BUDGET'):m.canonical_blob_archive(e,b'a'*40+b' blob 4194305\n',cfg['defaults'])
  a=m.project_limits(cfg,'python-fixture',sha,{'projectId':'python-fixture','commitSha':sha});e={'infra/security/controller.json':{'mode':'100644','oid':'a'*40}}
  with self.assertRaisesRegex(ValueError,'BUDGET'):m.canonical_blob_archive(e,b'a'*40+b' blob 8388609\n',a)
if __name__=='__main__':unittest.main()
