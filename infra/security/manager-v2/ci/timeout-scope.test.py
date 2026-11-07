import pathlib,importlib.util,json,unittest,copy
p=pathlib.Path(__file__).with_name('source-snapshot.py');s=importlib.util.spec_from_file_location('source',p);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);cfg=json.loads(p.with_name('source-projects.json').read_text());sha='a'*40
class TimeoutTest(unittest.TestCase):
 def test_project_only_and_fixed_cap(self):
  self.assertEqual(m.project_execution_budget(cfg,'other',sha,{})['scanTimeoutMs'],10000)
  self.assertEqual(m.project_execution_budget(cfg,'python-fixture',sha,{'projectId':'python-fixture','commitSha':sha})['scanTimeoutMs'],60000)
  with self.assertRaises(ValueError):m.project_execution_budget(cfg,'python-fixture',sha,{'projectId':'other','commitSha':sha})
  bad=copy.deepcopy(cfg);bad['projectOverrides']['python-fixture']['executionBudget']['scanTimeoutMs']=60001
  with self.assertRaises(ValueError):m.project_execution_budget(bad,'python-fixture',sha,{'projectId':'python-fixture','commitSha':sha})
if __name__=='__main__':unittest.main()
