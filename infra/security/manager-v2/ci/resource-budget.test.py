import pathlib,importlib.util,unittest
p=pathlib.Path(__file__).with_name('resource-budget.py');s=importlib.util.spec_from_file_location('budget',p);m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
class BudgetTest(unittest.TestCase):
 def test_original_threshold_edges_and_actual_reason(self):
  self.assertFalse(any(m.decide(1073741824,1073741824,75).values()))
  for mem,disk,cpu,key in [(1073741823,1073741824,0,'memAvailable'),(1073741824,1073741823,0,'diskAvailable'),(1073741824,1073741824,75.01,'cpuBusy')]:
   r=m.decide(mem,disk,cpu);self.assertEqual([k for k,v in r.items()if v],[key])
 def test_unknown_fail_closed(self):
  for values in [(-1,1,0),(1,-1,0),(1,1,float('nan')),(1,1,101)]:
   with self.assertRaisesRegex(ValueError,'UNKNOWN'):m.decide(*values)
if __name__=='__main__':unittest.main()
