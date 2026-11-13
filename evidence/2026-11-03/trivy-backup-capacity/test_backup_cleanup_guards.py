import unittest
from copy import deepcopy
from backup_cleanup_guards import *
class Guards(unittest.TestCase):
 def dest(self):return {**{k:True for k in ('independent','mountVerified','stableMount','formatSupported','reliabilityVerified','availableForFullWindow','restoreReadVerified','permissionsStable','largeFileValidated')},'freeBytes':200,'requiredBytes':100,'maxFileBytes':500,'largestFileBytes':300,'network':False,'usesSparseBudget':False}
 def candidate(self):return {'path':'/tmp/owned-fixture','classification':'SAFE_EPHEMERAL','sizeBytes':20,**{k:True for k in ('ownerVerified','lastUseVerified','reproducible','recoveryVerified','projectDependencyChecked','currentReferenceCheckComplete')},'neededByCurrentProject':False,'currentProcessReference':False,'symlink':False}
 def test_dest_valid_synthetic_only(self):self.assertTrue(destination_ready(self.dest()))
 def test_dest_each_missing_fact_fails_closed(self):
  for k in self.dest():
   with self.subTest(k=k):d=self.dest();del d[k];self.assertFalse(destination_ready(d))
 def test_dest_unknown_or_false_required_fails(self):
  for k in ('independent','stableMount','restoreReadVerified','reliabilityVerified','largeFileValidated','permissionsStable'):
   for val in (None,False,'true'):
    with self.subTest(k=k,val=val):d=self.dest();d[k]=val;self.assertFalse(destination_ready(d))
 def test_no_free_capacity(self):d=self.dest();d['freeBytes']=99;self.assertFalse(destination_ready(d))
 def test_large_file_limit(self):d=self.dest();d['maxFileBytes']=299;self.assertFalse(destination_ready(d))
 def test_invalid_sizes(self):
  for k in ('freeBytes','requiredBytes','maxFileBytes','largestFileBytes'):
   for v in (True,None,-1,float('nan'),'200'):
    with self.subTest(k=k,v=v):d=self.dest();d[k]=v;self.assertFalse(destination_ready(d))
 def test_network_needs_all_three_observations(self):
  d=self.dest();d['network']=True;self.assertFalse(destination_ready(d))
  for k in ('sustainedConnectivity','largeFileRoundtrip','timeoutBehaviorVerified'):d[k]=True
  self.assertTrue(destination_ready(d))
  for k in ('sustainedConnectivity','largeFileRoundtrip','timeoutBehaviorVerified'):
   c=deepcopy(d);c[k]=None;self.assertFalse(destination_ready(c))
 def test_sparse_estimate_needs_cold_source_and_restore(self):
  d=self.dest();d['usesSparseBudget']=True;self.assertFalse(destination_ready(d))
  for k in ('sparsePreservationValidated','coldSourceBoundVerified','sparseRestoreVerified'):d[k]=True
  self.assertTrue(destination_ready(d))
 def test_destination_boolean_types_strict(self):
  for k in ('network','usesSparseBudget'):
   for v in (0,1,None,'false'):
    d=self.dest();d[k]=v;self.assertFalse(destination_ready(d))
 def test_candidate_synthetic_valid(self):self.assertTrue(safe_candidate(self.candidate(),['/production']))
 def test_each_missing_proof_retains(self):
  for k in self.candidate():
   d=self.candidate();del d[k];self.assertFalse(safe_candidate(d,[]),k)
 def test_unknown_class_retained(self):
  for val in ('UNKNOWN','REVIEW_REQUIRED','RETAIN'):
   d=self.candidate();d['classification']=val;self.assertFalse(safe_candidate(d,[]))
 def test_process_reference_blocks(self):d=self.candidate();d['currentProcessReference']=True;self.assertFalse(safe_candidate(d,[]))
 def test_current_project_dependency_blocks(self):d=self.candidate();d['neededByCurrentProject']=True;self.assertFalse(safe_candidate(d,[]))
 def test_symlink_blocks(self):d=self.candidate();d['symlink']=True;self.assertFalse(safe_candidate(d,[]))
 def test_protected_child_blocks(self):self.assertFalse(safe_candidate(self.candidate(),['/tmp']))
 def test_protected_parent_blocks(self):self.assertFalse(safe_candidate(self.candidate(),['/tmp/owned-fixture/important']))
 def test_unsafe_paths_block(self):
  for p in ('/','relative','/tmp/../production'):
   d=self.candidate();d['path']=p;self.assertFalse(safe_candidate(d,[]))
 def test_insufficient_candidates_no_partial_delete(self):self.assertFalse(cleanup_plan_ready([self.candidate()],[],10,100)['ready'])
 def test_sufficient_synthetic_plan(self):self.assertTrue(cleanup_plan_ready([self.candidate()],[],90,100)['ready'])
 def test_duplicates_not_double_counted(self):self.assertFalse(cleanup_plan_ready([self.candidate(),self.candidate()],[],90,100)['ready'])
 def test_nested_not_double_counted(self):d=self.candidate();d['path']+='/child';self.assertFalse(cleanup_plan_ready([self.candidate(),d],[],90,100)['ready'])
 def test_empty_plan_does_not_execute_cleanup(self):self.assertFalse(cleanup_plan_ready([],[],100,100)['ready'])
 def test_invalid_free_or_target(self):
  for v in (-1,None,True):self.assertFalse(cleanup_plan_ready([],[],v,100)['ready'])
if __name__=='__main__':unittest.main()
