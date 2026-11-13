import unittest,json,hashlib,copy
from pathlib import Path
from jsonschema import Draft202012Validator,ValidationError
from audit_model import score,resource_decision,validate_capacity,validate_inventory,validate_blocker,COLUMNS
from boundary_review import validate_graph
O=Path(__file__).resolve().parent;R=O.parents[2];D=O.parent/'trivy-guard-experiment-design';B=O.parent/'trivy-guard-dependency-boundary-review';E=O.parent/'runtime-checkpoint-epoch-v2'
load=lambda p:json.loads(p.read_text());ROWS=load(O/'candidate-inventory.json')['candidates'];REQ=load(O/'EXPERIMENT_RESOURCE_REQUIREMENTS.json');BLOCK=load(O/'blocker-receipt.json')
def good():return dict(ROWS[4],productionRole='VALIDATION_SAFE',**{k:'PASS' for k in COLUMNS})
class Inventory(unittest.TestCase):
 def test_current_inventory_valid(self):self.assertTrue(validate_inventory(ROWS,REQ))
 def test_seven_actual_candidates(self):self.assertEqual(len(ROWS),7)
 def test_no_eligible(self):self.assertEqual(resource_decision(ROWS),'NOT_AVAILABLE')
 def test_duplicate_candidate_rejected(self):self.assertRaises(ValueError,validate_inventory,ROWS+[ROWS[0]],REQ)
 def test_actual_free_not_total(self):self.assertLess(ROWS[0]['availableCapacityBytes'],REQ['minimumIndependentPhysicalAvailableBytes'])
 def test_free_math(self):
  for r in ROWS:
   for c in r['capacityChecks']:validate_capacity(c)
 def test_total_capacity_does_not_override_free(self):x=copy.deepcopy(ROWS[0]['capacityChecks'][0]);x['status']='PASS';self.assertRaises(ValueError,validate_capacity,x)
 def test_unknown_free_not_pass(self):x={'requiredBytes':100,'availableBytes':None,'headroomBytes':None,'status':'PASS'};self.assertRaises(ValueError,validate_capacity,x)
 def test_negative_headroom_preserved(self):self.assertTrue(all(c['headroomBytes']<0 for r in ROWS for c in r['capacityChecks'] if c['status']=='FAIL'))
 def test_no70GiB_relaxation(self):self.assertEqual(REQ['primaryGuestCapacityBytes'],270430261248);self.assertEqual(REQ['minimumIndependentPhysicalAvailableBytes'],300*2**30)
 def test_full_filesystem_matrix(self):self.assertEqual(len(ROWS[0]['mustMatchFilesystem']),8)
 def test_missing_property_rejected(self):r=copy.deepcopy(ROWS);r[0]['mustMatchFilesystem'].pop();self.assertRaises(ValueError,validate_inventory,r,REQ)
 def test_workers_arm64_mismatch_retained(self):
  for r in ROWS:
   if r['candidateId'].startswith('node-'):self.assertEqual(next(x['result'] for x in r['mustMatchFilesystem'] if x['property']=='architecture/tool'),'FAIL')
 def test_kind_tmpfs_rejection(self):r=next(x for x in ROWS if x['candidateId']=='kind-security-test-sops');self.assertEqual(r['Storage Topology'],'FAIL')
 def test_unknown_worker_fs_not_fabricated(self):r=next(x for x in ROWS if x['candidateId']=='node-ucloud-worker');self.assertEqual(r['filesystem'],'UNKNOWN')
 def test_all_failures_explained(self):self.assertTrue(all(r['rejectionReasons'] for r in ROWS))
class Scoring(unittest.TestCase):
 def test_complete_synthetic_eligible(self):self.assertEqual(score(good()),'ELIGIBLE')
 def test_prod_critical_free_disk_not_eligible(self):r=good();r['productionRole']='PRODUCTION_CRITICAL';self.assertEqual(score(r),'INELIGIBLE')
 def test_prod_shared_not_eligible(self):r=good();r['productionRole']='PRODUCTION_SHARED';self.assertEqual(score(r),'INELIGIBLE')
 def test_unknown_safety_rejected(self):r=good();r['productionRole']='UNKNOWN';self.assertEqual(score(r),'INELIGIBLE')
 def test_disk_fail_not_conditional(self):r=good();r['Disk']='FAIL';r['nonDestructivePreflightOnlyProven']=True;self.assertEqual(score(r),'INELIGIBLE')
 def test_fs_fail_not_conditional(self):r=good();r['Filesystem']='FAIL';self.assertEqual(score(r),'INELIGIBLE')
 def test_isolation_fail_not_conditional(self):r=good();r['Isolation']='FAIL';self.assertEqual(score(r),'INELIGIBLE')
 def test_missing_critical_unknown(self):r=good();r['Filesystem']='UNKNOWN';self.assertEqual(score(r),'UNKNOWN')
 def test_conditional_needs_non_destructive_proof(self):r=good();r['Network']='UNKNOWN';self.assertEqual(score(r),'UNKNOWN');r['nonDestructivePreflightOnlyProven']=True;self.assertEqual(score(r),'CONDITIONALLY_ELIGIBLE')
 def test_unknown_not_available(self):r=good();r['Disk']='UNKNOWN';self.assertEqual(resource_decision([r]),'UNKNOWN')
 def test_available_requires_eligible(self):self.assertEqual(resource_decision([good()]),'AVAILABLE')
 def test_empty_inventory_unknown(self):self.assertEqual(resource_decision([]),'UNKNOWN')
class Boundaries(unittest.TestCase):
 def test_dependency_graph_preserved(self):self.assertTrue(validate_graph(load(O/'dependency-graph.json'))['validated'])
 def test_no_proxy_dependency(self):self.assertEqual(load(O/'dependency-graph.json')['productionProxyRequired'],'NO')
 def test_preflight_schema_valid(self):Draft202012Validator.check_schema(load(O/'future-preflight.schema.json'))
 def test_preflight_byte_identical(self):self.assertEqual((O/'future-preflight.schema.json').read_bytes(),(B/'future-preflight.schema.json').read_bytes())
 def test_blocker_valid(self):self.assertTrue(validate_blocker(BLOCK,ROWS))
 def test_blocker_cannot_pass_policy(self):b=copy.deepcopy(BLOCK);b['policyResult']='PASS';self.assertRaises(ValueError,validate_blocker,b,ROWS)
 def test_blocker_cannot_hide_missing_rejection(self):b=copy.deepcopy(BLOCK);b['rejectedCandidates'].pop();self.assertRaises(ValueError,validate_blocker,b,ROWS)
 def test_no_loop_requires_material_change(self):b=copy.deepcopy(BLOCK);b['materialChanges']=[];self.assertRaises(ValueError,validate_blocker,b,ROWS)
 def test_sampler_only_not_peak_proof(self):d=load(O/'validation-existing-detail.json')['samplerCalibration']['result'];self.assertEqual(d['samples'],100);self.assertFalse(d['fullPeakMeasurementProven'])
 def test_no_proxy_reinvestigation(self):self.assertFalse(load(O/'scope.json')['proxyReinvestigation'])
 def test_no_new_epoch_or_experiment(self):s=load(O/'scope.json');self.assertFalse(s['newEpochAllowed']);self.assertFalse(s['experimentAllowed'])
class Integrity(unittest.TestCase):
 def test_all_prior_sealed_files_unchanged(self):
  for root in [D,B,E]:
   for name,h in load(root/'evidence-sha256.json')['files'].items():self.assertEqual(hashlib.sha256((root/name).read_bytes()).hexdigest(),h,name)
 def test_frozen_sources_and_gates_preserved(self):
  m=load(E/'source-hash-matrix.json')
  for group in ['implementationHashes','frozenGateHashes']:
   for p,h in m[group].items():self.assertEqual(hashlib.sha256((R/p).read_bytes()).hexdigest(),h,p)
 def test_guard_formula_identity(self):self.assertEqual(hashlib.sha256((R/'infra/observability/scanner-db-refresh.mjs').read_bytes()).hexdigest(),'6e49e8e3d79264e916f0c3c424181ab6e8d15342fcca24a811e3f78de89f306a')
if __name__=='__main__':unittest.main(verbosity=2)
