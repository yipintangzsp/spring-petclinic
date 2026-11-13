"""In-memory schema/graph/gate fixtures ONLY. No real pre-flight or DB refresh."""
import unittest,json,hashlib,copy
from pathlib import Path
from jsonschema import Draft202012Validator,ValidationError
from boundary_review import validate_graph,evaluate_preflight,evaluate_gates,ReviewError
O=Path(__file__).resolve().parent;R=O.parents[2];D=O.parent/'trivy-guard-experiment-design';E=O.parent/'runtime-checkpoint-epoch-v2'
def read(p):return json.loads(p.read_text())
GRAPH=read(O/'dependency-graph.json');SCHEMA=read(O/'future-preflight.schema.json');CHECKS=read(O/'design-completeness-review.json')['checks']
def fixture(status='VERIFIED'):
 return {'schemaVersion':1,'classification':'ISOLATED_PREFLIGHT_ONLY','targetId':'synthetic-lab-never-executed','networkMode':'DIRECT','checks':{k:{'status':status,'evidenceRef':'synthetic-only/'+k+'.json' if status=='VERIFIED' else None} for k in SCHEMA['properties']['checks']['required']}}
class SchemaTests(unittest.TestCase):
 def test_sealed_plan_validates_review_schema(self):Draft202012Validator(read(O/'sealed-design-review.schema.json')).validate(read(D/'experiment-plan.json'))
 def test_design_missing_disk_budget_rejected(self):x=read(D/'experiment-plan.json');del x['diskSizing'];self.assertRaises(ValidationError,Draft202012Validator(read(O/'sealed-design-review.schema.json')).validate,x)
 def test_design_guard_mutation_not_allowed(self):x=read(D/'experiment-plan.json');x['guardChangeAllowed']=True;self.assertRaises(ValidationError,Draft202012Validator(read(O/'sealed-design-review.schema.json')).validate,x)
 def test_sealed_design_evidence_schema_valid(self):Draft202012Validator.check_schema(read(D/'future-evidence.schema.json'))
 def test_new_preflight_schema_valid(self):Draft202012Validator.check_schema(SCHEMA)
 def test_design_coverage(self):self.assertEqual({c['case'] for c in read(D/'experiment-plan.json')['cases']},set('ABCDEFGH'))
 def test_design_frozen_topology(self):self.assertEqual(read(D/'experiment-plan.json')['measurement']['fastSampler']['periodMs'],10)
 def test_design_all_review_checks_true(self):self.assertTrue(all(CHECKS.values()));self.assertEqual(len(CHECKS),11)
 def test_preflight_complete_synthetic(self):self.assertTrue(evaluate_preflight(fixture(),SCHEMA))
 def test_preflight_unknown_is_not_ready(self):self.assertFalse(evaluate_preflight(fixture('NOT_TESTED'),SCHEMA))
 def test_preflight_blocked_is_not_ready(self):self.assertFalse(evaluate_preflight(fixture('BLOCKED'),SCHEMA))
 def test_preflight_no_target_is_not_ready(self):x=fixture();x['targetId']=None;self.assertFalse(evaluate_preflight(x,SCHEMA))
 def test_preflight_no_selected_route_is_not_ready(self):x=fixture();x['networkMode']='NOT_SELECTED';self.assertFalse(evaluate_preflight(x,SCHEMA))
 def test_independent_proxy_supported(self):x=fixture();x['networkMode']='VALIDATION_PROXY';self.assertTrue(evaluate_preflight(x,SCHEMA))
 def test_production_proxy_hash_not_criterion(self):x=fixture();x['productionProxyHash']='synthetic';self.assertRaises(ValidationError,evaluate_preflight,x,SCHEMA)
 def test_production_proxy_route_forbidden(self):x=fixture();x['networkMode']='PRODUCTION_PROXY';self.assertRaises(ValidationError,evaluate_preflight,x,SCHEMA)
 def test_missing_criterion_not_pass(self):x=fixture();del x['checks']['availableDisk'];self.assertRaises(ValidationError,evaluate_preflight,x,SCHEMA)
 def test_verified_without_evidence_rejected(self):x=fixture();x['checks']['samplerReadiness']['evidenceRef']=None;self.assertRaises(ValidationError,evaluate_preflight,x,SCHEMA)
 def test_blank_evidence_rejected(self):x=fixture();x['checks']['networkPath']['evidenceRef']=' ';self.assertRaises(ValidationError,evaluate_preflight,x,SCHEMA)
 def test_unknown_status_rejected(self):x=fixture();x['checks']['networkPath']['status']='PASS';self.assertRaises(ValidationError,evaluate_preflight,x,SCHEMA)
class GraphTests(unittest.TestCase):
 def test_graph_valid(self):self.assertTrue(validate_graph(GRAPH)['validated'])
 def test_prod_proxy_not_reachable(self):self.assertNotIn('prod-v2rayN',validate_graph(GRAPH)['reachable'])
 def test_unknown_category_rejected(self):g=copy.deepcopy(GRAPH);g['nodes'][0]['classification']='PASS';self.assertRaises(ReviewError,validate_graph,g)
 def test_duplicate_node_rejected(self):g=copy.deepcopy(GRAPH);g['nodes'].append(g['nodes'][0]);self.assertRaises(ReviewError,validate_graph,g)
 def test_missing_node_reference_rejected(self):g=copy.deepcopy(GRAPH);g['edges'].append({'from':'experiment','to':'missing'});self.assertRaises(ReviewError,validate_graph,g)
 def test_cycle_rejected(self):g=copy.deepcopy(GRAPH);g['edges'].append({'from':'network','to':'experiment'});self.assertRaises(ReviewError,validate_graph,g)
 def test_new_prod_proxy_edge_rejects_no(self):g=copy.deepcopy(GRAPH);g['edges'].append({'from':'network','to':'prod-xray'});self.assertRaises(ReviewError,validate_graph,g)
 def test_missing_rationale_rejected(self):g=copy.deepcopy(GRAPH);g['nodes'][0]['rationale']='';self.assertRaises(ReviewError,validate_graph,g)
class GateTests(unittest.TestCase):
 def eval(self,c='BROKEN',x=None,graph=None,checks=None):return evaluate_gates(CHECKS if checks is None else checks,GRAPH if graph is None else graph,c,fixture() if x is None else x,SCHEMA)
 def test_broken_continuity_not_design_blocker(self):self.assertEqual(self.eval()['DESIGN_COMPLETENESS'],'READY')
 def test_independent_ready_lab_not_blocked_by_prod_drift_synthetic(self):self.assertEqual(self.eval()['EXPERIMENT_EXECUTION_GATE'],'READY')
 def test_continuity_remains_broken(self):self.assertEqual(self.eval()['PRODUCTION_CHECKPOINT_CONTINUITY'],'BROKEN')
 def test_no_execution_authorized(self):self.assertFalse(self.eval()['executionAuthorizedByThisReview'])
 def test_case1_missing_lab_not_proxy(self):self.assertEqual(self.eval(x=fixture('NOT_TESTED'))['decisionMatrixCase'],1)
 def test_actual_missing_prerequisites_not_ready(self):self.assertEqual(self.eval(x=fixture('NOT_TESTED'))['EXPERIMENT_EXECUTION_GATE'],'NOT_READY')
 def test_case2_actual_dependency_needs_continuity(self):g=copy.deepcopy(GRAPH);g['productionProxyRequired']='YES';self.assertEqual(self.eval(graph=g)['decisionMatrixCase'],2);self.assertEqual(self.eval(graph=g)['EXPERIMENT_EXECUTION_GATE'],'NOT_READY')
 def test_case3_design_gap(self):checks=copy.deepcopy(CHECKS);checks['peak-space measurement']=False;self.assertEqual(self.eval(checks=checks)['decisionMatrixCase'],3)
 def test_empty_design_not_pass(self):self.assertRaises(ReviewError,self.eval,checks={})
 def test_string_true_not_bool(self):checks=copy.deepcopy(CHECKS);checks['A-H coverage']='true';self.assertRaises(ReviewError,self.eval,checks=checks)
 def test_unknown_continuity_not_silently_accepted(self):self.assertRaises(ReviewError,self.eval,c='UNKNOWN')
class IntegrityTests(unittest.TestCase):
 def test_old_seals_all_files_unchanged(self):
  for root in [D,E]:
   for p,h in read(root/'evidence-sha256.json')['files'].items():self.assertEqual(hashlib.sha256((root/p).read_bytes()).hexdigest(),h,p)
 def test_frozen_implementation_references(self):
  for p,h in read(D/'frozen-implementation.json')['files'].items():self.assertEqual(hashlib.sha256((R/p).read_bytes()).hexdigest(),h,p)
 def test_source_and_frozen_gates(self):
  for k in ['implementationHashes','frozenGateHashes']:
   for p,h in read(E/'source-hash-matrix.json')[k].items():self.assertEqual(hashlib.sha256((R/p).read_bytes()).hexdigest(),h,p)
 def test_old_verdict_remains_not_ready(self):self.assertEqual(read(D/'verdict.json')['TRIVY_GUARD_REVALIDATION_EXPERIMENT_DESIGN'],'NOT_READY')
 def test_no_new_epoch(self):self.assertFalse(read(O/'review-scope.json')['newEpochAllowed'])
 def test_no_live_experiment(self):self.assertFalse(read(O/'review-scope.json')['experimentAllowed'])
if __name__=='__main__':unittest.main(verbosity=2)
