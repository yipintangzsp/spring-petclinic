import unittest,copy,tempfile,json
from pathlib import Path
from epoch_engine import validate_blocker,validate_shape,safe_read,verify_epoch
def blocker(source='trivy'):
 return {'sourceId':source,'kind':'EngineeringBlockerReceipt','blockerType':'ENVIRONMENT' if source=='trivy' else 'DEPENDENCY','state':'ENVIRONMENT_BLOCKED' if source=='trivy' else 'BLOCKED_BY_TRIVY','runtimeResult':None,'runtimeResultPresent':False,'policyResult':None,'policyEvaluations':0,'blockerIsNotPolicyResult':True}
def shape():
 c={k:{} for k in ['v1SummaryIdentity','policyIdentity','canonicalSourceManifest','proxyBaseline','implementationHashes','historicalFailedCheckpointRefs']};c.update(checkpointSchemaVersion=2,epochId='runtime-checkpoint-v2-fixture',createdAt='fixture',gitRevision='fixture',pipelineState={'job':'petclinic-ci','latestBuild':270,'result':'SUCCESS'},runtimeCapabilities=[{}]*16,blockerReceipts=[],proxySemanticDigest='fixture',historicalContinuity='NOT_PROVEN',newEpochBaseline='CURRENT_STATE_ONLY',oldCheckpointStatus='FAILED',oldCheckpointReason='UNEXPLAINED_PROXY_DRIFT',acceptanceStatus='FAILED',release=0,rollout=0,newPolicyEvaluations=0,sameRun16Proven=False,completeRuntimeArtifactGenerated=False,acceptedWiredCount=14,runtimeVerdicts={k:'INCOMPLETE' for k in ['REAL_RUNTIME_FACT_CAPTURE','REAL_POLICY_OWNER','IMMUTABLE_ARTIFACT_RUNTIME','SUMMARY_V2_MIGRATION']});c['runtimeVerdicts']['FINAL_WIRED_CAPABILITY']='14/16';return c
class EpochTests(unittest.TestCase):
 def test_explicit_new_epoch_shape(self):self.assertTrue(validate_shape(shape()))
 def test_no_old_failure_upgrade(self):
  c=shape();c['oldCheckpointStatus']='VERIFIED'
  with self.assertRaisesRegex(ValueError,'OLD_FAILURE'):validate_shape(c)
 def test_no_continuity_claim(self):
  c=shape();c['historicalContinuity']='PROVEN'
  with self.assertRaisesRegex(ValueError,'CONTINUITY'):validate_shape(c)
 def test_missing_required_field(self):
  c=shape();del c['proxyBaseline']
  with self.assertRaisesRegex(ValueError,'MISSING'):validate_shape(c)
 def test_no_same_run_complete(self):
  c=shape();c['sameRun16Proven']=True
  with self.assertRaisesRegex(ValueError,'COMPLETE'):validate_shape(c)
 def test_no_release(self):
  c=shape();c['release']=1
  with self.assertRaisesRegex(ValueError,'MUTATION'):validate_shape(c)
 def test_no_capability_upgrade(self):
  c=shape();c['acceptedWiredCount']=16
  with self.assertRaisesRegex(ValueError,'COUNT'):validate_shape(c)
 def test_no_summary_upgrade(self):
  c=shape();c['runtimeVerdicts']['SUMMARY_V2_MIGRATION']='VERIFIED'
  with self.assertRaisesRegex(ValueError,'OVERALL'):validate_shape(c)
 def test_Trivy_blocker_is_not_Policy(self):self.assertTrue(validate_blocker(blocker()))
 def test_Dojo_blocker_is_not_Policy(self):self.assertTrue(validate_blocker(blocker('defectdojo')))
 def test_blocker_cannot_PASS(self):
  b=blocker();b['policyResult']={'decision':'PASS'}
  with self.assertRaisesRegex(ValueError,'NOT_POLICY'):validate_blocker(b)
 def test_blocker_cannot_SKIP(self):
  b=blocker();b['status']='SKIPPED'
  with self.assertRaisesRegex(ValueError,'SMUGGLING'):validate_blocker(b)
 def test_runtime_result_absent(self):
  b=blocker();b['runtimeResultPresent']=True
  with self.assertRaisesRegex(ValueError,'NOT_POLICY'):validate_blocker(b)
 def test_unknown_blocker_rejected(self):
  b=blocker();b['sourceId']='unknown'
  with self.assertRaisesRegex(ValueError,'SOURCE'):validate_blocker(b)
 def test_absolute_reference_rejected(self):
  with tempfile.TemporaryDirectory() as d:
   with self.assertRaisesRegex(ValueError,'UNSAFE'):safe_read(Path(d),'/etc/hosts')
 def test_traversal_rejected(self):
  with tempfile.TemporaryDirectory() as d:
   with self.assertRaisesRegex(ValueError,'UNSAFE'):safe_read(Path(d),'../file')
 def test_changed_manifest_fails(self):
  with tempfile.TemporaryDirectory() as d:
   p=Path(d);(p/'manifest.json').write_text('{}')
   with self.assertRaisesRegex(ValueError,'MANIFEST_DIGEST'):verify_epoch(p,'checkpoint.json','0'*64,'manifest.json','0'*64)
 def test_manifest_must_bind_checkpoint(self):
  from epoch_proxy import sha
  with tempfile.TemporaryDirectory() as d:
   p=Path(d);b=b'{"files":{}}';(p/'manifest.json').write_bytes(b)
   with self.assertRaisesRegex(ValueError,'BINDING'):verify_epoch(p,'checkpoint.json','0'*64,'manifest.json',sha(b))
 def test_referenced_bytes_tamper(self):
  from epoch_proxy import sha
  with tempfile.TemporaryDirectory() as d:
   p=Path(d);(p/'checkpoint.json').write_text('tampered');m=json.dumps({'files':{'checkpoint.json':'0'*64}}).encode();(p/'manifest.json').write_bytes(m)
   with self.assertRaisesRegex(ValueError,'REFERENCE_HASH'):verify_epoch(p,'checkpoint.json','0'*64,'manifest.json',sha(m))
if __name__=='__main__':unittest.main(verbosity=2)
