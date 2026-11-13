"""Read-only negative integrity tests against this new epoch's real artifacts.
All mutations exist solely in mocked read buffers; never modify evidence/live files.
"""
import unittest,json,copy
from pathlib import Path
from unittest.mock import patch
from epoch_engine import verify_epoch,safe_read
from epoch_proxy import sha
O=Path(__file__).resolve().parent;R=O.parents[2]
class IntegrityTests(unittest.TestCase):
 def setUp(self):
  self.a=json.loads((O/'checkpoint-digest.json').read_text());self.c=json.loads((R/self.a['checkpointPath']).read_text());self.m=json.loads((R/self.a['integrityManifestPath']).read_text())
 def run_verify(self,a=None):
  a=a or self.a;return verify_epoch(R,a['checkpointPath'],a['checkpointSha256'],a['integrityManifestPath'],a['integrityManifestSha256'])
 def tamper(self,path):
  def fake(root,p):return safe_read(root,p)+b' ' if p==path else safe_read(root,p)
  with patch('epoch_engine.safe_read',side_effect=fake):
   with self.assertRaisesRegex(ValueError,'REFERENCE_HASH'):self.run_verify()
 def forge_checkpoint(self,change,error):
  c=copy.deepcopy(self.c);change(c);cb=json.dumps(c).encode();m=copy.deepcopy(self.m);m['files'][self.a['checkpointPath']]=sha(cb);mb=json.dumps(m).encode();a={**self.a,'checkpointSha256':sha(cb),'integrityManifestSha256':sha(mb)}
  def fake(root,p):
   if p==a['checkpointPath']:return cb
   if p==a['integrityManifestPath']:return mb
   return safe_read(root,p)
  with patch('epoch_engine.safe_read',side_effect=fake):
   with self.assertRaisesRegex(ValueError,error):self.run_verify(a)
 def test_real_checkpoint_all_refs_validate(self):self.assertEqual(self.run_verify()['acceptanceStatus'],self.c['acceptanceStatus'])
 def test_checkpoint_byte_tamper(self):self.tamper(self.a['checkpointPath'])
 def test_baseline_tamper(self):self.tamper(self.c['proxyBaseline']['path'])
 def test_contract_tamper(self):self.tamper(self.c['proxyContract']['path'])
 def test_blocker_receipt_tamper(self):self.tamper(self.c['blockerReceipts'][0]['receipt']['path'])
 def test_implementation_tamper(self):self.tamper(next(iter(self.c['implementationHashes'])))
 def test_bad_manifest_anchor(self):
  with self.assertRaisesRegex(ValueError,'MANIFEST_DIGEST'):self.run_verify({**self.a,'integrityManifestSha256':'0'*64})
 def test_recomputed_hash_cannot_change_acceptance(self):self.forge_checkpoint(lambda c:c.update(acceptanceStatus='FAILED' if c['acceptanceStatus']=='VERIFIED' else 'VERIFIED'),'FALSE_ACCEPTANCE')
 def test_recomputed_hash_cannot_rebind_receipt(self):self.forge_checkpoint(lambda c:c['runtimeCapabilities'][0].update(resultDigest='0'*64),'NO_RECEIPT_REBIND')
 def test_recomputed_hash_cannot_claim_history(self):self.forge_checkpoint(lambda c:c.update(historicalContinuity='PROVEN'),'HISTORICAL_CONTINUITY')
 def test_recomputed_hash_cannot_claim_complete(self):self.forge_checkpoint(lambda c:c.update(sameRun16Proven=True),'NO_COMPLETE')
if __name__=='__main__':unittest.main(verbosity=2)
