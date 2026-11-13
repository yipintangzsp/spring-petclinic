import unittest
from history_tools import OLD,NEW,classify,parse,differences,ordered,sha
class EvidenceSearchTests(unittest.TestCase):
 def test_old_sealed_digest_only(self):self.assertEqual(classify(OLD,None),'TRUSTED_PRE_DRIFT')
 def test_current_digest_not_old_even_with_old_mtime(self):self.assertEqual(classify(NEW,'2020-01-01T00:00:00Z',True),'POST_DRIFT')
 def test_missing_provenance_untrusted(self):self.assertEqual(classify('0'*64,'2020-01-01T00:00:00Z'),'UNTRUSTED')
 def test_old_mtime_never_authoritative(self):self.assertEqual(classify('0'*64,'2020-01-01T00:00:00Z',True),'LIKELY_PRE_DRIFT')
 def test_future_mtime_untrusted(self):self.assertEqual(classify('0'*64,'2030-01-01T00:00:00Z',True),'UNTRUSTED')
 def test_missing_time_untrusted(self):self.assertEqual(classify('0'*64,None,True),'UNTRUSTED')
class ConfigDiffParserTests(unittest.TestCase):
 def test_duplicate_keys_rejected(self):
  with self.assertRaisesRegex(ValueError,'DUPLICATE_KEY'):parse('{"port":1,"port":2}')
 def test_nonfinite_rejected(self):
  with self.assertRaisesRegex(ValueError,'NONFINITE'):parse('{"port":NaN}')
 def test_object_order_does_not_fabricate_field_diff(self):self.assertEqual(differences(parse('{"a":1,"b":2}'),parse('{"b":2,"a":1}')),[])
 def test_array_order_change_not_ignored(self):self.assertTrue(differences([1,2],[2,1]))
 def test_type_change_is_detected(self):self.assertEqual(differences({'port':10808},{'port':'10808'})[0]['kind'],'TYPE_CHANGE')
 def test_raw_diff_preserved_despite_parse_equivalence(self):
  a=b'{"a":1}';b=b'{ "a": 1 }\n';self.assertNotEqual(sha(a),sha(b));self.assertEqual(differences(parse(a),parse(b)),[])
class TimelineUnitTests(unittest.TestCase):
 def test_ordered(self):self.assertTrue(ordered([{'timestamp':'2026-11-03T09:17:41Z'},{'timestamp':'2026-11-03T09:21:44Z'}]))
 def test_out_of_order(self):self.assertFalse(ordered([{'timestamp':'2026-11-03T09:21:44Z'},{'timestamp':'2026-11-03T09:17:41Z'}]))
 def test_missing_time_fails(self):
  for value in [None,'invalid','2026-11-03T09:20:28']:self.assertFalse(ordered([{'timestamp':value}]))
 def test_same_instant_offsets(self):self.assertTrue(ordered([{'timestamp':'2026-11-03T09:20:28Z'},{'timestamp':'2026-11-03T17:20:28+08:00'}]))
if __name__=='__main__':unittest.main(verbosity=2)
