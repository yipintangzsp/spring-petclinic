# Synthetic copies only; this test helper is never wired to checkpoint acceptance.
import unittest,copy,json
from analysis_semantics import analyse_text,canonical_digest,exposure
class AnalysisTests(unittest.TestCase):
 def setUp(self):self.x={'inbounds':[{'listen':'127.0.0.1','port':10808,'protocol':'mixed','settings':{'auth':'noauth'}}],'routing':{'domainStrategy':'AsIs','rules':[{'type':'field','domain':['fixture.invalid'],'outboundTag':'proxy'}]},'outbounds':[{'tag':'proxy','protocol':'vless','settings':{'vnext':[{'address':'server.invalid','port':443,'users':[{'id':'SYNTHETIC_ID'}]}]},'streamSettings':{'security':'tls','tlsSettings':{'allowInsecure':False}}}],'stats':{},'timestamp':'UNPROVEN_VOLATILITY'}
 def changed(self,f):y=copy.deepcopy(self.x);f(y);self.assertNotEqual(canonical_digest(self.x),canonical_digest(y))
 def test_object_order_whitespace_analysis_only(self):self.assertEqual(analyse_text(json.dumps(self.x)),analyse_text(json.dumps(dict(reversed(list(self.x.items()))),indent=4)))
 def test_listener_change_detected(self):self.changed(lambda x:x['inbounds'][0].update(listen='::1'))
 def test_port_change_detected(self):self.changed(lambda x:x['inbounds'][0].update(port=10809))
 def test_lan_exposure_detected(self):self.changed(lambda x:x['inbounds'][0].update(listen='0.0.0.0'));self.assertFalse(exposure(self.x['inbounds']))
 def test_routing_change_detected(self):self.changed(lambda x:x['routing'].update(domainStrategy='IPIfNonMatch'))
 def test_outbound_identity_detected(self):self.changed(lambda x:x['outbounds'][0]['settings']['vnext'][0].update(address='other.invalid'))
 def test_security_flag_detected(self):self.changed(lambda x:x['outbounds'][0]['streamSettings']['tlsSettings'].update(allowInsecure=True))
 def test_auth_change_detected(self):self.changed(lambda x:x['inbounds'][0]['settings'].update(auth='password'))
 def test_array_order_preserved(self):self.changed(lambda x:x['routing']['rules'].append({'outboundTag':'direct'}))
 def test_unknown_timestamp_not_ignored(self):self.changed(lambda x:x.update(timestamp='OTHER'))
 def test_unknown_counter_not_ignored(self):self.changed(lambda x:x.update(counter=1))
 def test_duplicate_keys_fail(self):
  with self.assertRaises(ValueError):analyse_text('{"listen":"127.0.0.1","listen":"0.0.0.0"}')
if __name__=='__main__':unittest.main(verbosity=2)
