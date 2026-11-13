import unittest,json,copy,datetime,sqlite3,tempfile
from pathlib import Path
from epoch_proxy import digest,sha,parse,validate_samples,database_snapshot
C=json.loads(Path(__file__).with_name('proxy-contract.json').read_text())
F={'inbounds':[{'listen':'127.0.0.1','port':10808,'protocol':'mixed','settings':{'auth':'noauth'}}],'routing':{'domainStrategy':'AsIs','rules':[]},'outbounds':[{'protocol':'fixture','settings':{'address':'example.invalid'},'streamSettings':{'allowInsecure':False}}]}
def samples():
 out=[]
 for i in range(5):
  public={'lanExposure':False};protected={'runtimeSemanticDigest':digest(F),'guiSemanticDigest':digest({'selection':'fixture'}),'databaseSemanticDigest':digest({'rows':'fixture'}),'publicSemanticsDigest':digest(public)};processes=[{'role':'fixture','pid':1}]
  out.append({'sample':'T'+str(i),'startedAt':(datetime.datetime(2026,11,3,tzinfo=datetime.timezone.utc)+datetime.timedelta(seconds=i*30)).isoformat(),'captureSeconds':.1,'status':'CAPTURED','files':{k:{'rawSha256':sha(json.dumps(F).encode()),'mtimeNs':i,'inode':i} for k in ['runtime','gui','database']},'protected':protected,'proxySemanticDigest':digest(protected),'publicSemantics':public,'immutableProxyFiles':{p:'a'*64 for p in C['A']['files']},'processState':{'processes':processes,'identityDigest':digest(processes),'allXrayListeners':[{'loopback':True}]}})
 return out
class ProxyTests(unittest.TestCase):
 def test_controlled_stable_positive(self):self.assertEqual(validate_samples(samples(),C)['status'],'VERIFIED')
 def changed(self,mutate):
  ss=samples();f=copy.deepcopy(F);mutate(f);ss[1]['protected']['runtimeSemanticDigest']=digest(f);ss[1]['proxySemanticDigest']=digest(ss[1]['protected']);ss[1]['files']['runtime']['rawSha256']=sha(json.dumps(f).encode());self.assertEqual(validate_samples(ss,C)['status'],'FAILED')
 def test_listener_address(self):self.changed(lambda f:f['inbounds'][0].update(listen='127.0.0.2'))
 def test_listener_port(self):self.changed(lambda f:f['inbounds'][0].update(port=10809))
 def test_lan_exposure(self):self.changed(lambda f:f['inbounds'][0].update(listen='0.0.0.0'))
 def test_routing_mode(self):self.changed(lambda f:f['routing'].update(domainStrategy='IPIfNonMatch'))
 def test_outbound_identity(self):self.changed(lambda f:f['outbounds'][0]['settings'].update(address='other.example.invalid'))
 def test_security_flag(self):self.changed(lambda f:f['outbounds'][0]['streamSettings'].update(allowInsecure=True))
 def test_auth_change(self):self.changed(lambda f:f['inbounds'][0]['settings'].update(auth='password'))
 def test_unknown_field_not_ignored(self):self.changed(lambda f:f.update(unknownSecurityToggle=True))
 def test_array_order_preserved(self):self.assertNotEqual(digest([1,2]),digest([2,1]))
 def test_json_key_order_and_whitespace_only(self):self.assertEqual(digest(parse('{"a":1,"b":2}')),digest(parse('{ "b":2, "a":1 }')))
 def test_duplicate_keys_fail(self):
  with self.assertRaisesRegex(ValueError,'DUPLICATE'):parse('{"a":1,"a":2}')
 def test_nonfinite_fail(self):
  with self.assertRaisesRegex(ValueError,'NONFINITE'):parse('{"a":NaN}')
 def test_generated_raw_formatting_not_exempt(self):
  s=samples();s[2]['files']['runtime']['rawSha256']='b'*64;self.assertIn('T2:GENERATED_RAW_DRIFT_NOT_EXEMPT',validate_samples(s,C)['failures'])
 def test_gui_raw_diff_same_complete_semantics_allowed(self):
  s=samples();s[2]['files']['gui']['rawSha256']='b'*64;r=validate_samples(s,C);self.assertEqual(r['status'],'VERIFIED');self.assertTrue(r['benignDifferences'])
 def test_gui_semantic_change_fails(self):
  s=samples();s[2]['protected']['guiSemanticDigest']='b'*64;self.assertEqual(validate_samples(s,C)['status'],'FAILED')
 def test_db_semantic_change_fails(self):
  s=samples();s[2]['protected']['databaseSemanticDigest']='b'*64;self.assertEqual(validate_samples(s,C)['status'],'FAILED')
 def test_metadata_only_replacement_allowed(self):self.assertEqual(validate_samples(samples(),C)['status'],'VERIFIED')
 def test_process_restart_fails(self):
  s=samples();s[3]['processState']['processes'][0]['pid']=2;s[3]['processState']['identityDigest']=digest(s[3]['processState']['processes']);self.assertEqual(validate_samples(s,C)['status'],'FAILED')
 def test_failed_capture_fails_closed(self):
  s=samples();s[3]={'sample':'T3','status':'CAPTURE_ERROR'};self.assertEqual(validate_samples(s,C)['status'],'FAILED')
 def test_missing_sample_fails(self):self.assertEqual(validate_samples(samples()[:-1],C)['status'],'FAILED')
 def test_short_window_fails(self):
  s=samples();s[-1]['startedAt']=s[0]['startedAt'];self.assertEqual(validate_samples(s,C)['status'],'FAILED')
 def test_forged_public_fact_fails(self):
  s=samples();s[1]['publicSemantics']['forged']=True;self.assertEqual(validate_samples(s,C)['status'],'FAILED')
 def test_binary_hash_drift_fails(self):
  s=samples();s[1]['immutableProxyFiles'][C['A']['files'][0]]='b'*64;self.assertEqual(validate_samples(s,C)['status'],'FAILED')
 def test_real_disposable_db_all_tables_values_preserved(self):
  with tempfile.TemporaryDirectory() as d:
   p=Path(d)/'test.db';c=sqlite3.connect(p);c.executescript('CREATE TABLE Profile(id TEXT,value TEXT);CREATE TABLE Stats(n INTEGER);INSERT INTO Profile VALUES("fixture","synthetic");INSERT INTO Stats VALUES(1);');c.close();b=p.read_bytes();a=database_snapshot(p);self.assertEqual(b,p.read_bytes());c=sqlite3.connect(p);c.execute('UPDATE Stats SET n=2');c.commit();c.close();self.assertNotEqual(a['semanticDigest'],database_snapshot(p)['semanticDigest']);self.assertEqual(len(a['tables']),2)
if __name__=='__main__':unittest.main(verbosity=2)
