from pathlib import Path
import sys,importlib.util,json,tempfile,ssl,http.client
sys.path.insert(0,str(Path('infra/security/testing').resolve()))
import isolated_sops_executor as g
spec=importlib.util.spec_from_file_location('legacy',Path('infra/security/testing/test_isolated_sops_executor.py'));m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
p=g.profile_from_document(m.guard.profile_document(m.LEGACY_PROFILE));a=g.Audit();v=g.validate(str(p.binding.path),{'KUBECONFIG':str(p.binding.path)},profile=p)
with tempfile.TemporaryDirectory(dir=p.temp_parent) as d:
 root=Path(d);g.verify_live(v,root,a,p)
 g.write_private(root/'cert',v.cert);g.write_private(root/'key',v.key)
 ctx=ssl.create_default_context(cadata=v.ca);ctx.load_cert_chain(root/'cert',root/'key')
 c=http.client.HTTPSConnection('127.0.0.1',59645,context=ctx,timeout=10);c.request('GET','/api/v1/nodes');resp=c.getresponse();assert resp.status==200
 nodes=json.loads(resp.read());c.close()
 safe=[{'name':x['metadata']['name'],'uid':x['metadata']['uid'],'arch':x['status']['nodeInfo']['architecture'],'Ready':next(z['status'] for z in x['status']['conditions'] if z['type']=='Ready')} for x in nodes['items']]
 assert len(safe)==1 and safe[0]['arch']=='arm64' and safe[0]['Ready']=='True'
 out={'guardProfile':g.profile_document(p),'identityApiRequests':a.api_attempts,'additionalReadOnlyNodeRequests':1,'nodes':safe,'productionApiRequests':0}
 Path('evidence/2026-11-02/sops-authoritative-baseline-02/cluster-preflight.json').write_text(json.dumps(out,indent=2))
 print(json.dumps({'clusterIdentity':'MATCHED','nodes':safe,'productionApiRequests':0}))
