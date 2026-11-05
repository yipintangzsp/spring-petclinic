from pathlib import Path
import sys,importlib.util,tempfile,json,subprocess,io,tarfile,shutil,hashlib
sys.dont_write_bytecode=True
O=Path(__file__).resolve().parent;R=O.parents[2];base=json.loads((O/'protected-before.json').read_text());spec=importlib.util.spec_from_file_location('b',R/'infra/security/testing/evidence-boundary.py');b=importlib.util.module_from_spec(spec);spec.loader.exec_module(b);assert b.snapshot(base['protected'])==base['protected']
archive=subprocess.check_output(['git','archive',base['head'],'infra'],cwd=R);old=subprocess.check_output(['git','show',base['head']+':infra/security/manager-v2/router.mjs'],cwd=R)
js=r'''
import fs from 'node:fs';import path from 'node:path';import assert from 'node:assert/strict';import {routeResults as before,CONSUMERS as oldConsumers} from './infra/security/manager-v2/old-router.mjs';import {routeResults as after,CONSUMERS as newConsumers} from './infra/security/manager-v2/router.mjs';import {digest} from './infra/security/summary-v2/codec.mjs';import {DEFINITION} from './infra/security/manager-v2/consumers/defectdojo.mjs';
assert.deepEqual(newConsumers,oldConsumers);const records=[];
for(const name of ['A-three-valid','H-gitleaks-fail','G-semgrep-fail','I-cosign-timeout','Q-cross-project-identity-rejected']){
 const dir=path.resolve('inputs',name),summary=JSON.parse(fs.readFileSync(path.join(dir,'candidate-summary.json'))),seal=JSON.parse(fs.readFileSync(path.join(dir,'candidate-seal.json'))),a=path.resolve('out',name,'before'),b=path.resolve('out',name,'after');fs.mkdirSync(a,{recursive:true,mode:0o700});fs.mkdirSync(b,{recursive:true,mode:0o700});
 const common={run:{summary},artifactDirectory:dir,expectedSealDigest:digest(seal)};
 const x=before({...common,output:a}),y=after({...common,output:b});assert.deepEqual(y,x);
 const xr=before({...common,output:a}),yr=after({...common,output:b});assert.deepEqual(yr,xr);
 const xf=before({...common,definitions:[{...oldConsumers[2],enabled:true}]}),yf=after({...common,definitions:[{...newConsumers[2],enabled:true}]});assert.deepEqual(yf,xf);
 const xd=before({...common,output:a,definitions:[DEFINITION]}),yd=after({...common,output:b,definitions:[DEFINITION]});assert.deepEqual(yd,xd);
 records.push({offlineDojoIdentical:true,name,sourceClass:'REPLAY_OF_PRIOR_REAL_CANDIDATE',firstDeliveryIdentical:true,retryFailureIdentical:true,oldFuturePlaceholderIdentical:true,resultDigests:x.receipts[0].resultDigests,policyOrScannerReexecution:false});
}
fs.writeFileSync('comparison.json',JSON.stringify({classification:'LEGACY_ROUTER_DIFFERENTIAL_ON_SAME_REPLAY_INPUTS',defaultConsumersIdentical:true,cases:records,newDojoConsumerOptInOnly:true,httpRequests:0},null,2));
'''
with tempfile.TemporaryDirectory(prefix='security-cosign-boundary-')as d:
 tree=Path(d).resolve()
 with tarfile.open(fileobj=io.BytesIO(archive))as t:t.extractall(tree,filter='data')
 shutil.copyfile(R/'infra/security/manager-v2/router.mjs',tree/'infra/security/manager-v2/router.mjs');shutil.copytree(R/'infra/security/manager-v2/consumers',tree/'infra/security/manager-v2/consumers',dirs_exist_ok=True);(tree/'infra/security/manager-v2/old-router.mjs').write_bytes(old)
 for name in ['A-three-valid','H-gitleaks-fail','G-semgrep-fail','I-cosign-timeout','Q-cross-project-identity-rejected']:shutil.copytree(R/'evidence/2026-11-05/security-manager-v2-cosign-real/real-linux/outputs'/('attempt2-'+name),tree/'inputs'/name)
 p=b.guarded(tree,[shutil.which('node'),'--input-type=module','-e',js]);assert p.returncode==0,p.stderr;result=json.loads((tree/'comparison.json').read_text());result['oldSourceSha256']=hashlib.sha256(old).hexdigest()
assert b.snapshot(base['protected'])==base['protected'];result['temporaryTreeRemoved']=not Path(d).exists();result['protectedContentAndMetadataUnchanged']=True
with(O/'router-compatibility.json').open('x')as f:json.dump(result,f,indent=2);f.write('\n')
print(json.dumps({'cases':len(result['cases']),'comparisons':len(result['cases'])*4,'status':'IDENTICAL','temporaryTreeRemoved':result['temporaryTreeRemoved']}))
