import {test} from 'node:test';
import assert from 'node:assert/strict';
import {highAlerts,requireSignedRelease} from './gate-contract.mjs';
test('DAST fails closed on absent report or unknown severity',()=>{
 assert.throws(()=>highAlerts({}));assert.throws(()=>highAlerts({site:[]}));assert.throws(()=>highAlerts({site:[{alerts:[{riskcode:'unknown'}]}]}));
});
test('DAST blocks High while retaining lower findings',()=>{
 const alerts=[0,1,2,3].map(riskcode=>({riskcode:String(riskcode)}));assert.equal(highAlerts({site:[{alerts}]}).length,1);
});
test('promotion rejects unsigned, wrong-image or wrong-source evidence',()=>{
 const source='a'.repeat(40),image='sha256:'+'b'.repeat(64);
 const proof={signed:true,source,imageDigest:image};
 const signing={status:'success',mode:'release',source,artifactSignatureVerified:true,temporaryPrivateFilesRemoved:true,images:[{verified:true,image:'core.harbor.domain/petclinic/petclinic@'+image}]};
 const input={signing,proof,image,source};assert.doesNotThrow(()=>requireSignedRelease(input));
 for(const change of [{signing:{...signing,status:'failed'}},{source:'c'.repeat(40)},{image:'sha256:'+'d'.repeat(64)},{proof:{...proof,signed:false}},{signing:{...signing,artifactSignatureVerified:false}}])assert.throws(()=>requireSignedRelease({...input,...change}));
});
