import test from 'node:test';
import assert from 'node:assert/strict';
import {validatePause,validateRestore,otherBuilds} from './sonar-resource-slot.mjs';
const sts=()=>({metadata:{uid:'expected',annotations:{}},spec:{replicas:1},status:{readyReplicas:1}});
const lease=()=>({metadata:{uid:'lease1',annotations:{}},spec:{holderIdentity:'ci1'}});
test('idle scanner slot borrows the current CI lease without nested acquisition',()=>assert.equal(validatePause(sts(),lease(),'expected','ci1').leaseUid,'lease1'));
test('foreign lease, replaced UID, foreign resource owner and unready scanner are preserved',()=>{
 assert.throws(()=>validatePause(sts(),lease(),'expected','foreign'));
 assert.throws(()=>validatePause(sts(),lease(),'replacement','ci1'));
 let x=sts();x.metadata.annotations['petclinic.devops.local/analysis-holder']='someone-else';assert.throws(()=>validatePause(x,lease(),'expected','ci1'));
 x=sts();x.status.readyReplicas=0;assert.throws(()=>validatePause(x,lease(),'expected','ci1'));
});
test('restoration requires exact UID and owner; only proven restored original replica is idempotent',()=>{
 let x=sts();const state={uid:'expected',holder:'ci1',replicas:1,restored:false};assert.throws(()=>validateRestore(x,state));
 x.metadata.annotations['petclinic.devops.local/analysis-holder']='ci1';validateRestore(x,state);
 state.uid='different';assert.throws(()=>validateRestore(x,state));state.uid='expected';state.restored=true;delete x.metadata.annotations['petclinic.devops.local/analysis-holder'];validateRestore(x,state);
 x.spec.replicas=0;assert.throws(()=>validateRestore(x,state));
});

test('current CI never waits for itself; other active builds prevent pause',()=>{
 const jobs=[{name:'petclinic-ci',lastBuild:{number:210,building:true}}];
 assert.equal(otherBuilds(jobs,'petclinic-ci','210'),false);
 assert.equal(otherBuilds(jobs,'petclinic-ci','211'),true);
 assert.equal(otherBuilds([...jobs,{name:'other',lastBuild:{number:1,building:true}}],'petclinic-ci','210'),true);
});
