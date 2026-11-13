import test from 'node:test';
import assert from 'node:assert/strict';
import {syntheticCredential} from './synthetic-credential.mjs';
test('synthetic scanner fixture always matches pinned rule length and entropy',()=>{
 const seen=new Set();
 for(let i=0;i<1000;i++){
  const value=syntheticCredential();const suffix=value.slice(4);
  assert.match(value,new RegExp(['ghp','[0-9a-zA-Z]{36}$'].join('_')));
  assert.equal(new Set(suffix).size,36);
  const counts=new Map();for(const c of value)counts.set(c,(counts.get(c)||0)+1);
  const entropy=[...counts.values()].reduce((s,n)=>s-(n/value.length)*Math.log2(n/value.length),0);
  assert.ok(entropy>4.5);assert.ok(!seen.has(value));seen.add(value);
 }
});
