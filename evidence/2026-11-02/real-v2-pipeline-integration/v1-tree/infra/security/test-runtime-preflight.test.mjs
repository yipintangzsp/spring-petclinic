import {test} from 'node:test';
import assert from 'node:assert/strict';
import {expectedId,validateTestRuntime} from './test-runtime-preflight.mjs';
test('test runtime refuses changed bytes or foreign architecture',()=>{
 const valid={Id:expectedId,Architecture:'arm64',Os:'linux'};
 assert.doesNotThrow(()=>validateTestRuntime(valid));
 assert.throws(()=>validateTestRuntime({...valid,Id:'sha256:'+'0'.repeat(64)}));
 assert.throws(()=>validateTestRuntime({...valid,Architecture:'amd64'}));
});
