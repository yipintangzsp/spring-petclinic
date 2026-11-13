import test from 'node:test';
import assert from 'node:assert/strict';
import {checkCosignVerification as check} from './cosign-verification.mjs';
test('negative fixtures accept actual signature failures independent of exit code',()=>{assert.equal(check('unsigned', 255, 'Error: no signatures found'),false);assert.equal(check('wrong-key',1,'signature verification failed'),false);assert.equal(check('signed',0,''),true);});
test('registry and unexpected successes fail closed',()=>{assert.throws(()=>check('unsigned',255,'UNAUTHORIZED'));assert.throws(()=>check('wrong-key',1,'connection refused'));assert.throws(()=>check('unsigned',0,''));assert.throws(()=>check('signed',255,'no signatures found'));});
