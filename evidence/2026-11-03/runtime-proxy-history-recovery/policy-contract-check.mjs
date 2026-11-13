import assert from 'node:assert/strict';import fs from 'node:fs';import os from 'node:os';import path from 'node:path';
import {resolvePolicy,evaluate} from '../../../infra/security/policy/engine.mjs';
const checks=[];function check(capability,fn){fn();checks.push({capability,status:'VERIFIED'});}
const facts={component:'semgrep',status:'success',raw:{findings:[{check_id:'review-only',extra:{severity:'WARNING'}}]}};
const override={project:'a',componentOverrides:{semgrep:{Medium:'FAIL'}},projectOverride:{project:'a',components:{semgrep:{Medium:'WARN'}}}};
check('baseline-v1',()=>assert.equal(resolvePolicy().policyVersion,'baseline-v1'));
check('default standard',()=>assert.equal(resolvePolicy().securityLevel,'standard'));
check('explicit low',()=>{assert.equal(resolvePolicy({securityLevel:'low'}).securityLevel,'low');assert.throws(()=>resolvePolicy({securityLevel:'typo'}),/POLICY_ERROR/);});
check('strict',()=>{const before=JSON.stringify(facts);assert.equal(evaluate(facts).decision,'WARN');assert.equal(evaluate(facts,{securityLevel:'strict'}).decision,'FAIL');assert.equal(JSON.stringify(facts),before);});
check('component override',()=>{const base=resolvePolicy(),p=resolvePolicy({componentOverrides:override.componentOverrides});assert.equal(p.effectivePolicy.semgrep.Medium,'FAIL');assert.deepEqual(p.effectivePolicy.trivy,base.effectivePolicy.trivy);});
check('project override',()=>{assert.equal(resolvePolicy(override).effectivePolicy.semgrep.Medium,'WARN');assert.throws(()=>resolvePolicy({...override,project:'b'}),/POLICY_ERROR/);});
check('policy version metadata',()=>{const r=evaluate(facts);for(const k of ['policyVersion','securityLevel','profile'])assert.ok(Object.hasOwn(r,k));});
check('effective policy',()=>assert.equal(typeof evaluate(facts).effectivePolicy.semgrep,'object'));
check('override source',()=>assert.deepEqual(resolvePolicy(override).appliedOverrides.map(x=>x.layer),['component','project']));
check('POLICY_ERROR on broken config',()=>{for(const c of [{profile:'missing'},{policyVersion:'missing'},{componentOverrides:[]},{componentOverrides:{typo:{High:'PASS'}}},{securityLevel:''}])assert.throws(()=>resolvePolicy(c),/POLICY_ERROR/);});
fs.writeFileSync(new URL('./policy-contract.json',import.meta.url),JSON.stringify({scope:'Read-only repeated contract assertions, not additions to authoritative compatibility count',checks,ready:checks.length===10},null,2)+'\n');console.log(JSON.stringify({checks:checks.length,ready:true}));
