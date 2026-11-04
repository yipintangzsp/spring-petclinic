import test from 'node:test';import assert from 'node:assert/strict';import fs from 'node:fs';
import {resolvePolicy,evaluate} from './engine.mjs';
const facts={component:'semgrep',status:'success',raw:{findings:[{check_id:'review-only',extra:{severity:'WARNING'}}]}};
test('default standard; explicit low; invalid values never fall back',()=>{
 assert.equal(resolvePolicy().securityLevel,'standard');assert.equal(resolvePolicy({securityLevel:'low'}).securityLevel,'low');
 for(const c of [{securityLevel:''},{securityLevel:'typo'},{profile:'typo'},{policyVersion:'missing'},{componentOverrides:[]},{componentOverrides:{typo:{High:'WARN'}}},{componentOverrides:{semgrep:{High:'typo'}}},{project:'a',projectOverride:{project:'b',components:{}}}])assert.throws(()=>resolvePolicy(c),/POLICY_ERROR/);
});
test('standard matches pre-extraction frozen Semgrep Trivy and ZAP decisions',()=>{
 const baseline=JSON.parse(fs.readFileSync('evidence/2026-11-01/policy-engine/gate-decision-before.json'));
 for(const c of baseline.cases.filter(c=>c.scope==='frozen')){
  const raw=c.component==='semgrep'?c.input:c.component==='trivy'?{findings:[c.input.finding],review:c.input.review,image:c.input.image}:{report:c.input.raw,context:c.input.context,approved:c.input.approved};
  assert.equal(evaluate({component:c.component,status:'success',raw}).decision,c.decision,JSON.stringify(c));
 }
});
test('strict strengthens same raw finding; input immutable',()=>{
 const before=JSON.stringify(facts);assert.equal(evaluate(facts).decision,'WARN');assert.equal(evaluate(facts,{securityLevel:'strict'}).decision,'FAIL');assert.equal(JSON.stringify(facts),before);
});
test('component/project overrides local, auditable and mandatory floor preserved',()=>{
 const c={project:'a',componentOverrides:{semgrep:{Medium:'FAIL'}},projectOverride:{project:'a',components:{semgrep:{Medium:'WARN'}}}};
 const p=resolvePolicy(c);assert.equal(p.effectivePolicy.semgrep.Medium,'WARN');assert.equal(p.effectivePolicy.trivy.Medium,'WARN');assert.equal(p.appliedOverrides.length,2);
 assert.equal(evaluate(facts,{componentOverrides:{semgrep:{Medium:'FAIL'}}}).decision,'FAIL');assert.equal(evaluate(facts,c).decision,'WARN');assert.equal(evaluate(facts,{project:'b'}).decision,'WARN');
 const blocked={...facts,raw:{findings:[{check_id:'java-http-runtime-exec',extra:{severity:'ERROR'}}]}};
 assert.equal(evaluate(blocked,{componentOverrides:{semgrep:{High:'PASS'}}}).decision,'FAIL');
});
test('summary payload carries policy provenance and operational failures are not findings',()=>{
 const r=evaluate(facts);for(const k of ['policyVersion','securityLevel','profile','effectivePolicy','appliedOverrides'])assert.ok(Object.hasOwn(r,k));
 assert.equal(evaluate({...facts,status:'error'},{mode:'audit'}).decision,'FAIL');assert.equal(evaluate({...facts,status:'not_configured'}).decision,null);
});
