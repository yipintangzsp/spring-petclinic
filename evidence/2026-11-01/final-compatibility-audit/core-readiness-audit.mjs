// Read-only audit of existing behavior. No Policy implementation or fixture is modified.
import fs from 'node:fs';
import assert from 'node:assert/strict';
import {resolvePolicy,evaluate} from '../../../infra/security/policy/engine.mjs';
const rows=[];
function check(capability,fn){try{rows.push({capability,status:'VERIFIED',evidence:fn()});}catch(e){rows.push({capability,status:'FAILED',error:e.message});}}
const finding={component:'semgrep',status:'success',raw:{findings:[{check_id:'review-only',extra:{severity:'WARNING'}}]}};
check('baseline-v1',()=>{assert.equal(resolvePolicy().policyVersion,'baseline-v1');return 'Existing version document resolved';});
check('default standard',()=>{assert.equal(resolvePolicy({}).securityLevel,'standard');return 'Absent level resolves to standard';});
check('explicit low',()=>{assert.equal(resolvePolicy({securityLevel:'low'}).securityLevel,'low');assert.throws(()=>resolvePolicy({securityLevel:'typo'}),/POLICY_ERROR/);return 'Explicit low only; invalid level rejected';});
check('strict',()=>{const before=JSON.stringify(finding);assert.equal(evaluate(finding).decision,'WARN');assert.equal(evaluate(finding,{securityLevel:'strict'}).decision,'FAIL');assert.equal(JSON.stringify(finding),before);return 'Same immutable finding WARN -> FAIL';});
check('component override',()=>{const p=resolvePolicy({componentOverrides:{semgrep:{Medium:'FAIL'}}});assert.equal(p.effectivePolicy.semgrep.Medium,'FAIL');assert.equal(p.effectivePolicy.trivy.Medium,'WARN');return 'Target only';});
check('project override',()=>{const p=resolvePolicy({project:'a',componentOverrides:{semgrep:{Medium:'FAIL'}},projectOverride:{project:'a',components:{semgrep:{Medium:'WARN'}}}});assert.equal(p.effectivePolicy.semgrep.Medium,'WARN');assert.equal(p.effectivePolicy.trivy.Medium,'WARN');assert.throws(()=>resolvePolicy({project:'b',projectOverride:{project:'a',components:{}}}),/POLICY_ERROR/);return 'Project overrides component; mismatched identity rejected';});
check('policy version metadata',()=>{assert.equal(evaluate(finding).policyVersion,'baseline-v1');return 'Engine return payload only; no actual Summary integration';});
check('effective policy',()=>{assert.ok(evaluate(finding).effectivePolicy.semgrep);return 'Resolved component map present';});
check('override source',()=>{const p=resolvePolicy({project:'a',componentOverrides:{semgrep:{Medium:'FAIL'}},projectOverride:{project:'a',components:{semgrep:{Medium:'WARN'}}}});assert.deepEqual(p.appliedOverrides.map(x=>x.layer),['component','project']);return p.appliedOverrides;});
check('POLICY_ERROR on broken config',()=>{
 const errors=[];
 for(const cfg of [{policyVersion:'missing'},{profile:'missing'},{componentOverrides:[]},{componentOverrides:{semgrep:{High:'invalid'}}}])assert.throws(()=>resolvePolicy(cfg),/POLICY_ERROR/);
 // Fault injection in this disposable audit process only; original files remain untouched.
 const original=fs.readFileSync;
 for(const [name,substitute] of [['unreadable',()=>{throw Error('audit read error');}],['malformed',()=>'{'],['wrong schema',()=>JSON.stringify({schema:99,policyVersion:'baseline-v1'})]]){
  try{fs.readFileSync=function(file,...args){return String(file).endsWith('/versions/baseline-v1.json')?substitute():original.call(this,file,...args);};assert.throws(()=>resolvePolicy(),/POLICY_ERROR/);errors.push(name+': POLICY_ERROR');}
  finally{fs.readFileSync=original;}
 }
 return errors;
});
const snapshot=JSON.parse(fs.readFileSync('evidence/2026-11-01/policy-engine/gate-decision-before.json'));
const classifierRecheck=[];
for(const c of snapshot.cases.filter(c=>c.scope==='frozen')){
 const raw=c.component==='semgrep'?c.input:c.component==='trivy'?{findings:[c.input.finding],review:c.input.review,image:c.input.image}:{report:c.input.raw,context:c.input.context,approved:c.input.approved};
 const before=JSON.stringify(raw),decision=evaluate({component:c.component,status:'success',raw}).decision;
 classifierRecheck.push({component:c.component,oldDecision:c.decision,standardDecision:decision,rawPreserved:before===JSON.stringify(raw)});
}
const sonar=JSON.parse(fs.readFileSync('evidence/2026-11-01/sonar-policy/analysis-bound-facts.json'));
const sonarBefore=JSON.stringify(sonar),positive=evaluate({component:'sonarqube',status:'success',raw:sonar}).decision;
const negative=structuredClone(sonar);negative.gate.projectStatus.status='ERROR';const negativeBefore=JSON.stringify(negative);
const sonarLogic={positive:{classification:'HISTORICAL_ARCHIVE',decision:positive,rawPreserved:sonarBefore===JSON.stringify(sonar)},negative:{classification:'SYNTHETIC_UNIT_ONLY',decision:evaluate({component:'sonarqube',status:'success',raw:negative}).decision,rawPreserved:negativeBefore===JSON.stringify(negative),realNegativeStatus:'DEFERRED_REAL_NEGATIVE_EVIDENCE'}};
console.log(JSON.stringify({scope:'Read-only audit observations; not new cumulative Policy test cases',checks:rows,ready:rows.every(r=>r.status==='VERIFIED'),classifierRecheck,sonarLogic},null,2));
process.exitCode=rows.every(r=>r.status==='VERIFIED')&&classifierRecheck.every(r=>r.oldDecision===r.standardDecision&&r.rawPreserved)&&positive==='PASS'&&sonarLogic.negative.decision==='FAIL'?0:1;
