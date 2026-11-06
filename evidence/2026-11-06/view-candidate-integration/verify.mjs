// Focused HTTP acceptance only. No scan requests, Policy evaluations or remote writes.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import {createHash} from 'node:crypto';
const base='http://security.devops.local:17862';
const get=p=>fetch(base+p,{signal:AbortSignal.timeout(5000)});
const response=await get('/');assert.equal(response.status,200);const html=await response.text();
assert.match(html,/id="candidate-overview"/);assert.match(html,/id="registry-rows"/);assert.match(html,/CI_CD_SAME_RUN_BEGIN/);
const data=await (await get('/api/overview')).json();
assert.equal(data.registry.entries.length,13);assert.equal(data.baseline.PRODUCTION_SECURITY_MANAGER,'NOT_ACTIVE');assert.equal(data.baseline.FINAL_WIRED_CAPABILITY,'14/16');assert.equal(data.baseline.ORIGINAL_EVIDENCE_INTEGRITY,'FAILED');
assert.equal(data.semgrepAdmission.state,'BLOCKED');assert.equal(data.semgrepAdmission.newExecution,false);assert.ok(data.semgrepAdmission.historicalWorkspaces.every(x=>x.exists===false));
const selected=data.runs.find(r=>r.runId==='attempt2-A-three-valid');assert.equal(selected.availability,'AVAILABLE');
assert.equal(selected.configuration.plugins.semgrep.enabled,true);assert.equal(selected.configuration.securityLevel,'standard');
for(const r of data.runs){assert.equal(r.availability,'AVAILABLE');assert.ok(r.configuration.source.sha256);assert.ok(r.artifact.seal.sha256);for(const p of r.plugins)assert.equal(p.availability,'AVAILABLE');}
for(const [id,decision] of [['attempt2-A-three-valid','PASS'],['attempt2-G-semgrep-fail','FAIL']]){
 const p=data.runs.find(r=>r.runId===id).plugins.find(p=>p.pluginId==='semgrep');assert.equal(p.evidenceClass,'REAL');assert.equal(p.displayMode,'REPLAY');assert.equal(p.policyDecision,decision);assert.equal(p.evaluationCount,1);assert.ok(p.completedAt);assert.ok(p.policy.effectivePolicy);
}
const disabled=data.runs.find(r=>r.runId==='attempt2-E-all-disabled');assert.ok(Object.values(disabled.configuration.plugins).every(p=>p.enabled===false));assert.ok(disabled.plugins.every(p=>p.policyDecision===null&&p.executionStatus==='DISABLED'));
for(const c of data.consumers){assert.equal(c.evidenceClass,'MOCK');assert.equal(c.realRemoteDelivery,'NOT_TESTED');assert.equal(c.productionDeliveryCount,0);}
assert.equal(data.grafana.panelCount,8);assert.equal(data.grafana.realQuery,'NOT_TESTED');assert.equal(data.grafana.productionActivation,'NOT_ACTIVE');
const dashboard=await get('/candidate-dashboard.json');assert.equal(dashboard.status,200);const json=await dashboard.json();assert.equal(json.uid,data.grafana.uid);assert.equal(json.panels.length,8);
assert.equal(data.ciCd.build,6);assert.equal(data.ciCd.classification,'HISTORICAL');assert.equal(data.ciCd.evidenceClass,'REAL');assert.equal(data.ciCd.updatedValue,'updated');assert.equal(data.ciCd.restoredValue,'baseline');assert.equal(data.ciCd.policyDecision,'PASS');assert.ok(html.includes(data.ciCd.runId));
const cap=await (await get('/api/plugins')).json();assert.equal(cap.plugins.find(p=>p.pluginId==='semgrep').state,'BLOCKED');assert.equal(cap.plugins.find(p=>p.pluginId==='gitleaks').state,'READY');
const runs=await (await get('/api/runs')).json();const real=runs.runs.filter(r=>r.pluginId==='gitleaks'&&r.evidenceClass==='REAL'&&r.state==='COMPLETED');assert.ok(real.some(p=>p.scenarioId==='clean'&&p.policyDecision==='PASS'));assert.ok(real.some(p=>p.scenarioId==='controlled-finding'&&p.policyDecision==='FAIL'));
const origin=await fetch(base+'/api/overview',{headers:{Origin:'https://example.com'}});assert.equal(origin.status,403);
const csrf=await fetch(base+'/api/run',{method:'POST',headers:{'Content-Type':'application/json'},body:'{"pluginId":"semgrep","scenarioId":"clean"}'});assert.equal(csrf.status,403);
assert.equal((await get('/.git/config')).status,404);
assert.doesNotMatch(JSON.stringify(data),/-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY-----|\bglpat-[A-Za-z0-9_-]{12,}|AGE-SECRET-KEY-/);
assert.equal((await get('/')).status,200);assert.equal((await get('/api/overview')).status,200);
const result={verifiedAt:new Date().toISOString(),url:base,http:200,registryEntries:data.registry.entries.length,allHistoricalArtifactsBound:true,semgrepNewExecution:'NOT_EXECUTED',semgrepHistoricalPassFailVisible:true,
 consumers:'MOCK / real remote NOT_TESTED',grafana:'8-panel CANDIDATE / real query NOT_TESTED',existingCiCd6:'VERIFIED',existingGitleaksPassFail:'VERIFIED',csrfAndOrigin:'VERIFIED',browserClick:'NOT_TESTED',newScans:0,releaseCount:0,rolloutCount:0,
 sourceHashes:Object.fromEntries(['data.mjs','app.js','server.mjs'].map(n=>[n,createHash('sha256').update(fs.readFileSync(new URL('../../../infra/security/manager-v2/view/'+n,import.meta.url))).digest('hex')]))};
fs.writeFileSync(new URL('acceptance.json',import.meta.url),JSON.stringify(result,null,2)+'\n',{flag:'wx'});console.log(JSON.stringify(result));
