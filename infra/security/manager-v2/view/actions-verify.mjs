// Real HTTP intake verification, explicitly not scanner or browser-click proof.
import assert from 'node:assert/strict';
import http from 'node:http';
import {validateRequest} from './actions.mjs';
const base='http://127.0.0.1:17862',origin=base,checks=[],runs=[];
const request=(p,o={})=>fetch(base+p,{signal:AbortSignal.timeout(5000),...o});
const test=(name,fn)=>{fn();checks.push({name,status:'PASS'});};
const page=await request('/');test('page HTTP 200, distinct live and history sections',()=>assert.equal(page.status,200));
const html=await page.text();assert.match(html,/Live Validation|LIVE VALIDATION/);assert.match(html,/Historical Replay Results/);
const capabilities=await (await request('/api/plugins')).json();const token=capabilities.csrfToken;
test('explicit existing Linux-only runner capability blockage',()=>{assert.equal(capabilities.platform,'darwin');assert.equal(capabilities.plugins.length,3);for(const p of capabilities.plugins){assert.equal(p.state,'BLOCKED');assert.equal(p.reason,'REAL_SCANNER_REQUIRES_APPROVED_LINUX_IDENTITY');}});
const post=(body,headers={})=>request('/api/run',{method:'POST',headers:{Origin:origin,'Content-Type':'application/json','X-CSRF-Token':token,...headers},body:typeof body==='string'?body:JSON.stringify(body)});
for(const [label,headers,code] of [['missing token',{'X-CSRF-Token':''},403],['wrong token',{'X-CSRF-Token':'a'.repeat(64)},403],['wrong origin',{Origin:'https://example.com'},403],['missing origin',{Origin:''},403],['cross-site fetch',{'Sec-Fetch-Site':'cross-site'},403]]){const r=await post({pluginId:'gitleaks',scenarioId:'clean'},headers);test(label,()=>assert.equal(r.status,code));}
for(const body of [{pluginId:'trivy',scenarioId:'clean'},{pluginId:'gitleaks',scenarioId:'../clean'},{pluginId:'gitleaks',scenarioId:'clean',path:'/etc'},{pluginId:'cosign',scenarioId:'clean',env:{HOME:'/'}},'bad json']){const r=await post(body);test('reject unapproved request '+checks.length,()=>assert.equal(r.status,400));}
const huge=await post('x'.repeat(1025));test('request body capped',()=>assert.equal(huge.status,413));
// fetch normalizes Host: use native HTTP to actually put an invalid Host on wire.
const hostStatus=await new Promise((resolve,reject)=>{const r=http.get(base+'/api/plugins',{headers:{Host:'attacker.invalid:17862'}},res=>{res.resume();resolve(res.statusCode);});r.on('error',reject);r.setTimeout(3000,()=>r.destroy(Error('timeout')));});test('DNS rebinding host rejected',()=>assert.equal(hostStatus,403));
const crossed=await request('/api/plugins',{headers:{Origin:'https://example.com'}});test('cross-origin session rejected',()=>assert.equal(crossed.status,403));
const traversal=await request('/api/runs/..%2f..%2fetc');test('run path traversal rejected',()=>assert.equal(traversal.status,400));
for(const pluginId of ['gitleaks','semgrep','cosign'])for(const scenarioId of ['clean','controlled-finding']){
 const res=await post({pluginId,scenarioId});assert.equal(res.status,202);let run=await res.json();
 for(let i=0;i<50;i++){run=await (await request('/api/runs/'+run.runId)).json();if(!['QUEUED','RUNNING'].includes(run.state))break;await new Promise(r=>setTimeout(r,100));}
 test(pluginId+' '+scenarioId+' safely BLOCKED, never claimed REAL',()=>{assert.equal(run.state,'BLOCKED');assert.equal(run.scannerExecuted,false);assert.equal(run.evidenceClass,'NOT_TESTED');assert.equal(run.policyDecision,null);assert.equal(run.evaluationCount,0);assert.match(run.auditDigest,/^[a-f0-9]{64}$/);});
 const refresh=await (await request('/api/runs/'+run.runId)).json();assert.deepEqual(refresh,run);runs.push(run);
}
const latest=await (await request('/api/runs')).json();test('reload API retains all new runs',()=>{for(const r of runs)assert.ok(latest.runs.some(v=>v.runId===r.runId&&v.auditDigest===r.auditDigest));});
for(const body of [null,[],{pluginId:'gitleaks',scenarioId:'clean',command:'x'}])assert.throws(()=>validateRequest(body));
test('no private report material in response',()=>assert.doesNotMatch(JSON.stringify(latest),/-----BEGIN .*PRIVATE KEY-----|AGE-SECRET-KEY-|github_pat_|\bBearer\s+\S{10,}/));
console.log(JSON.stringify({at:new Date().toISOString(),url:base,checks,pass:checks.length,fail:0,runs,realScannerExecutions:0,policyEvaluationCount:0,browserClickAcceptance:'NOT_TESTED',realRunnerIntegration:'BLOCKED_BY_EXISTING_LINUX_ONLY_CONTRACT',releaseCount:0,rolloutCount:0},null,2));
