// HTTP acceptance only. No scans, fixture generation, or production connections.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import {createHash} from 'node:crypto';
import {root} from './data.mjs';
const url='http://127.0.0.1:17862';
const get=p=>fetch(url+p,{signal:AbortSignal.timeout(5000)});
const checks=[];
const check=(name,fn)=>{fn();checks.push({name,status:'PASS'});};
const h=await get('/');const html=await h.text();
check('Page HTTP 200 and real HTML',()=>{assert.equal(h.status,200);assert.match(html,/<title>Security Manager V2/);assert.match(html,/id="plugin-grid"/);});
for(const p of ['/style.css','/app.js']){const r=await get(p);check(p+' HTTP 200',()=>assert.equal(r.status,200));}
const response=await get('/api/overview');assert.equal(response.status,200);const data=await response.json();
check('Read-only replay, never live scanning',()=>{assert.equal(data.mode,'REPLAY');assert.equal(data.liveScan,false);});
check('Authority limits remain visible',()=>{assert.equal(data.baseline.PRODUCTION_SECURITY_MANAGER,'NOT_ACTIVE');assert.equal(data.baseline.FINAL_WIRED_CAPABILITY,'14/16');assert.equal(data.baseline.ORIGINAL_EVIDENCE_INTEGRITY,'FAILED');assert.equal(data.baseline.TRIVY_RUNTIME_FACT_CAPTURE,'INCOMPLETE');});
const find=n=>data.runs.find(r=>r.runId===n);
check('Three real plugins visible in selected latest complete run',()=>{
 const r=find('attempt2-P-service-project');assert.equal(r.plugins.length,3);
 for(const name of ['gitleaks','semgrep','cosign']){const p=r.plugins.find(p=>p.pluginId===name);assert.equal(p.availability,'AVAILABLE');assert.equal(p.evidenceClass,'REAL');assert.equal(p.policyDecision,'PASS');assert.match(p.resultDigest,/^[a-f0-9]{64}$/);assert.ok(p.completedAt);}
});
for(const [name,plugin] of [['attempt2-H-gitleaks-fail','gitleaks'],['attempt2-G-semgrep-fail','semgrep'],['attempt2-F-cosign-tampered','cosign']]){
 check(plugin+' historical real FAIL stays FAIL',()=>{const p=find(name).plugins.find(p=>p.pluginId===plugin);assert.equal(p.policyDecision,'FAIL');assert.equal(p.oldGateDecision,'FAIL');assert.equal(p.evidenceClass,'REAL');});
}
check('DISABLED is never converted to PASS',()=>{for(const p of find('attempt2-E-all-disabled').plugins){assert.equal(p.executionStatus,'DISABLED');assert.equal(p.policyDecision,null);assert.equal(p.evidenceClass,'NOT_TESTED');assert.equal(p.enabled,false);}});
check('ERROR and POLICY_ERROR have no invented decision',()=>{assert.equal(find('attempt2-I-cosign-timeout').plugins.find(p=>p.pluginId==='cosign').executionStatus,'ERROR');const p=find('attempt2-Q-cross-project-identity-rejected').plugins.find(p=>p.pluginId==='cosign');assert.equal(p.executionStatus,'POLICY_ERROR');assert.equal(p.policyDecision,null);});
check('All displayed decisions preserved and source files hash-match',()=>{
 for(const r of data.runs){assert.equal(r.availability,'AVAILABLE');const original=JSON.parse(fs.readFileSync(path.join(root,r.source.path)));
  for(const p of r.plugins){assert.equal(p.availability,'AVAILABLE');const op=original.pluginResults.find(x=>x.pluginId===p.pluginId);assert.equal(p.resultDigest,op.resultDigest);assert.equal(p.policyDecision,op.policyDecision);assert.equal(p.executionStatus,op.executionStatus);assert.equal(p.completedAt,op.completedAt);}
  for(const s of [r.source,...r.plugins.map(p=>p.source)]) assert.equal(createHash('sha256').update(fs.readFileSync(path.join(root,s.path))).digest('hex'),s.sha256);
 }
});
check('Consumers are independently sourced MOCK, never real delivery',()=>{assert.equal(data.consumers.length,2);for(const c of data.consumers){assert.equal(c.availability,'AVAILABLE');assert.equal(c.evidenceClass,'MOCK');assert.equal(c.realRemoteDelivery,'NOT_TESTED');assert.equal(c.productionDeliveryCount,0);assert.ok(c.source.sha256);assert.ok(c.runId);}assert.equal(data.dojo.httpAdapter,'VERIFIED');assert.equal(data.dojo.realDelivery,'NOT_TESTED');});
check('No raw findings or credential fields exposed',()=>{
 const walk=v=>{if(!v||typeof v!=='object')return;for(const [k,x] of Object.entries(v)){assert.ok(!/^(secret|password|token|privateKey|authorization|Match|Secret|findings|received|requests|rawReport)$/i.test(k),k);walk(x);}};walk(data);
 assert.doesNotMatch(JSON.stringify(data),/-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY-----|\b(?:ghp_|github_pat_|AKIA)[A-Za-z0-9]{16,}|\bBearer\s+[A-Za-z0-9._-]{10,}|AGE-SECRET-KEY-/);
});
for(const p of ['/api/raw','/.git/config','/candidate-summary.json']){const r=await get(p);check('No arbitrary file route '+p,()=>assert.equal(r.status,404));}
const post=await fetch(url+'/api/overview',{method:'POST',signal:AbortSignal.timeout(3000)});check('Writes rejected',()=>assert.equal(post.status,405));
const origin=await fetch(url+'/api/overview',{headers:{Origin:'https://example.com'},signal:AbortSignal.timeout(3000)});check('Cross-origin read rejected',()=>assert.equal(origin.status,403));
console.log(JSON.stringify({verifiedAt:new Date().toISOString(),url,pageStatus:h.status,apiStatus:response.status,runs:data.runs.length,pluginRecords:data.runs.length*3,pass:checks.length,fail:0,checks,sourceHashes:data.runs.map(r=>({runId:r.runId,...r.source})),browserAutomation:'SKIPPED_LOCAL_BROWSER_DISABLED_IN_WORK_SETTINGS',releaseCount:0,rolloutCount:0},null,2));
