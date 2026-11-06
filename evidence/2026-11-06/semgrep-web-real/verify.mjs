// Targeted acceptance: reads actual sealed runs; no additional scanner/Policy execution.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import http from 'node:http';
import {acceptLinuxSemgrepPacket} from '../../../infra/security/manager-v2/view/linux-semgrep.mjs';
const base='http://security.devops.local:17862',get=p=>fetch(base+p,{signal:AbortSignal.timeout(6000)});
const json=async p=>{const r=await get(p);assert.equal(r.status,200);return r.json();};
const records=[];
for(const scenario of ['clean','controlled-finding']){
 const r=JSON.parse(fs.readFileSync(new URL('web-'+scenario+'.json',import.meta.url)));const current=await json('/api/runs/'+r.runId);
 assert.deepEqual(current,r);assert.equal(r.pluginId,'semgrep');assert.equal(r.evidenceClass,'REAL');assert.equal(r.state,'COMPLETED');assert.equal(r.evaluationCount,1);assert.equal(r.scannerExitCode,0);
 assert.equal(r.policyDecision,scenario==='clean'?'PASS':'FAIL');assert.equal(r.findingsCount,scenario==='clean'?0:2);
 const root=path.resolve('.devsecops/security-view-runs-v1',r.runId,'artifact');
 const result=JSON.parse(fs.readFileSync(root+'/semgrep.result.json'));
 const files=Object.fromEntries(fs.readdirSync(root).map(n=>[n,fs.readFileSync(root+'/'+n).toString('base64')]));
 const packet=JSON.parse(fs.readFileSync(new URL('real-packets.json',import.meta.url)))[r.runId];
 assert.equal(packet.result.resultDigest,r.resultDigest);
 const temp=fs.mkdtempSync(path.join(os.tmpdir(),'semgrep-intake-'));
 try{
  const accepted=acceptLinuxSemgrepPacket(packet,scenario,r.runId,temp);assert.equal(accepted.resultDigest,r.resultDigest);
 }finally{fs.rmSync(temp,{recursive:true});}
 // Each negative starts with a real, valid same-run packet, changing exactly one bound field.
 for(const mutate of [p=>p.result.runId='web-'+ '0'.repeat(36),p=>p.result.policyDecision= p.result.policyDecision==='PASS'?'FAIL':'PASS',p=>p.result.runtimeFacts.tool.sha256='0'.repeat(64),p=>p.scenarioId='arbitrary',p=>p.files['../../escape.json']='e30=']){
  const bad=structuredClone(packet);mutate(bad);assert.throws(()=>acceptLinuxSemgrepPacket(bad,scenario,r.runId,'/nonexistent-never-created'));
 }
 records.push({runId:r.runId,policy:r.policyDecision,digest:r.resultDigest,findings:r.findingsCount,rawReportDigest:r.rawReportDigest});
}
const cap=await json('/api/plugins');assert.equal(cap.plugins.find(x=>x.pluginId==='semgrep').state,'READY');assert.equal(cap.plugins.find(x=>x.pluginId==='gitleaks').state,'READY');assert.equal(cap.plugins.find(x=>x.pluginId==='cosign').state,'BLOCKED');
const all=(await json('/api/runs')).runs;for(const decision of ['PASS','FAIL'])assert.ok(all.some(r=>r.pluginId==='gitleaks'&&r.evidenceClass==='REAL'&&r.state==='COMPLETED'&&r.policyDecision===decision));
const overview=await json('/api/overview');assert.equal(overview.registry.entries.length,13);assert.equal(overview.ciCd.build,6);assert.equal(overview.ciCd.evidenceClass,'REAL');assert.equal(overview.ciCd.restoredValue,'baseline');assert.equal(overview.baseline.PRODUCTION_SECURITY_MANAGER,'NOT_ACTIVE');assert.equal(overview.baseline.FINAL_WIRED_CAPABILITY,'14/16');
const html=await (await get('/')).text();assert.match(html,/id="live-validation"/);assert.match(html,/<option value="semgrep">Semgrep/);
const app=await (await get('/app.js')).text();assert.match(app,/run-validation.*addEventListener/);assert.match(app,/扫描工具/);assert.match(app,/Jenkins NOT_CONFIGURED/);
assert.equal((await fetch(base+'/api/overview',{headers:{Origin:'https://untrusted.invalid'}})).status,403);
assert.equal((await fetch(base+'/api/run',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({pluginId:'semgrep',scenarioId:'clean'})})).status,403);
const wrongHost=await new Promise((resolve,reject)=>{http.get({hostname:'127.0.0.1',port:17862,path:'/',headers:{Host:'untrusted.invalid'}},r=>{r.resume();resolve(r.statusCode);}).on('error',reject);});
assert.equal(wrongHost,403);
assert.equal((await fetch(base+'/api/run',{method:'POST',headers:{Origin:base,'Content-Type':'application/json','X-CSRF-Token':cap.csrfToken},body:JSON.stringify({pluginId:'semgrep',scenarioId:'arbitrary'})})).status,400);
assert.equal((await get('/.git/config')).status,404);
assert.doesNotMatch(JSON.stringify({overview,all,html,app}),/-----BEGIN (?:OPENSSH |RSA |EC )?PRIVATE KEY-----|AGE-SECRET-KEY-|\bglpat-[A-Za-z0-9_-]{12,}/);
const receipt={verifiedAt:new Date().toISOString(),url:base+'/#candidate-overview',http:200,records,postRestartPersistence:true,gitleaksPassFailPreserved:true,existingCiCd6Preserved:true,originHostCsrf:'VERIFIED',tamperedIntake:'REJECTED',arbitraryScenario:'REJECTED',browserClick:'NOT_TESTED',productionSecurityManager:'NOT_ACTIVE',release:0,rollout:0};
fs.writeFileSync(new URL('acceptance.json',import.meta.url),JSON.stringify(receipt,null,2)+'\n',{flag:'wx'});console.log(JSON.stringify(receipt));
