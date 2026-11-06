// Focused management/API security checks. No scanner execution or config mutation.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import http from 'node:http';
import {acceptLinuxGitleaksPacket} from '../../../infra/security/manager-v2/view/linux-gitleaks.mjs';
import {acceptLinuxSemgrepPacket} from '../../../infra/security/manager-v2/view/linux-semgrep.mjs';
import {acceptLinuxCosignPacket} from '../../../infra/security/manager-v2/view/linux-cosign.mjs';
const base='http://security.devops.local:17862';
const get=async p=>{const r=await fetch(base+p,{signal:AbortSignal.timeout(8000)});assert.equal(r.status,200);return r.json();};
const before=await get('/api/config'),cap=await get('/api/plugins');
assert.equal(before.settings.securityLevel,'standard');assert.equal(before.settings.enabled,true);assert.ok(Object.values(before.settings.plugins).every(p=>p.enabled));assert.equal(before.effectiveConfig.securityLevel,'standard');assert.ok(before.effectiveConfig.configurationOrigins.length>2);
const headers={Origin:base,'Content-Type':'application/json','X-CSRF-Token':cap.csrfToken};
for(const patch of [s=>s.securityLevel='unknown',s=>s.enabled='true',s=>s.plugins.semgrep.enabled='false',s=>s.plugins.extra={enabled:true},s=>s.path='/etc/passwd']){
 const settings=structuredClone(before.settings);patch(settings);const r=await fetch(base+'/api/config',{method:'POST',headers,body:JSON.stringify({revision:before.revision,settings})});assert.equal(r.status,400);
}
assert.equal((await fetch(base+'/api/config',{method:'POST',headers,body:JSON.stringify({revision:before.revision-1,settings:before.settings})})).status,409);
for(const route of ['/api/config','/api/config/reset'])assert.equal((await fetch(base+route,{method:'POST',headers:{'Content-Type':'application/json'},body:'{}'})).status,403);
assert.equal((await fetch(base+'/api/config',{headers:{Origin:'https://untrusted.invalid'}})).status,403);
const wrongHost=await new Promise((resolve,reject)=>http.get({hostname:'127.0.0.1',port:17862,path:'/api/config',headers:{Host:'untrusted.invalid'}},r=>{r.resume();resolve(r.statusCode);}).on('error',reject));assert.equal(wrongHost,403);
assert.deepEqual(await get('/api/config'),before);assert.ok(cap.plugins.every(p=>p.state==='READY'));
const html=await (await fetch(base+'/#candidate-overview')).text();for(const id of ['candidate-controls','control-enabled','control-level','control-form','save-controls','reset-controls'])assert.ok(html.includes('id="'+id+'"'));
const app=await (await fetch(base+'/app.js')).text();assert.match(app,/control-form.*addEventListener\('submit'/);assert.match(app,/reset-controls.*addEventListener/);
const overview=await get('/api/overview');assert.equal(overview.registry.entries.length,13);assert.equal(overview.ciCd.build,6);assert.equal(overview.ciCd.restoredValue,'baseline');assert.equal(overview.baseline.PRODUCTION_SECURITY_MANAGER,'NOT_ACTIVE');assert.equal(overview.baseline.FINAL_WIRED_CAPABILITY,'14/16');
const runs=(await get('/api/runs')).runs;for(const id of ['gitleaks','semgrep','cosign'])for(const decision of ['PASS','FAIL'])assert.ok(runs.some(r=>r.pluginId===id&&r.evidenceClass==='REAL'&&r.policyDecision===decision));
const g=JSON.parse(fs.readFileSync(new URL('prior-standard-gitleaks-packet.json',import.meta.url)));
const readPackets=p=>Object.values(JSON.parse(fs.readFileSync(new URL(p,import.meta.url))));
const prior=[[g,acceptLinuxGitleaksPacket],[readPackets('../semgrep-web-real/real-packets.json').find(p=>p.scenarioId==='clean'),acceptLinuxSemgrepPacket],[readPackets('../cosign-web-real/real-packets.json').find(p=>p.scenarioId==='clean'),acceptLinuxCosignPacket]];
for(const [p,accept]of prior){const dir=fs.mkdtempSync(path.join(os.tmpdir(),'candidate-standard-compat-'));try{assert.equal(accept(p,p.scenarioId,p.runId,dir).resultDigest,p.result.resultDigest);}finally{fs.rmSync(dir,{recursive:true});}}
assert.doesNotMatch(JSON.stringify({before,runs,overview}),/-----BEGIN (?:OPENSSH |RSA |EC )?PRIVATE KEY-----|\bglpat-[A-Za-z0-9_-]{12,}/);
const out={verifiedAt:new Date().toISOString(),url:base+'/#candidate-overview',http:200,controlsVisible:true,threePluginStateAndHistory:true,historyCiCd6Preserved:true,existingStandardPacketsCompatible:3,invalidConfigurationRejected:true,revisionConflictRejected:true,hostOriginCsrf:'VERIFIED',invalidRequestsDidNotChangeConfiguration:true,finalRevision:before.revision,browserClick:'NOT_TESTED',newScannerExecutions:0,release:0,rollout:0};
fs.writeFileSync(new URL('http-acceptance.json',import.meta.url),JSON.stringify(out,null,2)+'\n',{flag:'wx'});console.log(JSON.stringify(out));
