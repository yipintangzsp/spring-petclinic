import test from 'node:test';import assert from 'node:assert/strict';import fs from 'node:fs';import os from 'node:os';import path from 'node:path';import {spawnSync} from 'node:child_process';
import {runCandidate} from './core.mjs';import {registry} from './registry.mjs';import {CATALOG} from './archive.mjs';import {consumers,CONSUMERS,routeResults} from './router.mjs';import {parameters} from './cli.mjs';
const parent=fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(),'smv2-integration-')));let n=0;
const input=id=>({archiveId:id,approvedDigest:CATALOG[id].sha256});
const base=(extra={})=>({runId:'r'+(++n),projectId:'a',config:{security:{plugins:Object.fromEntries(registry().ids().map(id=>[id,{enabled:['semgrep','cosign'].includes(id)}]))}},context:{platform:process.platform,capabilities:{SECURITY_REPORTS:{state:'AVAILABLE'}}},inputs:{semgrep:input('semgrep-pass'),cosign:input('cosign-pass')},output:path.join(parent,'r'+n),...extra});
test.after(()=>fs.rmSync(parent,{recursive:true,force:true}));
test('I independent dry-run and local consumer verify receipt digests without re-evaluation',async()=>{
 const options=base(),r=await runCandidate(options),o=path.join(parent,'delivery');fs.mkdirSync(o,{mode:0o700});const args={run:r,artifactDirectory:options.output,expectedSealDigest:r.artifact.sealDigest,output:o};
 const deliveries=routeResults(args);assert.deepEqual(deliveries.receipts.map(x=>x.deliveryDecision),['DRY_RUN','DELIVERED_LOCAL_ONLY','DISABLED']);assert.equal(deliveries.productionDeliveryCount,0);
 assert.equal(deliveries.receipts[1].resultDigests.cosign,r.gate.cosign.resultDigest);
 const failure=routeResults(args);assert.equal(failure.receipts[1].deliveryDecision,'ERROR');assert.equal(failure.candidateDeliveryAllowed,false);assert.equal(failure.receipts[0].deliveryDecision,'DRY_RUN');assert.deepEqual(r.policyEvaluationCounts,{cosign:1,semgrep:1});
});
test('I duplicate consumers, injected handlers, mutated summary, bad seal rejected',async()=>{
 assert.throws(()=>consumers([CONSUMERS[0],CONSUMERS[0]]),/duplicate/);assert.throws(()=>consumers([{...CONSUMERS[0],publish:'exec'}]),/contract/);
 const o=base(),r=await runCandidate(o),args={run:r,artifactDirectory:o.output,expectedSealDigest:r.artifact.sealDigest};
 assert.throws(()=>routeResults({...args,expectedSealDigest:'bad'}),/seal mismatch/);
 assert.throws(()=>routeResults({...args,run:{...r,summary:{...r.summary,overallStatus:'FAIL'}}}),/summary integrity/);
});
test('I future DefectDojo cannot publish to network even if enabled',async()=>{const o=base(),r=await runCandidate(o);const d=routeResults({run:r,artifactDirectory:o.output,expectedSealDigest:r.artifact.sealDigest,definitions:[{...CONSUMERS[2],enabled:true}]});assert.equal(d.receipts[0].deliveryDecision,'NOT_CONFIGURED');assert.equal(d.productionDeliveryCount,0);});
test('J same manager across projects/profiles with isolated overrides, schemas and capabilities',async()=>{
 const a=await runCandidate(base()),b=await runCandidate(base({projectId:'python-example',config:{security:{profile:'python-api',plugins:Object.fromEntries(registry().ids().map(id=>[id,{enabled:id==='semgrep'||id==='trivy'}]))},profilePolicies:{'python-api':{securityLevel:'low'}},componentOverrides:{semgrep:{policy:{Medium:'WARN'}}},projectOverrides:{'python-example':{securityLevel:'strict'}}},context:{platform:process.platform,capabilities:{SECURITY_REPORTS:{state:'AVAILABLE'},SOURCE_DIR:{state:'AVAILABLE'},REGISTRY_ACCESS:{state:'UNAVAILABLE'}}},inputs:{semgrep:input('semgrep-pass')}}));
 assert.notEqual(a.summary.contextDigest,b.summary.contextDigest);assert.equal(a.summary.profile,'java-web');assert.equal(b.summary.profile,'python-api');assert.equal(a.summary.securityLevel,'standard');assert.equal(b.summary.securityLevel,'strict');assert.equal(b.gate.trivy.executionStatus,'NOT_CONFIGURED');assert.equal(a.gate.trivy.executionStatus,'DISABLED');assert.equal(b.gate.semgrep.policyDecision,'PASS');assert.equal(b.gate.cosign.executionStatus,'DISABLED');assert.equal(a.summary.schemaVersion,b.summary.schemaVersion);
});
test('J actual CLI master switch, required parameters, plugin selection and env validation',()=>{
 const output=path.join(parent,'cli'),args=['infra/security/manager-v2/cli.mjs','--output',output,'--project','other','--run-id','cli'];
 const p=spawnSync(process.execPath,args,{env:{SECURITY_ENABLED:'false',GLOBAL_MODE:'audit',SECURITY_LEVEL:'standard',PROFILE:'container-service',POLICY_VERSION:'baseline-v1',PLUGIN_SELECTION:'all'},encoding:'utf8'});
 assert.equal(p.status,0,p.stderr);const json=JSON.parse(p.stdout);assert.equal(json.overallStatus,'DISABLED');assert.equal(json.promotion.status,'BLOCKED');assert.equal(fs.existsSync(path.join(output,'candidate-summary.json')),true);assert.equal(fs.existsSync(path.join(output,'security-summary.json')),false);
 for(const env of [{SECURITY_ENABLED:'0'},{PLUGIN_SELECTION:'gitleaks,unknown'},{PLUGIN_SELECTION:'gitleaks,gitleaks'}])assert.throws(()=>parameters(args.slice(1),env),/POLICY_ERROR/);
 assert.throws(()=>parameters(['--output','x','--output','y'],{}),/POLICY_ERROR/);
});
