// Fixed, existing offline verification material only. No signing keys or registry access.
import fs from 'node:fs';
import assert from 'node:assert/strict';
import {runCandidate} from '../manager-v2/core.mjs';
import {realThreePluginsRegistry} from '../manager-v2/registry.mjs';
import {cosignExecutionCounts} from '../manager-v2/cosign-real.mjs';
import {verifyArtifact} from '../manager-v2/result.mjs';
import {routeResults} from '../manager-v2/router.mjs';
const root='/var/tmp/security-manager-gitleaks-cosign-web-20261106';
const [runId,scenarioId,securityLevel='standard']=process.argv.slice(2);
assert([4,5].includes(process.argv.length));assert(['low','standard','strict'].includes(securityLevel));
assert.match(runId,/^web-[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/);
assert(['clean','controlled-finding'].includes(scenarioId));
const invalid=scenarioId==='controlled-finding',approvalFile=root+'/cosign-approval.json',a=JSON.parse(fs.readFileSync(approvalFile));
assert.equal(process.getuid(),a.executionUid);
const objectId='java-fixture-'+(invalid?'tampered':'valid');
const output=a.outputRoot+'/'+runId;fs.mkdirSync(output,{mode:0o700});
const registry=realThreePluginsRegistry(),controller=new AbortController();
process.on('SIGTERM',()=>controller.abort());process.on('SIGHUP',()=>controller.abort());
const run=await runCandidate({runId,projectId:'java-fixture',registry,signal:controller.signal,
 config:{security:{enabled:true,globalMode:'audit',securityLevel,profile:'java-web',plugins:Object.fromEntries(registry.ids().map(id=>[id,{enabled:id==='cosign'}]))}},
 context:{platform:'linux',capabilities:Object.fromEntries(registry.get('cosign').requiredCapabilities.map(c=>[c,{state:'AVAILABLE'}]))},
 inputs:{cosign:{approvalFile,objectId}},output:output+'/artifact'});
const r=run.gate.cosign;verifyArtifact(output+'/artifact',run.artifact.sealDigest);
assert.equal(r.executionStatus,'COMPLETED',JSON.stringify(r.failureReason));
assert.equal(r.oldGateDecision,r.policyDecision);assert.equal(r.evaluationCount,1);assert.equal(run.policyEvaluationCounts.cosign,1);
assert.equal(cosignExecutionCounts().verifications,1);assert.equal(cosignExecutionCounts().commands,2);
assert.equal(r.policyDecision,invalid?'FAIL':'PASS');
const raw=JSON.parse(fs.readFileSync(output+'/artifact/cosign.raw.json'));
assert.equal(raw.command.exitStatus,invalid?1:0);assert.equal(raw.command.signal,null);
assert(invalid?raw.command.stderr.length>0&&!raw.command.stderr.includes('Verified OK'):raw.command.stderr.includes('Verified OK'));
assert.equal(raw.binding.objectId,objectId);
fs.mkdirSync(output+'/router',{mode:0o700});
const routed=routeResults({run,artifactDirectory:output+'/artifact',expectedSealDigest:run.artifact.sealDigest,output:output+'/router'});
assert.equal(routed.receipts.find(c=>c.consumerId==='local-evidence').deliveryDecision,'DELIVERED_LOCAL_ONLY');
const files={};for(const n of fs.readdirSync(output+'/artifact')){assert.match(n,/^[-a-zA-Z0-9_.]+\.json$/);files[n]=fs.readFileSync(output+'/artifact/'+n).toString('base64');}
const packet={schemaVersion:1,kind:'RestrictedLinuxCosign',runId,scenarioId,executionHost:'devops/192.168.64.11',result:r,
 artifactDigest:run.artifact.sealDigest,files,router:routed.receipts,policyEvaluationCount:run.policyEvaluationCounts.cosign,executionCounts:cosignExecutionCounts()};
fs.writeFileSync(output+'/receipt.json',JSON.stringify(packet),{flag:'wx',mode:0o400});process.stdout.write(JSON.stringify(packet)+'\n');
