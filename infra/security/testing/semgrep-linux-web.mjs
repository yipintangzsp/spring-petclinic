// Fixed passive fixtures only; invoked by the root-owned, dedicated SSH entry.
import fs from 'node:fs';
import assert from 'node:assert/strict';
import {runCandidate} from '../manager-v2/core.mjs';
import {realPluginsRegistry} from '../manager-v2/registry.mjs';
import {semgrepExecutionCounts} from '../manager-v2/semgrep-real.mjs';
import {verifyArtifact} from '../manager-v2/result.mjs';
import {routeResults} from '../manager-v2/router.mjs';
const root='/var/tmp/security-manager-gitleaks-semgrep-web-20261106';
const [runId,scenarioId]=process.argv.slice(2);
assert.equal(process.argv.length,4);
assert.match(runId,/^web-[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/);
assert(['clean','controlled-finding'].includes(scenarioId));
const approvalFile=root+'/semgrep-approval.json',a=JSON.parse(fs.readFileSync(approvalFile));
assert.equal(process.getuid(),a.executionUid);
const source=a.sources.find(s=>s.case===scenarioId);assert(source);
const output=a.outputRoot+'/'+runId;fs.mkdirSync(output,{mode:0o700});
const registry=realPluginsRegistry(),controller=new AbortController();
process.on('SIGTERM',()=>controller.abort());process.on('SIGHUP',()=>controller.abort());
const run=await runCandidate({runId,projectId:'java-fixture',registry,signal:controller.signal,
 config:{security:{enabled:true,globalMode:'audit',securityLevel:'standard',profile:'java-web',plugins:Object.fromEntries(registry.ids().map(id=>[id,{enabled:id==='semgrep'}]))}},
 context:{platform:'linux',capabilities:Object.fromEntries(['SOURCE_DIR','SEMGREP_BINARY','SEMGREP_RULESET','OUTPUT_DIR','POLICY_VERSION','TRUSTED_VALIDATION_WORKSPACE'].map(c=>[c,{state:'AVAILABLE'}]))},
 inputs:{semgrep:{approvalFile,sourceDir:source.sourceDir}},output:output+'/artifact'});
const r=run.gate.semgrep;verifyArtifact(output+'/artifact',run.artifact.sealDigest);
assert.equal(r.executionStatus,'COMPLETED',JSON.stringify(r.failureReason));
assert.equal(r.oldGateDecision,r.policyDecision);assert.equal(r.evaluationCount,1);assert.equal(run.policyEvaluationCounts.semgrep,1);
assert.equal(semgrepExecutionCounts().scans,1);
assert.equal(r.policyDecision,scenarioId==='clean'?'PASS':'FAIL');
const raw=JSON.parse(fs.readFileSync(output+'/artifact/semgrep.raw.json'));
assert.equal(raw.reports.length,1);assert.equal(raw.reports[0].results.length,r.runtimeFacts.findingsCount);
assert(scenarioId==='clean'?r.runtimeFacts.findingsCount===0:r.runtimeFacts.findingsCount>0);
fs.mkdirSync(output+'/router',{mode:0o700});
const routed=routeResults({run,artifactDirectory:output+'/artifact',expectedSealDigest:run.artifact.sealDigest,output:output+'/router'});
assert.equal(routed.receipts.find(c=>c.consumerId==='local-evidence').deliveryDecision,'DELIVERED_LOCAL_ONLY');
const files={};for(const n of fs.readdirSync(output+'/artifact')){assert.match(n,/^[-a-zA-Z0-9_.]+\.json$/);files[n]=fs.readFileSync(output+'/artifact/'+n).toString('base64');}
const packet={schemaVersion:1,kind:'RestrictedLinuxSemgrep',runId,scenarioId,executionHost:'devops/192.168.64.11',result:r,
 artifactDigest:run.artifact.sealDigest,files,router:routed.receipts,policyEvaluationCount:run.policyEvaluationCounts.semgrep,executionCounts:semgrepExecutionCounts()};
fs.writeFileSync(output+'/receipt.json',JSON.stringify(packet),{flag:'wx',mode:0o400});process.stdout.write(JSON.stringify(packet)+'\n');
