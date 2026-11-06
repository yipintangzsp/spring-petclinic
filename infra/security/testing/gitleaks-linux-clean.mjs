// Fixed non-production fixtures. Invoked only by the root-owned SSH wrapper.
import fs from 'node:fs';
import path from 'node:path';
import assert from 'node:assert/strict';
import {runCandidate} from '../manager-v2/core.mjs';
import {realGitleaksRegistry} from '../manager-v2/registry.mjs';
import {realExecutionCounts} from '../manager-v2/gitleaks-real.mjs';
import {verifyArtifact} from '../manager-v2/result.mjs';
import {routeResults} from '../manager-v2/router.mjs';
const root='/var/tmp/security-manager-gitleaks-v2-linux-20261105';
const runId=process.argv[2];
assert(process.argv.length===3||process.argv.length===4&&process.argv[3]==='controlled-finding'||process.argv.length===5&&['clean','controlled-finding'].includes(process.argv[3]));
const securityLevel=process.argv[4]??'standard';assert(['low','standard','strict'].includes(securityLevel));
const finding=process.argv[3]==='controlled-finding';
const scenarioId=finding?'controlled-finding':'clean';
const projectId=finding?'java-fixture':'python-fixture',profile=finding?'java-web':'python-api';
assert.match(runId,/^web-[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/);
assert.equal(process.getuid(),24021);
const approvalFile=root+'/approval.json',approval=JSON.parse(fs.readFileSync(approvalFile));
assert.equal(approval.executionUid,24021);
const source=approval.sources.find(s=>s.projectId===projectId);
assert.equal(source.sourceDir,root+(finding?'/source-java':'/source-python'));
assert.equal(source.profile,profile);
const output=path.join(approval.outputRoot,runId);fs.mkdirSync(output,{mode:0o700});
const registry=realGitleaksRegistry(),controller=new AbortController();
const cancel=()=>controller.abort();process.on('SIGTERM',cancel);process.on('SIGHUP',cancel);
const run=await runCandidate({runId,projectId,registry,signal:controller.signal,
 config:{security:{enabled:true,globalMode:'audit',securityLevel,profile,plugins:Object.fromEntries(registry.ids().map(id=>[id,{enabled:id==='gitleaks'}]))}},
 context:{platform:'linux',capabilities:Object.fromEntries(['SOURCE_DIR','GITLEAKS_TOOL','TRUSTED_VALIDATION_WORKSPACE'].map(c=>[c,{state:'AVAILABLE'}]))},
 inputs:{gitleaks:{approvalFile,sourceDir:source.sourceDir}},output:output+'/artifact'});
const r=run.gate.gitleaks;verifyArtifact(output+'/artifact',run.artifact.sealDigest);
assert.equal(r.executionStatus,'COMPLETED');assert.equal(r.oldGateDecision,r.policyDecision);
assert.equal(r.evaluationCount,1);assert.equal(run.policyEvaluationCounts.gitleaks,1);
assert.equal(realExecutionCounts().scans,1);
assert.equal(r.runtimeFacts.command.exitStatus,finding?1:0);
assert.equal(r.policyDecision,finding?'FAIL':'PASS');
const raw=JSON.parse(fs.readFileSync(output+'/artifact/gitleaks.raw.json'));
assert.equal(raw.length,r.runtimeFacts.findingsCount);
assert(finding?raw.length>0&&raw.every(f=>f.RuleID==='github-pat'&&f.File===source.sourceDir+'/Main.java'&&f.StartLine===2):raw.length===0);
const synthetic=finding?fs.readFileSync(source.sourceDir+'/Main.java','utf8').match(/\bghp_[A-Za-z0-9]{36}\b/)?.[0]:null;
assert(!finding||synthetic);
fs.mkdirSync(output+'/router',{mode:0o700});
const routed=routeResults({run,artifactDirectory:output+'/artifact',expectedSealDigest:run.artifact.sealDigest,output:output+'/router'});
assert.equal(routed.receipts.find(c=>c.consumerId==='local-evidence').deliveryDecision,'DELIVERED_LOCAL_ONLY');
const files={};for(const n of fs.readdirSync(output+'/artifact')){
 assert.match(n,/^[-a-zA-Z0-9_.]+\.json$/);
 const bytes=fs.readFileSync(output+'/artifact/'+n);
 assert(!synthetic||!bytes.includes(synthetic),'Synthetic credential was not redacted');
 files[n]=bytes.toString('base64');
}
const packet={schemaVersion:1,kind:finding?'RestrictedLinuxGitleaksFinding':'RestrictedLinuxGitleaksClean',runId,scenarioId,executionHost:'devops/192.168.64.11',
 result:r,artifactDigest:run.artifact.sealDigest,files,router:routed.receipts,
 policyEvaluationCount:run.policyEvaluationCounts.gitleaks,executionCounts:realExecutionCounts()};
fs.writeFileSync(output+'/receipt.json',JSON.stringify(packet),{flag:'wx',mode:0o400});
process.stdout.write(JSON.stringify(packet)+'\n');
