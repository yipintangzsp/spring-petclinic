import test from 'node:test';import assert from 'node:assert/strict';import fs from 'node:fs';
import {evaluate} from './engine.mjs';import {gitleaksParent} from './gitleaks-parent.mjs';import {gitleaksEvidence} from './gitleaks-evidence.mjs';
import {replayGitleaksParent} from './gitleaks-parent-replay.mjs';import {fixture,sourceFinding,base,sha} from './gitleaks-parent-fixtures.mjs';
fs.mkdirSync(base+'fixtures',{recursive:true});const records=[],cases=[];
const add=(name,branch,change=()=>{})=>cases.push({name,branch,change});
add('healthy-zero-findings','positive');
add('current-unreviewed-finding','classification',r=>sourceFinding(r));
add('reviewed-finding','classification',r=>sourceFinding(r,{reviewed:true}));
add('changed-source-line','classification',r=>{sourceFinding(r,{reviewed:true});r.sourceText['/work/source/a.txt']='changed public fixture';});
add('changed-rule','classification',r=>{sourceFinding(r,{reviewed:true});const f=JSON.parse(r.reportFiles['/work/source.json']);f[0].RuleID='other-rule';r.reportFiles['/work/source.json']=JSON.stringify(f);});
add('changed-review-path','classification',r=>{sourceFinding(r,{reviewed:true});r.reviewedEntries[0].path='other.txt';});
add('duplicate-reviewed-findings','classification',r=>sourceFinding(r,{reviewed:true,duplicate:true}));
add('scanner-exit-zero-still-blocking','exit-semantics',r=>{sourceFinding(r);r.scans['/work/source'].exit=0;});
add('scanner-exit-one-empty-is-current-pass','exit-semantics',r=>r.scans['/work/source'].exit=1);
add('explicit-holder-fallback','prerequisite',r=>{delete r.env.HEAVY_HOLDER;r.lease.spec.holderIdentity='jenkins-petclinic-270';});
add('manual-no-build-identity-current-semantics','prerequisite',r=>delete r.env.BUILD_NUMBER);
add('foreign-lease','prerequisite',r=>r.lease.spec.holderIdentity='foreign');
add('lease-empty-spec','prerequisite',r=>r.lease={});
add('lock-malformed','prerequisite',r=>r.toolLock='{');
add('lock-tool-missing','prerequisite',r=>r.toolLock='{}');
add('invalid-canary-ip','isolation',r=>r.interfaces={eth0:[{family:'IPv4',address:'192.0.2.5'}]});
add('missing-interface','isolation',r=>r.interfaces={});
add('canary-listen-error','isolation',r=>r.canaryListen=false);
add('canary-baseline-error','isolation',r=>r.canaryEvents=['error']);
add('canary-baseline-timeout','timeout',r=>r.canaryEvents=['timeout']);
add('canary-after-probe-error','isolation',r=>r.canaryEvents=['connect','connect','error']);
add('network-nonconvergence','isolation',r=>r.isolationExits=[0]);
add('network-counter-resets-before-converging','isolation',r=>r.isolationExits=[1,0,1,1]);
add('nc-help-no-zero-io','prerequisite',r=>r.ncHelp='unsupported');
add('nc-help-supported-exit-one','exit-semantics',r=>r.commands['probe-help']={status:1});
add('wrong-effective-uid','isolation',r=>r.effectiveUid='0');
add('readonly-write-succeeds','isolation',r=>r.readOnlyExit=0);
add('readonly-wrong-error','isolation',r=>r.readOnlyStderr='permission denied');
add('node-api-reachable-not-gate-failure','existing-not-enforced',r=>r.nodeNetworkExit=0);
add('image-id-mismatch','identity',r=>r.imageId='sha256:'+'b'.repeat(64));
add('image-id-missing','identity',r=>r.imageId=null);
add('archive-budget-exceeded','bounds',r=>r.archiveOversize=true);
add('positive-exit-zero-even-with-finding','scanner-self-test',r=>r.scans['/work/fixture'].exit=0);
add('positive-wrong-rule','scanner-self-test',r=>r.reportFiles['/work/positive.json']='[{"RuleID":"other"}]');
add('clean-exit-one','scanner-self-test',r=>r.scans['/work/clean'].exit=1);
add('clean-has-finding','scanner-self-test',r=>r.reportFiles['/work/clean.json']='[{"RuleID":"fixture-rule"}]');
add('source-empty-bytes-current-empty-array','report',r=>r.reportFiles['/work/source.json']='');
add('source-json-null','malformed-report',r=>r.reportFiles['/work/source.json']='null');
add('source-json-object','malformed-report',r=>r.reportFiles['/work/source.json']='{}');
add('source-location-outside-root','classification-error',r=>{sourceFinding(r);const f=JSON.parse(r.reportFiles['/work/source.json']);f[0].File='/other/a.txt';r.reportFiles['/work/source.json']=JSON.stringify(f);});
add('source-location-parent-traversal','classification-error',r=>{sourceFinding(r);const f=JSON.parse(r.reportFiles['/work/source.json']);f[0].File='/work/source/../a.txt';r.reportFiles['/work/source.json']=JSON.stringify(f);});
add('source-location-missing-line','classification-error',r=>{sourceFinding(r);r.sourceText['/work/source/a.txt']='';const f=JSON.parse(r.reportFiles['/work/source.json']);f[0].StartLine=9;r.reportFiles['/work/source.json']=JSON.stringify(f);});
add('source-file-read-failure','execution-error',r=>{sourceFinding(r);delete r.sourceText['/work/source/a.txt'];});
add('review-json-invalid-shape','malformed-report',r=>r.reviewedEntries=null);
add('review-json-malformed','malformed-report',r=>r.reviewText='{');
add('review-entries-object-with-finding','malformed-report',r=>{sourceFinding(r);r.reviewedEntries={};});
add('readiness-command-timeout','timeout',r=>r.commands.ready={status:null,error:{code:'ETIMEDOUT',message:'controlled timeout'}});
add('git-revision-spawn-failed','prerequisite',r=>r.commands['git-revision']={status:null,error:{code:'ENOENT'}});
add('memory-peak-non-numeric-is-null','existing-not-enforced',r=>r.memoryPeak='max');
add('memory-peak-exit-one-accepted','exit-semantics',r=>r.commands['memory-peak']={status:1,stdout:''});
add('created-uid-missing-skips-cleanup-current-semantics','existing-not-enforced',r=>r.createdUid=null);
add('cleanup-replacement-refused','cleanup',r=>r.podUids=['fixture-pod-uid','fixture-pod-uid','replacement']);
add('cleanup-still-present','cleanup',r=>r.cleanupRemaining=true);
add('canary-close-error','cleanup',r=>r.canaryCloseError=true);
add('body-failure-and-cleanup-failure','cleanup',r=>{sourceFinding(r);r.commands.delete={status:1,stderr:'delete failed'};});
for(const path of ['/work/positive.json','/work/clean.json','/work/source.json']){
 add('missing-'+path.split('/').at(-1),'missing-report',r=>delete r.reportFiles[path]);
 add('malformed-'+path.split('/').at(-1),'malformed-report',r=>r.reportFiles[path]='{');
 add('read-error-'+path.split('/').at(-1),'report-read',r=>r.commands['report:'+path]={status:1,stderr:'read denied'});
 add('whitespace-'+path.split('/').at(-1),'malformed-report',r=>r.reportFiles[path]=' ');
}
for(const key of ['lease','git-revision','create','ready','probe-help','isolation-probe','node-network','token-probe','effective-uid','readonly-probe','pod-get-1','work-mkdir','source-archive','archive-transfer','fixture-write','memory-peak','pod-get-2','pod-get-3','delete','cleanup-verify']){
 add('command-failed-'+key,key==='delete'||key==='cleanup-verify'||key==='pod-get-3'?'cleanup':'execution-error',r=>r.commands[key]={status:2,stderr:'controlled command error'});
}
for(const scan of ['/work/fixture','/work/clean','/work/source'])for(const [tag,result]of Object.entries({missing:{status:127,stderr:'gitleaks unavailable'},unexpected:{status:2},timeout:{status:null,error:{code:'ETIMEDOUT',message:'controlled timeout'}},signal:{status:null,signal:'SIGTERM'},spawnerror:{status:null,error:{code:'ENOENT',message:'controlled missing tool'}}})){
 add(scan.split('/').at(-1)+'-'+tag,tag==='timeout'?'timeout':tag==='missing'||tag==='spawnerror'?'tool-unavailable':'scanner-execution-error',r=>r.commands['scan:'+scan]=result);
}
for(const key of ['mkdir:.devsecops','read:infra/security/tools-lock.json','read:infra/security/reviewed-false-positives.json','write:.devsecops/source-gate.json#1','write:.devsecops/source-gate.json#2','write:.devsecops/gitleaks-native.json'])add('io-'+key.replaceAll('/','_'),'io-write',r=>r.io[key]='controlled EACCES');
for(const c of cases)test('Gitleaks complete original parent: '+c.name,async()=>{
 const input=fixture();c.change(input);const inputBefore=JSON.stringify(input),facts=await replayGitleaksParent(input),before=JSON.stringify(facts);
 const old=facts.execution.exitStatus===0?'PASS':'FAIL',result=evaluate({component:'gitleaks',status:'success',raw:facts},{policyVersion:'baseline-v1',securityLevel:'standard'});
 assert.equal(result.decision,old,c.name+': '+facts.execution.diagnostic);assert.deepEqual(result.rawEvidence,facts);assert.equal(JSON.stringify(facts),before);assert.equal(JSON.stringify(input),inputBefore);
 if(result.normalizedFacts.classification)assert.deepEqual(result.normalizedFacts.classification,gitleaksEvidence(facts.classifierInput));
 const file=c.name.replace(/[^a-zA-Z0-9_.-]/g,'_')+'.json';fs.writeFileSync(base+'fixtures/'+file,JSON.stringify({input,facts},null,2));
 records.push({name:c.name,branch:c.branch,classification:'CONTROLLED_REPLAY',oldDecision:old,standardDecision:result.decision,rawPreserved:true,inputSha256:sha(inputBefore),rawSha256:sha(before),fixture:file,execution:facts.execution,scannerExits:facts.observations.filter(x=>x.type==='command'&&x.key.startsWith('scan:')).map(x=>({key:x.key,status:x.result.status,error:x.result.error??null}))});
});
test('Missing parent evidence is NOT_TESTED, never PASS',()=>{
 for(const raw of [{},{schema:1,stage:'parent',complete:true,observations:[]},{schema:1,stage:'wrapper',complete:true,observations:[],execution:{}}])assert.equal(gitleaksParent(raw).decision,null);
});
test('All policy levels retain authoritative parent facts and legacy failure floor',async()=>{
 const input=fixture();sourceFinding(input);const raw=await replayGitleaksParent(input),before=JSON.stringify(raw);
 for(const securityLevel of ['low','standard','strict'])assert.equal(evaluate({component:'gitleaks',status:'success',raw},{securityLevel}).decision,'FAIL');
 assert.equal(JSON.stringify(raw),before);
});
test('Original seven accepted classifier receipts remain intact',()=>{
 const old=JSON.parse(fs.readFileSync('evidence/2026-11-01/policy-engine/gitleaks-differential.json'));assert.equal(old.records.length,7);assert.ok(old.records.every(x=>x.legacy===x.standard&&x.inputUnchanged));
});
test('Missing successful native receipt cannot become PASS',async()=>{
 const raw=await replayGitleaksParent(fixture());delete raw.reports['.devsecops/gitleaks-native.json'];assert.equal(gitleaksParent(raw).status,'NOT_TESTED');assert.equal(gitleaksParent(raw).decision,null);
});
test('Existing Gitleaks non-decision statuses stay non-decisions',()=>{
 for(const status of ['disabled','skipped','not_configured']){const p=evaluate({component:'gitleaks',status,raw:{stage:'parent'}});assert.equal(p.decision,null);assert.equal(p.status,status.toUpperCase());}
});
test.after(()=>fs.writeFileSync(base+'differential.json',JSON.stringify({scope:'Whole unchanged production source-gate with inert fs/process/network; no real secrets/scanner/cluster',records},null,2)));
