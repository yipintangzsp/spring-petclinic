import test from 'node:test';import assert from 'node:assert/strict';import fs from 'node:fs';
import {evaluate} from './engine.mjs';import {zapParent} from './zap-parent.mjs';import {classifyZap} from '../zap-policy.mjs';
import {fixture,confirmation,alert,base,sha} from './zap-parent-fixtures.mjs';import {replayZapParent} from './zap-parent-replay.mjs';
fs.mkdirSync(base+'fixtures',{recursive:true});const records=[],cases=[];
const add=(name,branch,change=()=>{})=>cases.push({name,branch,change});
add('healthy-no-business-alert','positive');
add('unconfirmed-high','unconfirmed-lower',r=>r.scanReports.business.site[0].alerts=[alert()]);
for(const category of ['sql_injection','command_injection','xss','path_traversal','ssrf','auth_bypass'])add('confirmed-high-'+category,'confirmed-high',r=>confirmation(r,{category}));
add('confirmed-high-warn-mode-still-fails','confirmed-high',r=>{confirmation(r);r.env.GATE_ZAP='warn';});
for(const pluginid of ['10020','10021','10038','10062'])add('ordinary-information-high-'+pluginid,'unconfirmed-lower',r=>{r.scanReports.business.site[0].alerts=[alert('3',pluginid)];confirmation(r);});
for(const risk of ['0','1','2'])add('lower-risk-'+risk,'unconfirmed-lower',r=>{r.scanReports.business.site[0].alerts=[alert(risk)];confirmation(r);});
add('confidence-is-not-an-additional-block-rule','confirmed-high',r=>{r.scanReports.business.site[0].alerts=[{...alert(),confidence:'0'}];confirmation(r);});
for(const [name,patch]of Object.entries({expired:{expiresAt:'2000-01-01'},badExpiry:{expiresAt:'bad'},image:{targetImage:'other'},report:{reportSha256:'other'},uri:{uri:'http://10.43.0.9:8080/other'},category:{category:'headers'},positive:{positiveValidated:false},negative:{negativeValidated:false},exploit:{exploitConfirmed:false}}))add('unconfirmed-proof-'+name,'unconfirmed-lower',r=>confirmation(r,patch));
add('instance-post-not-a-get-proof','unconfirmed-lower',r=>{r.scanReports.business.site[0].alerts=[alert()];r.scanReports.business.site[0].alerts[0].instances[0].method='POST';confirmation(r);});
add('proof-verification-claim-reset-by-original-gate','proof-validation',r=>{const p=confirmation(r,{evidenceVerified:true});p.evidenceSha256='wrong';});
add('proof-path-outside-reviewed-scope','proof-validation',r=>confirmation(r,{evidencePath:'/other/fixture.json'}));
add('proof-digest-mismatch','proof-validation',r=>confirmation(r).evidenceSha256='wrong');
add('proof-file-missing','proof-validation',r=>{confirmation(r);r.evidenceFiles={};});
add('proof-file-malformed','proof-validation',r=>{const p=confirmation(r);r.evidenceFiles[p.evidencePath]='{';p.evidenceSha256=sha('{');});
for(const key of ['pluginid','targetImage','reportSha256','uri','category','positiveValidated','negativeValidated','exploitConfirmed'])add('proof-file-mismatch-'+key,'proof-validation',r=>{const p=confirmation(r),e=JSON.parse(r.evidenceFiles[p.evidencePath]);e[key]=key.endsWith('Validated')||key==='exploitConfirmed'?false:'other';const bytes=JSON.stringify(e);r.evidenceFiles[p.evidencePath]=bytes;p.evidenceSha256=sha(bytes);});
add('no-visited-business-site','malformed-report',r=>r.scanReports.business={site:[]});
add('no-business-site-field','malformed-report',r=>r.scanReports.business={});
add('business-alerts-absent-is-current-empty','existing-boundary',r=>delete r.scanReports.business.site[0].alerts);
add('confidence-not-rewritten','unconfirmed-lower',r=>r.scanReports.business.site[0].alerts=[{...alert(),confidence:'synthetic-confidence-retained'}]);
for(const risk of ['4','bad','1.5','-1'])add('invalid-risk-'+risk,'malformed-report',r=>r.scanReports.business.site[0].alerts=[alert(risk)]);
add('fixture-positive-high-missing','fixture-validation',r=>r.scanReports.fixture.site[0].alerts=[]);
add('fixture-positive-high-not-unconfirmed','fixture-validation',r=>r.scanReports.fixture.site[0].alerts=[alert('2','10062')]);
add('fixture-confirmed-high-is-rejected-by-original-selftest','fixture-validation',r=>{r.scanReports.fixture.site[0].alerts=[alert()];confirmation(r,{targetImage:'loopback-fixture',reportSha256:'synthetic-fixture'});});
add('clean-fixture-high-10062','fixture-validation',r=>r.scanReports['fixture-negative'].site[0].alerts=[alert('3','10062')]);
add('clean-fixture-other-high-not-new-failure','existing-boundary',r=>r.scanReports['fixture-negative'].site[0].alerts=[alert('3','OTHER-SYNTHETIC')]);
for(const label of ['fixture','fixture-negative','business']){
 add('report-missing-'+label,'missing-report',r=>delete r.scanReports[label]);
 add('report-malformed-'+label,'malformed-report',r=>r.scanReports[label]='{');
 add('report-null-'+label,'malformed-report',r=>r.scanReports[label]='null');
 add('report-read-fails-'+label,'report-read',r=>r.commands['report:'+label]={status:1,stderr:'controlled read error'});
 add('report-whitelist-host-'+label,'target-identity',r=>r.scanReports[label].site[0]['@host']='nonwhitelisted.invalid');
 add('scan-process-error-'+label,'execution-error',r=>r.commands['scan:'+label]={status:1,stderr:'controlled scan/target error'});
 add('scan-timeout-'+label,'timeout',r=>r.commands['scan:'+label]={status:null,error:{code:'ETIMEDOUT'},signal:'SIGTERM'});
 add('scan-tool-missing-'+label,'tool-unavailable',r=>r.commands['scan:'+label]={status:127,stderr:'controlled java/jar unavailable'});
 add('scan-unexpected-warning-exit-'+label,'exit-semantics',r=>r.commands['scan:'+label]={status:2});
 add('session-cleanup-fails-'+label,'cleanup',r=>r.commands['session-rm:/work/'+label+'-home']={status:1,stderr:'controlled cleanup failure'});
 add('session-du-fails-'+label,'cleanup',r=>r.commands['du:/work/'+label+'-home']={status:1});
}
add('manifest-digest-mismatch','prerequisite',r=>r.expectedManifestSha256='wrong');
add('manifest-malformed','prerequisite',r=>{r.manifest='{';r.expectedManifestSha256=sha('{');});
add('lock-malformed','prerequisite',r=>r.lockText='{');
add('lock-supply-chain-missing','prerequisite',r=>r.lockText='{}');
add('foreign-lease','prerequisite',r=>r.lease.spec.holderIdentity='foreign');
add('holder-fallback','prerequisite',r=>{delete r.env.HEAVY_HOLDER;r.lease.spec.holderIdentity='jenkins-petclinic-270';});
add('tool-bytes-changed','tool-unavailable',r=>r.toolFiles['zap/zap-2.17.0.jar']='changed synthetic bytes');
add('tool-file-unavailable','tool-unavailable',r=>delete r.toolFiles['zap/zap-2.17.0.jar']);
add('tool-symlink-changed','tool-unavailable',r=>r.symlinks['zap/current']='other');
add('tool-prefix-other-files-not-checked','existing-boundary',r=>{const m=JSON.parse(r.manifest);m.files.push({path:'other/unused',sha256:'wrong'});r.manifest=JSON.stringify(m);r.expectedManifestSha256=sha(r.manifest);});
add('canary-bad-ip','runtime-network',r=>r.podIp='192.0.2.1');
add('canary-listen-fails','runtime-network',r=>r.canaryListen=false);
add('canary-connect-fails','runtime-network',r=>r.canaryEvents=['error']);
add('canary-connect-timeout','timeout',r=>r.canaryEvents=['timeout']);
add('canary-post-probe-fails','runtime-network',r=>r.canaryEvents=['connect','error']);
add('isolation-does-not-converge','runtime-network',r=>r.isolationExits=[0]);
add('isolation-counter-resets','runtime-network',r=>r.isolationExits=[124,0,1,124]);
add('fixture-readiness-never-recovers','target-readiness',r=>r.readinessExits=[124]);
add('fixture-readiness-eventual-success','target-readiness',r=>r.readinessExits=[1,124,0]);
add('promoted-image-mismatch','target-identity',r=>r.env.K8S_IMAGE='different');
add('promoted-image-not-configured-currently-allowed','existing-boundary',r=>delete r.env.K8S_IMAGE);
add('scan-home-cleanup-disabled-current-path','cleanup',r=>r.env.SECURITY_CLEANUP_SCAN_HOMES='false');
add('finding-mode-invalid','configuration',r=>r.env.GATE_ZAP='typo');
add('finding-mode-default-enforce','configuration',r=>delete r.env.GATE_ZAP);
add('auth-probe-json-malformed','malformed-report',r=>r.authText='{');
add('auth-probe-structure-missing','malformed-report',r=>r.auth={});
add('auth-status-field-not-extra-gate','existing-boundary',r=>r.auth.status='synthetic-failed-field');
add('auth-public-http-status-not-extra-gate','existing-boundary',r=>r.auth.business=[{case:'public-get',status:503}]);
add('cleanup-replacement-uid','cleanup',r=>r.currentUid='replacement');
add('cleanup-never-disappears','cleanup',r=>r.cleanupRemaining=true);
add('canary-close-fails','cleanup',r=>r.canaryCloseError=true);
add('missing-created-uid-originally-skips-delete','existing-boundary',r=>{r.createdUid=null;r.currentUid=null;});
for(const side of ['source','sink']){
 add('transfer-exit-failure-'+side,'transfer',r=>r.transfer[side+'Exit']=1);
 add('transfer-spawn-error-'+side,'transfer',r=>r.transfer[side+'Error']=true);
}
add('transfer-timeout','timeout',r=>r.transfer.timeout=true);
for(const key of ['lease','create','pod-ready','security-probe','isolation-probe','mkdir-work','javac','class-transfer','fixture-start','fixture-ready','auth-probe','fixture-stop','deployment','service','memory-peak','cleanup-pod','delete','cleanup-verify','plan:business'])add('command-error-'+key,key.startsWith('cleanup')||key==='delete'?'cleanup':'execution-error',r=>r.commands[key]={status:3,stderr:'controlled command error'});
add('pod-ready-timeout','timeout',r=>r.commands['pod-ready']={status:null,error:{code:'ETIMEDOUT'}});
add('auth-probe-timeout','timeout',r=>r.commands['auth-probe']={status:null,error:{code:'ETIMEDOUT'}});
add('javac-unavailable','tool-unavailable',r=>r.commands.javac={status:127});
add('memory-peak-exit-one-retained','exit-semantics',r=>r.commands['memory-peak']={status:1,stdout:''});
for(const key of ['read:infra/security/scanner-tools.json','read:infra/security/tools-lock.json','read:.git-sha','read:infra/security/zap-confirmations.json','mkdtemp','copy-auth-source','write:/tmp/zap-controlled/Synthetic.java','read:/tmp/zap-controlled/Synthetic.class','read:/tmp/zap-controlled/ZapAuthProbe.class','write:.devsecops/zap-gate.json#1','write:.devsecops/zap-gate.json#2','write:.devsecops/zap-business-report.json','write:.devsecops/zap-business-report.xml','write:.devsecops/zap-auth-readonly.json','write:.devsecops/zap-fixture-report.json','write:.devsecops/zap-fixture-negative-report.json','write:.devsecops/zap-business-native.json','write:.devsecops/zap-business-plan.json','read:.devsecops/zap-business-native.json','write:.devsecops/zap-business.log','rm:/tmp/zap-controlled'])add('io-'+key,key.startsWith('rm:')?'cleanup':'io-write',r=>r.io[key]='controlled EACCES');
for(const key of ['mkdir:.devsecops#1','mkdir:.devsecops#2'])add('io-'+key,'io-write',r=>r.io[key]='controlled EACCES');
add('confirmations-json-malformed','malformed-report',r=>r.confirmationsText='{');
add('confirmations-schema-invalid','malformed-report',r=>r.confirmations.schema=2);
add('business-finding-and-cleanup-failure','cleanup',r=>{confirmation(r);r.commands.delete={status:1};});
for(const c of cases)test('ZAP complete original runtime + parent: '+c.name,async()=>{
 const input=fixture();c.change(input);const initial=JSON.stringify(input),facts=await replayZapParent(input),before=JSON.stringify(facts),old=facts.execution.exitStatus===0?'PASS':'FAIL';
 const result=evaluate({component:'zap',status:'success',raw:facts},{policyVersion:'baseline-v1',securityLevel:'standard'});
 assert.equal(result.decision,old,c.name+': '+facts.execution.diagnostic);assert.deepEqual(result.rawEvidence,facts);assert.equal(JSON.stringify(input),initial);assert.equal(JSON.stringify(facts),before);
 if(result.normalizedFacts?.classification){const x=facts.classifierInput;assert.deepEqual(result.normalizedFacts.classification,classifyZap(x.report,x.context,x.approved));}
 if(c.branch==='confirmed-high'){assert.equal(old,'FAIL');assert.ok(result.normalizedFacts.classification.blocking.length>0);}
 if(c.branch==='unconfirmed-lower'){assert.equal(old,'PASS');assert.equal(result.normalizedFacts.classification.blocking.length,0);assert.ok(result.normalizedFacts.classification.warnings.length>0);}
 const file=c.name.replace(/[^a-zA-Z0-9_.-]/g,'_')+'.json';fs.writeFileSync(base+'fixtures/'+file,JSON.stringify({input,facts},null,2));
 records.push({name:c.name,branch:c.branch,classification:'CONTROLLED_REPLAY',oldDecision:old,standardDecision:result.decision,rawPreserved:true,inputSha256:sha(initial),rawSha256:sha(before),fixture:file,execution:facts.execution});
});
test('Missing complete parent evidence cannot PASS',()=>{for(const raw of [{},{schema:1,stage:'parent',complete:true,observations:[]}])assert.equal(zapParent(raw).decision,null);});
test('Original four classifier samples remain valid without rewriting their snapshot',()=>{
 const cases=JSON.parse(fs.readFileSync('evidence/2026-11-01/policy-engine/gate-decision-before.json')).cases.filter(c=>c.scope==='frozen'&&c.component==='zap');assert.equal(cases.length,4);
 for(const c of cases){const raw={report:c.input.raw,context:c.input.context,approved:c.input.approved},before=JSON.stringify(raw);assert.equal(evaluate({component:'zap',status:'success',raw}).decision,c.decision);assert.equal(JSON.stringify(raw),before);}
});
test('Disabled/skipped/not_configured remain non-decisions',()=>{for(const status of ['disabled','skipped','not_configured'])assert.equal(evaluate({component:'zap',status,raw:{stage:'parent'}}).decision,null);});
test('Missing or substituted successful native facts are NOT_TESTED',async()=>{
 const original=await replayZapParent(fixture());
 for(const change of [r=>delete r.reports['.devsecops/zap-business-report.json'],r=>r.classifierInput.context.targetImage='other',r=>r.classifierInput.report.site[0].alerts.push(alert())]){
  const raw=structuredClone(original);change(raw);assert.equal(zapParent(raw).status,'NOT_TESTED');assert.equal(zapParent(raw).decision,null);
 }
});
test('Default standard and mandatory complete parent failure floor preserved',async()=>{
 const i=fixture();confirmation(i);const raw=await replayZapParent(i),before=JSON.stringify(raw);assert.equal(evaluate({component:'zap',status:'success',raw}).securityLevel,'standard');
 for(const securityLevel of ['low','standard','strict'])assert.equal(evaluate({component:'zap',status:'success',raw},{securityLevel}).decision,'FAIL');assert.equal(JSON.stringify(raw),before);
});
test.after(()=>fs.writeFileSync(base+'differential.json',JSON.stringify({scope:'Whole unchanged shared scanner runtime and ZAP parent; controlled dependencies, no active scan/network/cluster',records},null,2)));
