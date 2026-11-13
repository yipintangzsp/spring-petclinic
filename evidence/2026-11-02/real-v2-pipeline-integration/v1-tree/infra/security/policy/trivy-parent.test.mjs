import test from 'node:test';import assert from 'node:assert/strict';import fs from 'node:fs';
import {evaluate} from './engine.mjs';import {trivyParent} from './trivy-parent.mjs';import {classifyVulnerability} from '../trivy-medium-policy.mjs';
import {trivyCounts} from '../governance/scan-counts.mjs';
import {replayTrivy} from './trivy-parent-replay.mjs';import {base,fixture,findings,vulnerability,sha,child} from './trivy-parent-fixtures.mjs';
fs.mkdirSync(base+'fixtures',{recursive:true});const records=[],cases=[];
const add=(name,branch,change=()=>{},stage='parent')=>cases.push({name,branch,change,stage});
add('zero-findings','positive');
for(const severity of ['Critical','High','Medium','Low','Unknown'])add('severity-'+severity,'vulnerability',r=>findings(r,[vulnerability(severity)]));
const medium=vulnerability('Medium'),confirmed={id:medium.id,package:medium.package,version:medium.version,mustFix:true,fixVersion:'2.0',reachability:'confirmed',evidence:{positive:'controlled positive',negative:'controlled negative',businessPath:'controlled path'}};
add('confirmed-reachable-fixable-medium','vulnerability',r=>findings(r,[medium],[confirmed]));
for(const [name,edit]of [['unconfirmed',e=>e.reachability='unconfirmed'],['no-fix',e=>e.fixVersion=''],['no-positive',e=>delete e.evidence.positive],['no-negative',e=>delete e.evidence.negative],['no-business-path',e=>delete e.evidence.businessPath],['not-mustfix',e=>e.mustFix=false],['wrong-package',e=>e.package='changed'],['wrong-version',e=>e.version='changed']])add('medium-'+name,'vulnerability',r=>{const e=structuredClone(confirmed);edit(e);findings(r,[medium],[e]);});
add('wrong-review-image-no-invented-block','identity',r=>{findings(r,[medium],[confirmed]);const review=JSON.parse(r.review);review.image='different';r.review=JSON.stringify(review);});
add('warn-env-does-not-weaken-critical','vulnerability',r=>{r.env.GATE_TRIVY='warn';findings(r,[vulnerability('Critical')]);});
add('constructed-counts-M108-L8-not-historical','vulnerability',r=>{r.root.references=[];findings(r,[...Array.from({length:108},(_,i)=>({...medium,id:'SYNTHETIC-M-'+i})),...Array.from({length:8},(_,i)=>({...vulnerability('Low'),id:'SYNTHETIC-L-'+i}))]);});
add('no-candidate-audits-live','identity',r=>r.env.AUDIT_CANDIDATE_IMAGE='');
add('candidate-tag-forbidden','identity',r=>r.env.AUDIT_CANDIDATE_IMAGE='core.harbor.domain/petclinic/petclinic:latest');
add('candidate-other-repository-forbidden','identity',r=>r.env.AUDIT_CANDIDATE_IMAGE=r.env.AUDIT_CANDIDATE_IMAGE.replace('/petclinic/petclinic','/other/repo'));
add('live-tag-not-pinned','identity',r=>{r.env.AUDIT_CANDIDATE_IMAGE='';r.deployment.spec.template.spec.containers[0].image='runtime:tag';});
add('live-other-repository-pinned-currently-allowed','existing-boundary',r=>{r.env.AUDIT_CANDIDATE_IMAGE='';r.deployment.spec.template.spec.containers[0].image='other/repo@'+r.expectedDigest;});
add('candidate-does-not-require-runtime-digest-match','existing-boundary',r=>r.deployment.spec.template.spec.containers[0].image='runtime:tag');
add('index-without-children-scans-index','architecture',r=>r.root.references=[]);
add('single-recognized-architecture-allowed','architecture',r=>r.root.references=r.root.references.slice(0,1));
add('unknown-architecture-ignored','architecture',r=>r.root.references.push({child_digest:'unknown',platform:{architecture:'unknown'}}));
add('duplicate-architecture-not-rejected','existing-boundary',r=>r.root.references[1].platform.architecture='amd64');
add('returned-report-identity-not-revalidated','existing-boundary',r=>r.defaultNative={unrelated:{artifact:'different',vulnerabilities:[]}});
add('runtime-maps-read-error-retained','existing-boundary',r=>r.commands['runtime-maps']={status:1});
add('unready-pod-skipped','runtime',r=>r.pods[0].status.containerStatuses[0].ready=false);
add('brotli-runtime-and-sbom-facts-retained','runtime',r=>{r.maps='000-001 r-xp /usr/lib/libbrotli.so';r.sbom='{"components":[{"name":"brotli","version":"1"}]}';});
add('review-expiration-is-metadata-not-new-fail','existing-boundary',r=>{const d=JSON.parse(r.review);d.reviewAfter='2020-01-01';r.review=JSON.stringify(d);});
add('native-empty-object-current-pass','existing-boundary',r=>r.defaultNative={});
add('native-vulnerabilities-null-current-pass','existing-boundary',r=>r.defaultNative={report:{vulnerabilities:null}});
add('missing-finding-severity-remains-raw-warn','existing-boundary',r=>findings(r,[{id:'SYNTHETIC-unrated'}]));
for(const key of ['candidate-exists','candidate-source','candidate-alias','candidate-verified','root','scan:'+child[0],'overview:'+child[0],'report:'+child[0]]){
 add('http-forbidden-'+key,'registry',r=>{if(key.startsWith('candidate-')&&key!=='candidate-exists')r.http['candidate-exists']={status:404,json:{}};r.http[key]={status:403,json:{}};});
}
add('candidate-copy-complete','candidate-copy',r=>r.http['candidate-exists']={status:404,json:{}});
add('candidate-copy-error-field-with-zero-status-currently-ignored','existing-boundary',r=>{r.http['candidate-exists']={status:404,json:{}};r.commands['candidate-copy']={status:0,error:'controlled unused error field'};});
add('missing-audit-credentials-delegated-to-harbor','prerequisite',r=>{delete r.env.HARBOR_USER;delete r.env.HARBOR_PASS;});
add('candidate-initial-lookup-transient-recovers','transport',r=>r.http['http:candidate-exists#1']={status:503,json:{}});
add('candidate-initial-lookup-transient-exhausted','transport',r=>r.http['candidate-exists']={status:503,json:{}});
add('candidate-source-digest-mismatch','identity',r=>{r.http['candidate-exists']={status:404,json:{}};r.http['candidate-source']={status:200,bytes:'different-index'};});
add('candidate-copy-fails-short-circuit','candidate-copy',r=>{r.http['candidate-exists']={status:404,json:{}};r.commands['candidate-copy']={status:1};});
add('candidate-copy-timeout-short-circuit','timeout',r=>{r.http['candidate-exists']={status:404,json:{}};r.commands['candidate-copy']={status:null,error:'ETIMEDOUT'};});
add('candidate-build-identity-missing','prerequisite',r=>{r.http['candidate-exists']={status:404,json:{}};delete r.env.BUILD_NUMBER;});
for(const status of ['Error','Stopped','Pending'])add('scan-state-'+status,status==='Pending'?'timeout':'execution-error',r=>r.scanSummary.scan_status=status);
add('scan-state-missing-timeout','timeout',r=>r.scanSummary={});
add('scan-state-pending-then-success','execution',r=>r.http['http:overview:'+child[0]+'#1']={status:200,json:{scan_overview:{trivy:{scan_status:'Pending'}}}});
add('second-architecture-critical-blocks','vulnerability',r=>r.nativeReports[child[1]]={report:{vulnerabilities:[vulnerability('Critical')]}});
add('second-architecture-report-missing','missing-report',r=>r.http['report:'+child[1]]={status:404,json:{}});
add('second-architecture-engine-error','execution-error',r=>r.http['overview:'+child[1]]={status:200,json:{scan_overview:{trivy:{scan_status:'Error'}}}});
add('first-overview-entry-is-authoritative-currently','existing-boundary',r=>r.http['overview:'+child[0]]={status:200,json:{scan_overview:{first:{scan_status:'Error'},second:{scan_status:'Success'}}}});
add('review-unused-for-high-can-be-null','existing-boundary',r=>{findings(r,[vulnerability('High')]);r.review='null';});
add('medium-review-null-current-error','malformed-report',r=>{findings(r,[vulnerability('Medium')]);r.review='null';});
add('reviewed-fixed-version-does-not-compare-native-fix-currently','vulnerability',r=>findings(r,[{...medium,fix_version:''}],[confirmed]));
add('scan-conflict-409-accepted','execution',r=>r.http['scan:'+child[0]]={status:409,json:{}});
add('report-409-still-parsed-currently','existing-boundary',r=>r.http['report:'+child[0]]={status:409,json:r.defaultNative});
for(const status of [408,429,502,503,504]){
 add('transient-'+status+'-recovers','transport',r=>r.http['http:root#1']={status,json:{}});
 add('persistent-'+status+'-fails','transport',r=>r.http.root={status,json:{}});
}
for(const name of ['TypeError','TimeoutError','AbortError','Error'])add('transport-'+name,name==='TimeoutError'?'timeout':name==='AbortError'?'transport-abort':'transport-error',r=>r.http.root={error:{name,message:'controlled network failure'}});
for(const key of ['root','overview:'+child[0],'report:'+child[0]]){
 add('json-parse-error-'+key,'malformed-report',r=>r.http[key]={status:200,jsonError:true});
 add('json-null-'+key,'malformed-report',r=>r.http[key]={status:200,json:null});
}
add('report-404','missing-report',r=>r.http['report:'+child[0]]={status:404,json:{}});
add('report-empty-http-body','missing-report',r=>r.http['report:'+child[0]]={status:200,jsonError:true});
add('invalid-vulnerabilities-object','malformed-report',r=>r.defaultNative={report:{vulnerabilities:{}}});
add('null-native-entry','malformed-report',r=>r.defaultNative={report:null});
add('sbom-malformed','malformed-report',r=>r.sbom='{');
add('sbom-components-missing','malformed-report',r=>r.sbom='{}');
add('review-malformed','malformed-report',r=>r.review='{');
add('review-entries-invalid-with-medium','malformed-report',r=>{findings(r,[medium]);const review=JSON.parse(r.review);review.entries=null;r.review=JSON.stringify(review);});
for(const key of ['deployment','pods']){add('command-unavailable-'+key,'execution-error',r=>r.commands[key]={status:1,error:'controlled missing kubectl'});add('command-malformed-'+key,'malformed-report',r=>r.commands[key]={stdout:'{'});}
for(const key of ['mkdir:.devsecops','read:.devsecops/sbom.json','read:infra/security/trivy-medium-review.json','write:.devsecops/trivy-audit.json'])add('io-'+key,'io-write',r=>r.io[key]='controlled EACCES');
// Original release scan-health parent is distinct from the vulnerability classification Gate.
add('release-health-success','release-scan',()=>{},'release-scan');
for(const key of ['root','scan:'+child[0],'overview:'+child[0]])add('release-http-forbidden-'+key,'release-registry',r=>r.http[key]={status:403,json:{}},'release-scan');
add('release-transient-root-recovers','release-registry',r=>r.http['http:root#1']={status:503,json:{}},'release-scan');
add('release-scan-conflict-accepted','release-scan',r=>r.http['scan:'+child[0]]={status:409,json:{}},'release-scan');
add('release-second-architecture-error','release-scan',r=>r.http['overview:'+child[1]]={status:200,json:{scan_overview:{trivy:{scan_status:'Error'}}}},'release-scan');
add('release-transport-exhausted','release-registry',r=>r.http.root={error:{name:'TypeError'}},'release-scan');
add('release-completed-scan-with-critical-count-still-current-pass','existing-boundary',r=>r.scanSummary.summary.Critical=1,'release-scan');
for(const [name,edit]of [['credentials',r=>delete r.env.HARBOR_PASS],['tag',r=>r.env.IMAGE_TAG='latest'],['digest',r=>r.expectedDigest='sha256:'+'f'.repeat(64)],['one-arch',r=>r.root.references.pop()],['three-arch',r=>r.root.references.push(r.root.references[0])],['engine-error',r=>r.scanSummary.scan_status='Error'],['engine-stopped',r=>r.scanSummary.scan_status='Stopped'],['timeout',r=>r.scanSummary.scan_status='Pending'],['missing-overview',r=>r.scanSummary={}],['report-write',r=>r.io['write:target/platform/harbor.json']='EACCES'],['digest-file-read',r=>r.io['read:target/platform/image-digest.txt']='ENOENT']])add('release-'+name,'release-scan',edit,'release-scan');
for(const c of cases)test('Trivy whole original production stage: '+c.name,async()=>{
 const input=fixture();c.change(input);const initial=JSON.stringify(input),facts=await replayTrivy(input,c.stage),before=JSON.stringify(facts);
 const old=(facts.stage==='parent'?facts.operations.every(x=>x.execution.exitStatus===0):facts.execution.exitStatus===0)?'PASS':'FAIL';
 const result=evaluate({component:'trivy',status:'success',raw:facts},{policyVersion:'baseline-v1',securityLevel:'standard'});
 assert.equal(result.decision,old,JSON.stringify(facts.stage==='parent'?facts.operations.map(x=>x.execution):facts.execution));assert.deepEqual(result.rawEvidence,facts);assert.equal(JSON.stringify(facts),before);assert.equal(JSON.stringify(input),initial);
 if(result.normalizedFacts?.classifications){const op=facts.operations.find(x=>x.classifierInput);assert.deepEqual(result.normalizedFacts.classifications,op.classifierInput.findings.map(v=>classifyVulnerability(v,op.classifierInput.review,op.classifierInput.image)));}
 if(c.name==='constructed-counts-M108-L8-not-historical'){const report=JSON.parse(facts.operations[1].reports['.devsecops/trivy-audit.json']);assert.deepEqual(trivyCounts(report),{trivy_critical:0,trivy_high:0,trivy_medium:108,trivy_low:8});}
 const file=c.name.replace(/[^a-zA-Z0-9_.-]/g,'_')+'.json';fs.writeFileSync(base+'fixtures/'+file,JSON.stringify({input,facts},null,2));records.push({name:c.name,stage:c.stage,branch:c.branch,classification:'CONTROLLED_REPLAY',oldDecision:old,standardDecision:result.decision,rawPreserved:true,fixture:file,inputSha256:sha(initial),rawSha256:sha(before)});
});
test('Missing complete parent facts is NOT_TESTED, not PASS',()=>{for(const raw of [{},{schema:1,stage:'parent',complete:true,operations:[]}])assert.equal(trivyParent(raw).decision,null);});
test('Original eight classifier samples preserved and still identical',()=>{
 const original=JSON.parse(fs.readFileSync('evidence/2026-11-01/policy-engine/gate-decision-before.json')).cases.filter(c=>c.scope==='frozen'&&c.component==='trivy');assert.equal(original.length,8);
 for(const c of original){const raw={findings:[c.input.finding],review:c.input.review,image:c.input.image},before=JSON.stringify(raw);assert.equal(evaluate({component:'trivy',status:'success',raw}).decision,c.decision);assert.equal(JSON.stringify(raw),before);}
});
test('Disabled/skipped/not_configured remain non-decisions',()=>{for(const status of ['disabled','skipped','not_configured'])assert.equal(evaluate({component:'trivy',status,raw:{stage:'parent'}}).decision,null);});
test('A claimed success without its original report is NOT_TESTED',()=>{assert.equal(trivyParent({schema:1,stage:'release-scan',complete:true,execution:{exitStatus:0},observations:[]}).decision,null);assert.equal(trivyParent({schema:1,stage:'database-prerequisite',complete:true,execution:{exitStatus:0},observations:[]}).decision,null);});
test('Default standard and mandatory parent floor preserved under all levels',async()=>{
 const input=fixture();findings(input,[vulnerability('High')]);const raw=await replayTrivy(input),before=JSON.stringify(raw);
 assert.equal(evaluate({component:'trivy',status:'success',raw}).securityLevel,'standard');
 for(const securityLevel of ['low','standard','strict'])assert.equal(evaluate({component:'trivy',status:'success',raw},{securityLevel}).decision,'FAIL');
 assert.equal(JSON.stringify(raw),before);
});
test('Classifier input cannot replace original report/image facts',async()=>{
 const original=await replayTrivy(fixture());
 for(const change of [r=>r.operations[1].classifierInput.findings.push(vulnerability('High')),r=>r.operations[1].classifierInput.image='different']){
  const raw=structuredClone(original);change(raw);const before=JSON.stringify(raw);assert.equal(trivyParent(raw).status,'NOT_TESTED');assert.equal(trivyParent(raw).decision,null);assert.equal(JSON.stringify(raw),before);
 }
});
test.after(()=>fs.writeFileSync(base+'differential.json',JSON.stringify({records},null,2)));
