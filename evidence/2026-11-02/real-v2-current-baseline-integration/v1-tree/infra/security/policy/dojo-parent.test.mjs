import test from 'node:test';import assert from 'node:assert/strict';import fs from 'node:fs';import vm from 'node:vm';
import {dojoFrozenIO} from './dojo-frozen-io.mjs';import {evaluateAsync} from './engine.mjs';
const out='evidence/2026-11-01/dojo-parent/',archive=JSON.parse(fs.readFileSync('evidence/2026-11-01/remaining-policy/archived-270.json')).reports,receipt=archive['defectdojo-import.json'];
const source=fs.readFileSync('infra/security/governance/defectdojo.mjs','utf8').replace(/^import .*;\s*$/gm,'');
const records=[];
function fixture(){
 const src=receipt.source,target={baseUrl:'https://dojo-fixture.invalid',product:receipt.product,engagement:receipt.engagement};
 const files={'.git-sha':src,'infra/security/governance/dojo-target.json':target,'.devsecops/gitleaks-native.json':[],'.devsecops/semgrep-native.json':{},'.devsecops/zap-business-report.xml':'<fixture/>','.devsecops/source-gate.json':{status:'success',sourceScan:{verifiedFalsePositives:[]}}};
 const digests=receipt.imports.filter(x=>x.scanType==='Harbor Vulnerability Scan').map(x=>x.title.match(/sha256:[a-f0-9]+/)[0]);
 files['.devsecops/trivy-audit.json']={status:'success',runtimeImage:receipt.runtimeImage,auditTargetImage:receipt.auditTargetImage,targetScope:receipt.targetScope,scans:digests.map(digest=>({digest,scan:{scan_status:'Success'},raw:{fixture:'not-scanner-evidence'}}))};
 const scans=archive['kubescape-gate.json'].scans.map(s=>({scope:s.scope,framework:s.framework,reportFile:s.reportFile}));
 files['.devsecops/kubescape-gate.json']={status:'success',source:src,scans};for(const s of scans)files[s.reportFile]={fixture:'not-native-scanner-evidence'};
 const tests=receipt.imports.map(x=>({id:x.testId,title:x.title}));
 return {classification:'SYNTHETIC_COMPLETE_STAGE_WITH_HISTORICAL_RECEIPT_IDENTITIES',target,files,credentials:{dojo:true,sonar:true},build:270,api:{},tests,findingsByTest:Object.fromEntries(tests.map(t=>[t.id,[{id:t.id*100,active:true,severity:'High'}]])),productFindings:[{id:11,active:true,severity:'High'},{id:12,active:true,severity:'High',duplicate:true}],sonar:{paging:{total:0},issues:[]}};
}
async function oldGate(raw){
 const io=dojoFrozenIO(raw);
 const context=vm.createContext({fs:io.fs,DojoClient:io.Client,governanceCounts:io.counts,fetch:io.fetch,Buffer,JSON,AbortSignal,process:{env:{BUILD_NUMBER:String(raw.build),DEFECTDOJO_TOKEN:raw.credentials.dojo?'FIXTURE':undefined,SONAR_TOKEN:raw.credentials.sonar?'FIXTURE':undefined}},console:{log:()=>{}}});
 try{await vm.runInContext('(async()=>{'+source+'})()',context);return {decision:'PASS',report:JSON.parse(io.files['.devsecops/defectdojo-import.json']),requests:io.requests};}
 catch(error){return {decision:'FAIL',reason:error.message,requests:io.requests};}
}
function run(name,change,expected,branch){test('Dojo complete acceptance '+name,async()=>{
 const raw=fixture();change(raw);const before=JSON.stringify(raw),old=await oldGate(raw),p=await evaluateAsync({component:'defectdojo',status:'success',raw},{policyVersion:'baseline-v1',securityLevel:'standard'});
 assert.equal(old.decision,expected,old.reason);assert.equal(p.decision,old.decision,p.reason);assert.equal(JSON.stringify(raw),before);assert.deepEqual(p.rawEvidence,raw);
 assert.deepEqual(p.requests,old.requests);
 if(p.decision==='PASS'){assert.deepEqual(JSON.parse(JSON.stringify(p.imports)),old.report.imports);assert.deepEqual(JSON.parse(JSON.stringify(p.counts)),old.report.counts);assert.deepEqual(JSON.parse(JSON.stringify(p.reviewedFalsePositives)),old.report.reviewedFalsePositives);}
 records.push({name,branch,classification:raw.classification,oldDecision:old.decision,standardDecision:p.decision,rawPreserved:true,imports:p.imports.length,legacyReason:old.reason,policyReason:p.reason,requests:old.requests});
});}
run('existing-tests-stable-dedupe',()=>{},'PASS','import-query-dedupe');
run('create-tests-first-import',r=>r.tests=[],'PASS','import-query-dedupe');
run('object-test-identity',r=>r.api.objectIdentity=true,'PASS','import-query-dedupe');
run('identity-fallback-existing-list',r=>r.api.identityFromList=true,'PASS','import-query-dedupe');
run('zero-findings-queryable',r=>{r.findingsByTest={};r.productFindings=[];},'PASS','existing-limitation');
run('vulnerabilities-do-not-fail-governance',r=>r.productFindings.push({id:99,active:true,severity:'Critical'}),'PASS','governance-not-scanner');
run('completed-upstream-finding-failure-still-imports',r=>{r.files['.devsecops/trivy-audit.json'].status='failed';r.files['.devsecops/trivy-audit.json'].failures=[{id:'fixture'}];},'PASS','upstream-acceptance');
run('source-finding-failure-still-imports',r=>r.files['.devsecops/source-gate.json']={status:'failed',sourceScan:{blockingFindings:[{}]}},'PASS','upstream-acceptance');
function withProof(r,already=false){const id=r.tests[0].id;const f={id:123,file_path:'/fixture/source',line:7,description:'**Rule Id:** fixture-rule',active:!already,false_p:already,severity:'High'};r.findingsByTest[id]=[f];r.files['.devsecops/source-gate.json'].sourceScan.verifiedFalsePositives=[{file:f.file_path,line:f.line,rule:'fixture-rule',line_sha256:'a'.repeat(64),reason:'synthetic reviewed fixture'}];}
run('reviewed-false-positive-synchronized',r=>withProof(r),'PASS','review-binding');
run('reviewed-false-positive-already-set',r=>withProof(r,true),'PASS','review-binding');
run('source-newline-normalization',r=>r.files['.git-sha']+='\n','PASS','identity');
const failure=(path,status=403,method='GET',extra={})=>({path,status,method,...extra});
for(const [name,change]of [
 ['missing-dojo-credential',r=>r.credentials.dojo=false],['missing-sonar-credential',r=>r.credentials.sonar=false],
 ['product-auth-failure',r=>r.api.failures=[failure('/api/v2/products/')]],['API-unavailable-after-retries',r=>r.api.failures=[failure('/api/v2/products/',503)]],
 ['API-transport-unavailable',r=>r.api.failures=[{path:'/api/v2/products/',method:'GET',errorName:'TypeError'}]],
 ['import-auth-failure',r=>{r.tests=[];r.api.failures=[failure('/api/v2/import-scan/',401,'POST')];}],
 ['import-gateway-not-retried',r=>{r.tests=[];r.api.failures=[failure('/api/v2/import-scan/',503,'POST')];}],
 ['reimport-rejected',r=>r.api.failures=[failure('/api/v2/reimport-scan/',400,'POST')]],
 ['import-response-malformed',r=>r.api.failures=[failure('/api/v2/reimport-scan/',200,'POST',{invalidJson:true})]],
 ['no-test-identity',r=>{r.tests=[];r.api.noTestIdentity=true;}],
 ['ambiguous-existing-tests',r=>r.tests.push({...r.tests[0],id:999})],
 ['query-back-unavailable',r=>r.api.failures=[failure('/api/v2/findings/?limit=200&test=',503)]],
 ['query-malformed-JSON',r=>r.api.failures=[failure('/api/v2/findings/?limit=200&test=',200,'GET',{invalidJson:true})]],
 ['query-malformed-collection',r=>r.api.failures=[failure('/api/v2/findings/?limit=200&test=',200,'GET',{body:{results:'bad'}})]],
 ['dedupe-ID-change',r=>r.api.dedupeChanges=true],
 ['external-pagination',r=>r.api.externalPagination=true],['unbounded-pagination',r=>r.api.unboundedPagination=true],
 ['sonar-export-unavailable',r=>r.api.failures=[failure('/api/issues/search',503)]],
 ['sonar-export-incomplete',r=>r.sonar={paging:{total:3},issues:[]}],
 ['trivy-report-missing',r=>delete r.files['.devsecops/trivy-audit.json']],
 ['trivy-report-malformed',r=>r.files['.devsecops/trivy-audit.json']='{'],
 ['trivy-report-incomplete',r=>r.files['.devsecops/trivy-audit.json'].scans=[]],
 ['trivy-engine-failure',r=>r.files['.devsecops/trivy-audit.json'].scans[0].scan.scan_status='Error'],
 ['trivy-unproven-status',r=>r.files['.devsecops/trivy-audit.json'].status='failed'],
 ['upstream-report-source-mismatch',r=>r.files['.devsecops/kubescape-gate.json'].source='other'],
 ['upstream-four-report-contract',r=>r.files['.devsecops/kubescape-gate.json'].scans.pop()],
 ['native-report-missing',r=>delete r.files['.devsecops/zap-business-report.xml']],
 ['native-report-unreadable',r=>r.files['.devsecops/gitleaks-native.json']={readError:true}],
 ['native-report-oversize',r=>r.files['.devsecops/gitleaks-native.json']={virtualLength:100*1024*1024+1}],
 ['source-proof-incomplete',r=>r.files['.devsecops/source-gate.json']={status:'failed'}],
 ['FP-patch-auth-failure',r=>{withProof(r);r.api.failures=[failure('/api/v2/findings/123/',403,'PATCH')];}],
 ['final-query-unavailable',r=>r.api.failures=[failure('test__engagement__product=',503)]],
 ['report-write-failure',r=>r.writeErrorPaths=['defectdojo-import.json']],
 ['intermediate-report-write-failure',r=>r.writeErrorPaths=['governance/trivy-']],
 ['source-read-failure',r=>delete r.files['.git-sha']],['output-dir-failure',r=>r.mkdirError=true]
 ])run(name,change,'FAIL','execution-report-query-identity');
run('GET-transient-retry-recovers',r=>r.api.failures=[failure('/api/v2/products/',503,'GET',{until:2})],'PASS','retry');
run('PATCH-transient-retry-recovers',r=>{withProof(r);r.api.failures=[failure('/api/v2/findings/123/',502,'PATCH',{until:2})];},'PASS','retry');
run('wrong-rule-proof-not-used',r=>{withProof(r);r.files['.devsecops/source-gate.json'].sourceScan.verifiedFalsePositives[0].rule='other';},'PASS','review-binding');
run('wrong-source-location-proof-not-used',r=>{withProof(r);r.files['.devsecops/source-gate.json'].sourceScan.verifiedFalsePositives[0].file='other';},'PASS','review-binding');
run('invalid-line-hash-proof-not-used',r=>{withProof(r);r.files['.devsecops/source-gate.json'].sourceScan.verifiedFalsePositives[0].line_sha256='bad';},'PASS','review-binding');
for(const [name,change]of [
 ['target-config-missing',r=>delete r.files['infra/security/governance/dojo-target.json']],
 ['target-config-malformed',r=>r.files['infra/security/governance/dojo-target.json']='{'],
 ['upstream-native-raw-missing',r=>delete r.files['.devsecops/trivy-audit.json'].scans[0].raw],
 ['upstream-status-unsuccessful',r=>r.files['.devsecops/kubescape-gate.json'].status='failed'],
 ['native-XML-missing',r=>delete r.files['.devsecops/zap-business-report.xml']],
 ['test-list-malformed-collection',r=>r.api.failures=[failure('/api/v2/tests/',200,'GET',{body:{results:null}})]],
 ['test-list-JSON-invalid',r=>r.api.failures=[failure('/api/v2/tests/',200,'GET',{invalidJson:true})]],
 ['product-JSON-invalid',r=>r.api.failures=[failure('/api/v2/products/',200,'GET',{invalidJson:true})]],
 ['sonar-JSON-invalid',r=>r.api.failures=[failure('/api/issues/search',200,'GET',{invalidJson:true})]],
 ['null-import-response',r=>r.api.failures=[failure('/api/v2/reimport-scan/',204,'POST')]],
 ['null-final-query-response',r=>r.api.failures=[failure('test__engagement__product=',204)]],
 ['review-proof-source-malformed',r=>r.files['.devsecops/source-gate.json']='{'],
 ['query-back-auth-failure',r=>r.api.failures=[failure('/api/v2/findings/?limit=200&test=',401)]],
 ])run(name,change,'FAIL','remaining-error');
run('finding-ID-order-does-not-change-set',r=>{for(const k of Object.keys(r.findingsByTest))r.findingsByTest[k]=[{id:999,active:true,severity:'Low'},...r.findingsByTest[k]];},'PASS','dedupe');
run('title-fallback-reviewed-binding',r=>{withProof(r);const f=r.findingsByTest[r.tests[0].id][0];delete f.file_path;f.title='fixture found in /fixture/source';},'PASS','review-binding');
run('line-mismatch-proof-not-used',r=>{withProof(r);r.files['.devsecops/source-gate.json'].sourceScan.verifiedFalsePositives[0].line=8;},'PASS','review-binding');
test('missing complete facts never PASS',async()=>assert.equal((await evaluateAsync({component:'defectdojo',status:'success',raw:{}})).decision,null));
test.after(()=>fs.writeFileSync(out+'differential.json',JSON.stringify({scope:'Full unchanged Gate and actual frozen client validators; all HTTP/writes in memory',records},null,2)));
