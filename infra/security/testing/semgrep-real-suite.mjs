// Approved disposable source only; fixed tools are never supplied by a project.
import fs from 'node:fs';import path from 'node:path';import assert from 'node:assert/strict';
import {runCandidate} from '../manager-v2/core.mjs';import {registry,realPluginsRegistry} from '../manager-v2/registry.mjs';
import {realExecutionCounts} from '../manager-v2/gitleaks-real.mjs';import {semgrepExecutionCounts} from '../manager-v2/semgrep-real.mjs';
import {verifyArtifact} from '../manager-v2/result.mjs';import {routeResults} from '../manager-v2/router.mjs';import {digest,sha} from '../summary-v2/codec.mjs';
const root=process.argv[2],approvalFile=root+'/approval.json',semgrepApproval=root+'/semgrep-approval.json',a=JSON.parse(fs.readFileSync(semgrepApproval)),out=a.outputRoot;
const runPrefix=process.argv[3]??'';
assert.match(runPrefix,/^(?:attempt[1-9][0-9]*-)?$/);
const sources=Object.fromEntries(a.sources.map(s=>[s.case,s])),records=[];
const count=()=>({gitleaks:realExecutionCounts(),semgrep:semgrepExecutionCounts()});
const allCaps=Object.fromEntries(['SOURCE_DIR','GITLEAKS_TOOL','TRUSTED_VALIDATION_WORKSPACE','SEMGREP_BINARY','SEMGREP_RULESET','OUTPUT_DIR','POLICY_VERSION'].map(k=>[k,{state:'AVAILABLE'}]));
async function run(name,{g=true,s=true,gsource='clean',ssource='clean',master=true,expectedG='PASS',expectedS='PASS',expectedSStatus='COMPLETED',caps=allCaps,semgrepTimeout=null,expectedNativeScans=null,semgrepSourceOverride=null}={}){
 name=runPrefix+name;
 const source=sources[ssource],project=source.projectId,profile=source.profile;
 const config={security:{enabled:master,profile,globalMode:'audit',securityLevel:'standard',policyVersion:'baseline-v1',plugins:Object.fromEntries(registry().ids().map(id=>[id,{enabled:id==='gitleaks'?g:id==='semgrep'?s:false}]))}};
 const gs=sources[gsource],before=count(),dir=path.join(out,name);
 const options={runId:name,projectId:project,config,registry:semgrepTimeout?registry(realPluginsRegistry().all().map(p=>p.pluginId==='semgrep'?{...p,timeout:semgrepTimeout}:p)):realPluginsRegistry(),context:{platform:'linux',capabilities:caps},inputs:{gitleaks:{approvalFile,sourceDir:gs.sourceDir},semgrep:{approvalFile:semgrepApproval,sourceDir:semgrepSourceOverride??source.sourceDir}},output:dir};
 const r=await runCandidate(options),after=count();
 const expected={gitleaks:!master||!g?'DISABLED':'COMPLETED',semgrep:!master||!s?'DISABLED':expectedSStatus};
 const digests={};
 for(const id of ['gitleaks','semgrep']){
  const p=r.gate[id];assert.equal(p.executionStatus,expected[id],name+' '+id+' '+JSON.stringify(p.failureReason));
  const decision=expected[id]==='COMPLETED'?(id==='gitleaks'?expectedG:expectedS):null;
  assert.equal(p.policyDecision,decision,name+' '+id);assert.equal(p.evaluationCount,expected[id]==='COMPLETED'?1:0);
  assert.strictEqual(p,r.summary.pluginResults.find(x=>x.pluginId===id));
  digests[id]=p.resultDigest;
  if(expected[id]==='COMPLETED'){
   assert.equal(r.policyEvaluationCounts[id],1);assert.equal(p.oldGateDecision,p.policyDecision);
   const raw=fs.readFileSync(path.join(dir,id+'.raw.json'),'utf8'),facts=JSON.parse(fs.readFileSync(path.join(dir,id+'.facts.json')));
   assert.equal(sha(raw),p.rawReportDigest);assert.equal(digest(facts),p.factDigest);assert.equal(p.policy.factDigest,p.factDigest);assert.equal(p.runtimeFacts.classification,'REAL_CONTROLLED_EXECUTION');
   if(id==='semgrep'){
    const native=JSON.parse(raw);assert.deepEqual(native.reports,native.nativeReportTexts.map(x=>{assert.equal(sha(x.bytesUtf8),x.sha256);return JSON.parse(x.bytesUtf8);}));
    assert.deepEqual(facts.raw.findings,native.reports.flatMap(x=>x.results));
   }
  }
 }
 assert.equal(after.gitleaks.scans-before.gitleaks.scans,master&&g?1:0);
 assert.equal(after.semgrep.scans-before.semgrep.scans,expectedNativeScans??(master&&s&&['COMPLETED','ERROR'].includes(expectedSStatus)?1:0));
 assert.equal(verifyArtifact(dir,r.artifact.sealDigest),true);assert.equal(verifyArtifact(dir,r.artifact.sealDigest),true);
 assert.equal(r.summary.promotion.status,'BLOCKED');assert.equal(r.summary.productionEvidence,false);
 if(!master||!g&&!s){assert.equal(r.summary.overallStatus,'DISABLED');assert.equal(r.summary.candidateBuildAllowed,true);}
 if(expectedSStatus==='ERROR'&&master&&s){assert.equal(r.summary.overallStatus,'ERROR');assert.equal(r.summary.candidateBuildAllowed,false);assert.equal(fs.existsSync(path.join(dir,'semgrep.execution-error.json')),true);}
 const record={name,classification:'REAL_CONTROLLED_EXECUTION_SUITE',projectId:project,profile,enabled:{master,gitleaks:g,semgrep:s},expected,overallStatus:r.summary.overallStatus,candidateBuildAllowed:r.summary.candidateBuildAllowed,promotion:r.summary.promotion,countsBefore:before,countsAfter:after,policyCounts:r.policyEvaluationCounts,plugins:Object.fromEntries(['gitleaks','semgrep'].map(id=>{const p=r.gate[id];return [id,{executionStatus:p.executionStatus,policyDecision:p.policyDecision,oldGateDecision:p.oldGateDecision??null,rawReportDigest:p.rawReportDigest,factDigest:p.factDigest,resultDigest:p.resultDigest,evaluationCount:p.evaluationCount,failureReason:p.failureReason}]})),sealDigest:r.artifact.sealDigest};
 records.push(record);console.log(JSON.stringify({name,status:'PASS',plugins:record.plugins,countsBefore:before,countsAfter:after}));
 return {r,dir};
}
const securityBoundaryChecks=[];
for(const [name,action]of [
 ['approval-write-denied',()=>fs.writeFileSync(semgrepApproval,'changed')],
 ['rules-write-denied',()=>fs.writeFileSync(root+'/rules.json','changed')],
 ['source-symlink-injection-denied',()=>fs.symlinkSync('/etc/passwd',sources.clean.sourceDir+'/escape')],
 ['docker-socket-denied',()=>fs.accessSync('/run/docker.sock',fs.constants.R_OK)],
 ['admin-kubeconfig-denied',()=>fs.accessSync('/etc/rancher/k3s/k3s.yaml',fs.constants.R_OK)]
]){assert.throws(action);securityBoundaryChecks.push({name,classification:'REAL_CONTROLLED_EXECUTION',status:'PASS'});}
const first=await run('case1-both-clean');
await run('case2-gitleaks-off',{g:false});
await run('case3-semgrep-off',{s:false});
await run('case4-both-off',{g:false,s:false});
await run('case5-semgrep-error',{semgrepTimeout:1,expectedSStatus:'ERROR',expectedS:null,expectedNativeScans:0});
await run('case6-gitleaks-fail',{gsource:'secret',expectedG:'FAIL'});
await run('case7-semgrep-fail',{ssource:'vulnerable',expectedS:'FAIL'});
await run('case8-master-off',{master:false});
await run('cross-container-service',{ssource:'service-clean',gsource:'service-clean'});
await run('warning-classifier-only',{ssource:'warning',expectedS:'WARN'});
await run('missing-semgrep-binary-capability',{caps:{...allCaps,SEMGREP_BINARY:{state:'NOT_CONFIGURED'}},expectedSStatus:'NOT_CONFIGURED',expectedS:null});
await run('python-only-not-supported',{g:false,ssource:'python-only',expectedSStatus:'UNSUPPORTED',expectedS:null});
// Native prefilter selected no rules for this malformed text. It reported no parse
// error; preserve that observation rather than manufacture an error decision.
await run('parser-prefilter-observation',{ssource:'parse-error'});
await run('semgrep-unapproved-source',{semgrepSourceOverride:'/etc',expectedSStatus:'POLICY_ERROR',expectedS:null,expectedNativeScans:0});
const routeOut=path.join(out,runPrefix+'router');fs.mkdirSync(routeOut,{mode:0o700});const beforeRoute=count(),args={run:first.r,artifactDirectory:first.dir,expectedSealDigest:first.r.artifact.sealDigest,output:routeOut};
const delivered=routeResults(args),failed=routeResults(args);
assert.deepEqual(count(),beforeRoute);assert.equal(delivered.receipts[1].deliveryDecision,'DELIVERED_LOCAL_ONLY');assert.equal(failed.receipts[1].deliveryDecision,'ERROR');assert.equal(failed.receipts[0].deliveryDecision,'DRY_RUN');assert.equal(failed.candidateDeliveryAllowed,false);
for(const x of [delivered,failed])for(const receipt of x.receipts)for(const id of ['gitleaks','semgrep'])assert.equal(receipt.resultDigests[id],first.r.gate[id].resultDigest);
fs.writeFileSync(path.join(out,runPrefix+'router-receipts.json'),JSON.stringify({delivered,failed,countsBefore:beforeRoute,countsAfter:count(),policyEvaluationCounts:first.r.policyEvaluationCounts,resultObjectsUnchanged:true},null,2),{flag:'wx',mode:0o400});
assert.equal(fs.readdirSync(out).some(x=>x.startsWith('semgrep-scan-')||x.startsWith('scan-')),false);
fs.writeFileSync(path.join(out,runPrefix+'real-suite.json'),JSON.stringify({classification:'REAL_CONTROLLED_NON_PRODUCTION_EXECUTION_NOT_CANONICAL_RUNTIME',records,securityBoundaryChecks,counts:count(),routerDeliveryTests:2,sourceFixturesExecuted:false,productionDelivery:0,release:0,rollout:0,runtime:'14/16'},null,2),{flag:'wx',mode:0o400});
console.log(JSON.stringify({suite:'PASS',cases:records.length,counts:count(),routerDeliveryTests:2}));
