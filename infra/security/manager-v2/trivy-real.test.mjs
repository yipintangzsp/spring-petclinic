import test from 'node:test';import assert from 'node:assert/strict';import {trivySshTarget} from './trivy-real.mjs';
test('configured verified host',()=>assert.equal(trivySshTarget({}),'security-trivy@192.168.1.58'));
test('explicit verified host',()=>assert.equal(trivySshTarget({TRIVY_SSH_HOST:'192.168.1.58'}),'security-trivy@192.168.1.58'));
test('reject stale host and SSH injection',()=>{for(const host of ['192.168.64.11','-oProxyCommand=x','other-host',''])assert.throws(()=>trivySshTarget({TRIVY_SSH_HOST:host}),/NOT_AUTHORIZED/);});

import {normalizeTrivySeverity,buildTrivyFindings,buildTrivyFact,trivyProjects} from './trivy-real.mjs';
import {policyOwner} from './result.mjs';
import {configuration} from './config.mjs';
test('native severities normalize to canonical Policy values',()=>{
 assert.equal(normalizeTrivySeverity('CRITICAL'),'Critical');
 assert.equal(normalizeTrivySeverity('HIGH'),'High');
 assert.equal(normalizeTrivySeverity('MEDIUM'),'Medium');
 assert.equal(normalizeTrivySeverity('LOW'),'Low');
 // UNKNOWN has no scanner rating; it must land in the lowest rated bucket.
 assert.equal(normalizeTrivySeverity('UNKNOWN'),'Low');
});
test('unrecognized or missing severity fails closed before Policy',()=>{
 for(const bad of ['SEVERE','High','high','',undefined,null])assert.throws(()=>normalizeTrivySeverity(bad),/RUNNER_REPORT_ERROR/);
 assert.throws(()=>buildTrivyFindings({Results:[{Vulnerabilities:[{VulnerabilityID:'X',Severity:'SEVERE'}]}]}),/RUNNER_REPORT_ERROR/);
 assert.throws(()=>buildTrivyFindings({Results:[{Vulnerabilities:[{VulnerabilityID:'X'}]}]}),/RUNNER_REPORT_ERROR/);
 assert.deepEqual(buildTrivyFindings({Results:[{Vulnerabilities:null},{}]}),[]);
 assert.throws(()=>buildTrivyFindings({Results:[{Vulnerabilities:'bad'}]}),/RUNNER_REPORT_ERROR/);
});
// Real entries copied from the 2026-11-12 offline native Trivy report
// (devops data/offline-stale-20261112/native.json); CRITICAL/LOW/UNKNOWN rows
// are synthetic additions covering the remaining native severity values.
const nativeReport={Results:[{Vulnerabilities:[
 {VulnerabilityID:'CVE-2026-68494',PkgName:'com.fasterxml.jackson.core:jackson-core',InstalledVersion:'2.17.2',Severity:'HIGH',FixedVersion:'2.18.8, 2.21.4'},
 {VulnerabilityID:'CVE-2026-18401',PkgName:'com.fasterxml.jackson.core:jackson-core',InstalledVersion:'2.17.2',Severity:'MEDIUM',FixedVersion:'2.21.1, 2.18.6'},
 {VulnerabilityID:'SYNTHETIC-CRITICAL',PkgName:'example/pkg',InstalledVersion:'1.0.0',Severity:'CRITICAL',FixedVersion:'1.0.1'},
 {VulnerabilityID:'SYNTHETIC-LOW',PkgName:'example/pkg',InstalledVersion:'1.0.0',Severity:'LOW'},
 {VulnerabilityID:'SYNTHETIC-UNKNOWN',PkgName:'example/pkg',InstalledVersion:'1.0.0',Severity:'UNKNOWN'}
]}]};
test('formal adapter fact passes the real Policy engine without invalid severity',async()=>{
 const project=trivyProjects()['trivy-candidate'];
 const fact=buildTrivyFact({rawReport:nativeReport},project);
 assert.deepEqual(fact.raw.findings.map(f=>f.severity),['High','Medium','Critical','Low','Low']);
 const owner=policyOwner(configuration({},'trivy-formal-path'));
 const result=await owner.evaluateOnce('trivy',fact);
 assert.equal(result.evaluationCount,1);
 assert.equal(result.evaluation.decision,'FAIL');
 assert.equal(result.evaluation.status,'FAIL');
});
test('formal adapter fact with only low-rated findings warns at every level',async()=>{
 const project=trivyProjects()['trivy-candidate'];
 const lowReport={Results:[{Vulnerabilities:[
  {VulnerabilityID:'SYNTHETIC-LOW',PkgName:'example/pkg',InstalledVersion:'1.0.0',Severity:'LOW'},
  {VulnerabilityID:'SYNTHETIC-UNKNOWN',PkgName:'example/pkg',InstalledVersion:'1.0.0',Severity:'UNKNOWN'}]}]};
 const fact=buildTrivyFact({rawReport:lowReport},project);
 for(const level of ['low','standard','strict']){
  const result=await policyOwner(configuration({security:{securityLevel:level}},'trivy-low-'+level)).evaluateOnce('trivy',fact);
  assert.equal(result.evaluation.decision,'WARN');
 }
 const critical=buildTrivyFact({rawReport:{Results:[{Vulnerabilities:[{VulnerabilityID:'SYNTHETIC-CRITICAL',PkgName:'example/pkg',InstalledVersion:'1.0.0',Severity:'CRITICAL',FixedVersion:'1.0.1'}]}]}},project);
 const lowLevel=await policyOwner(configuration({security:{securityLevel:'low'}},'trivy-critical-low')).evaluateOnce('trivy',critical);
 assert.equal(lowLevel.evaluation.decision,'FAIL');
});

import {legacyGateFields,sealResult,verifyResult} from './result.mjs';
import {digest} from '../summary-v2/codec.mjs';
test('formal result seals with a Policy decision when the runner has no legacy gate',async()=>{
 const project=trivyProjects()['trivy-candidate'];
 const fact=buildTrivyFact({rawReport:nativeReport},project);
 const config=configuration({},'trivy-formal-seal');
 const policy=await policyOwner(config).evaluateOnce('trivy',fact);
 assert.equal(policy.evaluation.decision,'FAIL');
 // executeRealTrivy returns runtimeFacts and no oldDecision (no legacy Gate).
 const execution={fact,factDigest:digest(fact),rawReportDigest:'a'.repeat(64),runtimeFacts:{kind:'CandidateRuntimeFactsProbe'},evidenceRefs:[{kind:'REAL_CONTROLLED_EXECUTION'}],cleanup:{status:'VERIFIED',processExited:true},executionScope:'REAL_NON_PRODUCTION_IMAGE_SCAN'};
 assert.deepEqual(legacyGateFields(execution),{runtimeFacts:execution.runtimeFacts});
 assert.deepEqual(legacyGateFields({...execution,oldDecision:'FAIL'}),{runtimeFacts:execution.runtimeFacts,oldGateDecision:'FAIL'});
 assert.deepEqual(legacyGateFields({}),{});
 const body={schemaVersion:1,kind:'CandidatePluginResult',managerVersion:'test',securityEnabled:true,effectiveProfile:config.profile,globalMode:config.globalMode,securityLevel:config.securityLevel,runId:'run-seal',projectId:'trivy-candidate',pluginId:'trivy',pluginVersion:'test',executionScope:execution.executionScope,startedAt:new Date().toISOString(),inputDigest:'a'.repeat(64),configDigest:config.configDigest,effectiveConfigDigest:config.effectiveConfigDigest,contextDigest:'b'.repeat(64),policyVersion:config.policyVersion,executionStatus:'COMPLETED',policyDecision:policy.evaluation.decision,evaluationCount:1,policy,rawReportDigest:execution.rawReportDigest,factDigest:execution.factDigest,evidenceRefs:execution.evidenceRefs,failureReason:null,completedAt:new Date().toISOString(),cleanup:execution.cleanup,...legacyGateFields(execution)};
 const sealed=sealResult(body);
 assert.equal(sealed.policyDecision,'FAIL');
 assert.equal('oldGateDecision' in sealed,false);
 assert.equal(verifyResult(sealed),true);
 // The codec still fails closed on a genuinely non-JSON field value.
 assert.throws(()=>sealResult({...body,oldGateDecision:undefined}),/non-JSON value/);
});

import {buildTrivyRuntimeFacts,buildTrivyEvidenceRefs} from './trivy-real.mjs';
test('runner runtime facts carry validationRunId for the Loki fresh gate',()=>{
 const runId='web-00000000-1111-4222-8333-444444444444';
 // Shape of the restricted entry packet as consumed by executeRealTrivy:
 // it carries runId but no validationRunId (the 6b field-contract defect).
 const packet={kind:'RestrictedLinuxTrivy',projectId:'trivy-candidate',runId,uid:1000,gid:1000,groups:[1000],noNewPrivs:true,indexDigest:'sha256:'+'a'.repeat(64),platformDigest:'sha256:'+'b'.repeat(64),toolVersion:'0.76.2',exitCode:0,rawReport:{Results:[]},rawReportSha256:'c'.repeat(64),nativeReportSha256:'d'.repeat(64),findingCount:0,completedAt:new Date().toISOString()};
 const facts=buildTrivyRuntimeFacts(packet,runId);
 assert.equal(facts.validationRunId,runId);
 assert.equal(facts.runId,runId);
 assert.equal(facts.classification,'REAL_CONTROLLED_EXECUTION');
 assert.equal('rawReport' in facts,false);
 // Exactly the predicate prepareLoki applies to fresh runs (consumers/loki.mjs):
 // classification REAL_CONTROLLED_EXECUTION and validationRunId===freshRunId.
 assert.equal(facts.classification==='REAL_CONTROLLED_EXECUTION'&&facts.validationRunId===runId,true);
 const project=trivyProjects()['trivy-candidate'];
 const refs=buildTrivyEvidenceRefs(packet,project,runId);
 assert.equal(refs.length,1);
 assert.equal(refs[0].validationRunId,runId);
 assert.equal(refs[0].runId,runId);
 assert.equal(refs[0].indexDigest,project.indexDigest);
 assert.equal(refs[0].platformDigest,project.platformDigest);
 assert.equal(refs[0].nativeReportSha256,packet.nativeReportSha256);
});
