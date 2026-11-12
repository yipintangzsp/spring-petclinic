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
