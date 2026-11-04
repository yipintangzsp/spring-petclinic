import test from 'node:test';import assert from 'node:assert/strict';
import {BUILTINS,registry,capabilityCheck as check} from './registry.mjs';
test('B duplicate/unknown IDs rejected; removal does not rewrite others',()=>{assert.throws(()=>registry([BUILTINS[0],BUILTINS[0]]),/duplicate/);assert.throws(()=>registry().get('x'),/unknown/);const r=registry(BUILTINS.filter(p=>p.pluginId!=='trivy'));assert.deepEqual(r.get('semgrep'),registry().get('semgrep'));});
test('B arbitrary runner code is not a registration contract',()=>{assert.throws(()=>registry([{...BUILTINS[0],runner:()=>{throw Error('never');}}]),/untrusted/);});
test('C capabilities are scoped; Trivy never executes even with asserted prerequisites',()=>{
 const r=registry(),c={platform:'linux',capabilities:{SECURITY_REPORTS:{state:'AVAILABLE'}}};
 assert.equal(check(r.get('gitleaks'),c,'java-web').executionStatus,'READY');assert.equal(check(r.get('trivy'),c,'java-web').executionStatus,'NOT_CONFIGURED');
 for(const k of r.get('trivy').requiredCapabilities)c.capabilities[k]={state:'AVAILABLE'};
 assert.equal(check(r.get('trivy'),c,'java-web').executionStatus,'NOT_CONFIGURED');
});
test('C missing/unavailable/platform/profile are distinct',()=>{const p=registry().get('semgrep');assert.equal(check(p,{platform:'linux'},'java-web').executionStatus,'NOT_CONFIGURED');assert.equal(check(p,{platform:'linux',capabilities:{SECURITY_REPORTS:{state:'UNAVAILABLE'}}},'java-web').executionStatus,'UNSUPPORTED');assert.equal(check(p,{platform:'win32'},'java-web').executionStatus,'UNSUPPORTED');assert.equal(check({...p,supportedProfiles:['iac']},{platform:'linux'},'java-web').executionStatus,'SKIPPED');});
