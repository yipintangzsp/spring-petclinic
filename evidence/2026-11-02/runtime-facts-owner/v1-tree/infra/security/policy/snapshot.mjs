// Run before changing gates. Pure historical decision capture; never invokes scanners.
import fs from 'node:fs';
import crypto from 'node:crypto';
import {classifySemgrep} from '../semgrep-policy.mjs';
import {classifyVulnerability} from '../trivy-medium-policy.mjs';
import {classifyZap} from '../zap-policy.mjs';
const cases=[];
for(const rule of ['java-http-runtime-exec','java-http-process-builder','java-weak-cipher','unknown'])for(const severity of ['ERROR','WARNING']){
 const f={check_id:rule,extra:{severity}},r=classifySemgrep([f]);cases.push({component:'semgrep',scope:'frozen',input:{findings:[f]},decision:r.blocking.length?'FAIL':r.warnings.length?'WARN':'PASS'});
}
for(const severity of ['Critical','High','Medium','Low'])for(const confirmed of [false,true]){
 const v={id:'test',package:'pkg',version:'1',severity},review={image:'digest-fixture',entries:confirmed?[{...v,mustFix:true,reachability:'confirmed',fixVersion:'2',evidence:{positive:true,negative:true,businessPath:true}}]:[]};
 cases.push({component:'trivy',scope:'frozen',input:{finding:v,review,image:'digest-fixture'},decision:classifyVulnerability(v,review,'digest-fixture').mode});
}
for(const riskcode of ['0','1','2','3']){
 const raw={site:[{alerts:[{pluginid:'test',riskcode,instances:[]}]}]},r=classifyZap(raw,{}, {schema:1,confirmations:[]});
 cases.push({component:'zap',scope:'frozen',input:{raw,context:{},approved:{schema:1,confirmations:[]}},decision:r.blocking.length?'FAIL':r.warnings.length?'WARN':'PASS'});
}
for(const component of ['gitleaks','semgrep','trivy','sonarqube','kubescape','zap','sbom','cosign','defectdojo'])for(const mode of ['audit','enforce'])for(const findings of [0,1])for(const blocking of [0,1]){
 if(blocking>findings)continue;
 cases.push({component,scope:'generic',mode,input:{findings,blocking},decision:blocking?'FAIL':findings&&mode==='audit'?'WARN':'PASS'});
 // Audit transforms ordinary finding failures to WARN, not operational failures.
 if(mode==='audit')cases.at(-1).decision=findings?'WARN':'PASS';
}
const paths=['vars/securityManager.groovy','infra/security/manager/tool.mjs','infra/security/semgrep-policy.mjs','infra/security/trivy-medium-policy.mjs','infra/security/zap-policy.mjs','infra/security/runtime/event-policy.mjs'];
const hashes=Object.fromEntries(paths.map(p=>[p,crypto.createHash('sha256').update(fs.readFileSync(p)).digest('hex')]));
fs.writeFileSync('evidence/2026-11-01/policy-engine/gate-decision-before.json',JSON.stringify({scope:'Pure classifier and generic exit semantics; not complete production gate coverage',hashes,cases},null,2));
console.log('Captured',cases.length,'decisions before implementation');
