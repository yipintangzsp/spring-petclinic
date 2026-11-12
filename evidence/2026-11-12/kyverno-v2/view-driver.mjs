import fs from 'node:fs';import path from 'node:path';
import {capabilities,submit,getRun} from '../../../infra/security/manager-v2/view/actions.mjs';
import {currentControls,writeControls} from '../../../infra/security/manager-v2/view/controls.mjs';
const root=path.resolve(new URL('../../../',import.meta.url).pathname);
const evDir=path.join(root,'evidence/2026-11-12/kyverno-v2/raw');
const sleep=ms=>new Promise(r=>setTimeout(r,ms));
const out={};
const cap=capabilities();out.capability=cap.plugins.find(p=>p.pluginId==='kyverno');console.log('CAP',JSON.stringify(out.capability));
async function runAndWait(value){
 const q=submit(value);console.log('SUBMIT',value.pluginId,value.scenarioId,q.runId);
 for(let i=0;i<200;i++){await sleep(600);let r;try{r=getRun(q.runId);}catch{continue;}if(!['QUEUED','RUNNING'].includes(r.state))return r;}
 throw Error('POLL_TIMEOUT');
}
const clean=await runAndWait({pluginId:'kyverno',projectId:'kyverno-supply-chain',scenarioId:'clean'});
out.clean={runId:clean.runId,state:clean.state,policyDecision:clean.policyDecision,evaluationCount:clean.evaluationCount,evidenceClass:clean.evidenceClass,allowed:clean.allowed,caseId:clean.caseId,resultDigest:clean.resultDigest,lokiDelivery:clean.lokiDelivery?{state:clean.lokiDelivery.state,queryState:clean.lokiDelivery.queryState}:null};
console.log('CLEAN',JSON.stringify(out.clean));
const finding=await runAndWait({pluginId:'kyverno',projectId:'kyverno-supply-chain',scenarioId:'controlled-finding'});
out.finding={runId:finding.runId,state:finding.state,policyDecision:finding.policyDecision,evaluationCount:finding.evaluationCount,evidenceClass:finding.evidenceClass,allowed:finding.allowed,caseId:finding.caseId,resultDigest:finding.resultDigest,lokiDelivery:finding.lokiDelivery?{state:finding.lokiDelivery.state,queryState:finding.lokiDelivery.queryState}:null};
console.log('FINDING',JSON.stringify(out.finding));
// Switch OFF via the management controls, verify DISABLED with zero evaluation, then restore.
const before=currentControls();
const offSettings=structuredClone(before.settings);offSettings.plugins.kyverno.enabled=false;
writeControls({revision:before.revision,settings:offSettings});
const capOff=capabilities();out.capabilityOff=capOff.plugins.find(p=>p.pluginId==='kyverno');console.log('CAP_OFF',JSON.stringify(out.capabilityOff));
const disabled=await runAndWait({pluginId:'kyverno',projectId:'kyverno-supply-chain',scenarioId:'clean'});
out.disabled={runId:disabled.runId,state:disabled.state,evaluationCount:disabled.evaluationCount,policyDecision:disabled.policyDecision,scannerExecuted:disabled.scannerExecuted};
console.log('DISABLED',JSON.stringify(out.disabled));
const mid=currentControls();writeControls({revision:mid.revision,settings:before.settings});
const capOn=capabilities();out.capabilityRestored=capOn.plugins.find(p=>p.pluginId==='kyverno');console.log('CAP_RESTORED',JSON.stringify(out.capabilityRestored));
fs.writeFileSync(path.join(evDir,'view-driver-summary.json'),JSON.stringify(out,null,2)+'\n');
console.log('VIEW_DRIVER_DONE');
