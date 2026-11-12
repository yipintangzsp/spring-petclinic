// W12 generic view-driver: process-internal import of view/actions.
// Usage: node w12-view-driver.mjs <pluginKey> <outJson>
import fs from 'node:fs';import path from 'node:path';
import {capabilities,submit,getRun} from '../../../../infra/security/manager-v2/view/actions.mjs';
import {currentControls,writeControls} from '../../../../infra/security/manager-v2/view/controls.mjs';
const CFG={
 'kyverno':{project:'kyverno-supply-chain',a:['clean','PASS'],b:['controlled-finding','FAIL'],polls:160,extra:r=>r.allowed===true,extraB:r=>r.allowed===false},
 'sonarqube':{project:'sonarqube-petclinic',a:['clean','PASS'],b:['controlled-finding','FAIL'],polls:200,extra:r=>r.gateStatus==='OK',extraB:r=>r.gateStatus==='ERROR'},
 'kubescape':{project:'kubescape-petclinic',a:['clean','PASS'],b:['controlled-finding','PASS'],polls:1200,extra:r=>Number(r.findings)>0&&!r.violating,extraB:r=>!!r.violating&&Number(r.findings)>0},
 'zap':{project:'zap-lab',a:['clean','PASS'],b:['controlled-finding','FAIL'],polls:240,extra:r=>r.alertsTotal===0,extraB:r=>Number(r.alertsTotal)>=1},
 'provenance':{project:'petclinic-platform',a:['verified','PASS'],b:['rejected','FAIL'],polls:80,extra:r=>!!r.envelopeSha256,extraB:r=>!!r.envelopeSha256},
 'build-provenance':{project:'petclinic-platform',a:['verified','PASS'],b:['rejected','FAIL'],polls:80,extra:r=>!!r.envelopeSha256,extraB:r=>!!r.envelopeSha256},
 'sops':{project:'sops-lab',a:['clean','PASS'],b:['controlled-finding','FAIL'],polls:160,extra:r=>r.storeModel==='FILE_FIXTURE_STORE',extraB:r=>r.storeModel==='FILE_FIXTURE_STORE'},
};
const key=process.argv[2],outFile=process.argv[3],cfg=CFG[key];
const pid=key;
const sleep=ms=>new Promise(r=>setTimeout(r,ms));
const out={plugin:pid,checks:[],runs:{}};
const check=(name,ok,detail)=>{out.checks.push({name,ok,detail});console.log(ok?'PASS':'FAIL',name,JSON.stringify(detail));if(!ok)out.failed=true;};
async function runAndWait(value){
 const q=submit(value);console.log('SUBMIT',value.pluginId,value.scenarioId,q.runId);
 for(let i=0;i<cfg.polls;i++){await sleep(1500);let r;try{r=getRun(q.runId);}catch{continue;}if(!['QUEUED','RUNNING'].includes(r.state))return r;}
 throw Error('POLL_TIMEOUT');
}
const cap=capabilities();const capP=cap.plugins.find(p=>p.pluginId===pid);out.capability=capP;
check('capability-ready',capP?.state==='READY',capP);
const findingOnly=process.argv[4]==='finding-only';
const clean=findingOnly?null:await runAndWait({pluginId:pid,projectId:cfg.project,scenarioId:cfg.a[0]});
if(clean){out.runs.clean={runId:clean.runId,state:clean.state,policyDecision:clean.policyDecision,evaluationCount:clean.evaluationCount,evidenceClass:clean.evidenceClass,caseId:clean.caseId,resultDigest:clean.resultDigest,artifactDigest:clean.artifactDigest,allowed:clean.allowed??null,gateStatus:clean.gateStatus??null,violating:clean.violating??null,findings:clean.findings??null,auditDisposition:clean.auditDisposition??null,alertsTotal:clean.alertsTotal??null,storeModel:clean.storeModel??null,envelopeSha256:clean.envelopeSha256??null,lokiDelivery:clean.lokiDelivery?{state:clean.lokiDelivery.state,queryState:clean.lokiDelivery.queryState}:null};
check('clean-result',clean.state==='COMPLETED'&&clean.policyDecision===cfg.a[1]&&clean.evaluationCount===1&&cfg.extra(clean),out.runs.clean);}
const finding=await runAndWait({pluginId:pid,projectId:cfg.project,scenarioId:cfg.b[0]});
out.runs.finding={runId:finding.runId,state:finding.state,policyDecision:finding.policyDecision,evaluationCount:finding.evaluationCount,evidenceClass:finding.evidenceClass,caseId:finding.caseId,resultDigest:finding.resultDigest,artifactDigest:finding.artifactDigest,allowed:finding.allowed??null,gateStatus:finding.gateStatus??null,violating:finding.violating??null,findings:finding.findings??null,auditDisposition:finding.auditDisposition??null,alertsTotal:finding.alertsTotal??null,storeModel:finding.storeModel??null,envelopeSha256:finding.envelopeSha256??null,lokiDelivery:finding.lokiDelivery?{state:finding.lokiDelivery.state,queryState:finding.lokiDelivery.queryState}:null};
check('finding-result',finding.state==='COMPLETED'&&finding.policyDecision===cfg.b[1]&&finding.evaluationCount===1&&cfg.extraB(finding),out.runs.finding);
if(findingOnly){fs.writeFileSync(outFile,JSON.stringify(out,null,2)+'\n');console.log(out.failed?'VIEW_DRIVER_FAILED':'VIEW_DRIVER_DONE',pid,'finding-only');process.exit(out.failed?1:0);}
const before=currentControls();
try{
 const offSettings=structuredClone(before.settings);offSettings.plugins[pid].enabled=false;
 writeControls({revision:before.revision,settings:offSettings});
 const capOff=capabilities().plugins.find(p=>p.pluginId===pid);out.capabilityOff=capOff;
 check('capability-off-disabled',capOff?.state==='DISABLED',capOff);
 const disabled=await runAndWait({pluginId:pid,projectId:cfg.project,scenarioId:cfg.a[0]});
 out.runs.disabled={runId:disabled.runId,state:disabled.state,evaluationCount:disabled.evaluationCount,policyDecision:disabled.policyDecision,scannerExecuted:disabled.scannerExecuted};
 check('disabled-zero-exec',disabled.state==='DISABLED'&&disabled.evaluationCount===0&&disabled.scannerExecuted===false,out.runs.disabled);
}finally{
 const mid=currentControls();writeControls({revision:mid.revision,settings:before.settings});
}
const capOn=capabilities().plugins.find(p=>p.pluginId===pid);out.capabilityRestored=capOn;
check('capability-restored',capOn?.state==='READY',capOn);
fs.writeFileSync(outFile,JSON.stringify(out,null,2)+'\n');
console.log(out.failed?'VIEW_DRIVER_FAILED':'VIEW_DRIVER_DONE',pid);
process.exit(out.failed?1:0);
