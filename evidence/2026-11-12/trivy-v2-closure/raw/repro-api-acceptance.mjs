import {accessCredentials} from '/Users/zhangsir/code/petclinic-platform-20261011/infra/security/manager-v2/view/project-access.mjs';
const base='http://127.0.0.1:17862';
const auth='Bearer '+accessCredentials().operatorToken;
const plugins=await (await fetch(base+'/api/plugins')).json();
const csrf=plugins.csrfToken;
const trivyCap=plugins.plugins.find(p=>p.pluginId==='trivy');
console.log('CAPABILITY',JSON.stringify(trivyCap));
const H={'Content-Type':'application/json','X-CSRF-Token':csrf,Origin:base,Authorization:auth};
const getConfig=async()=>await (await fetch(base+'/api/config',{headers:{Authorization:auth}})).json();
let cfg=await getConfig();
console.log('CONFIG revision',cfg.revision,'trivy',JSON.stringify(cfg.settings.plugins.trivy),'pluginKeys',Object.keys(cfg.settings.plugins).join(','));
async function save(settings,revision){const r=await fetch(base+'/api/config',{method:'POST',headers:H,body:JSON.stringify({revision,settings})});const v=await r.json();if(!r.ok)throw Error('SAVE_FAILED '+JSON.stringify(v));return v;}
async function runTrivy(){
 const r=await fetch(base+'/api/run',{method:'POST',headers:H,body:JSON.stringify({pluginId:'trivy',projectId:'trivy-candidate',scenarioId:'clean'})});
 const v=await r.json();if(!r.ok)throw Error('RUN_FAILED '+JSON.stringify(v));
 for(let i=0;i<40;i++){const s=await (await fetch(base+'/api/runs/'+v.runId,{headers:{Authorization:auth}})).json();if(!['QUEUED','RUNNING'].includes(s.state))return s;await new Promise(x=>setTimeout(x,500));}
 throw Error('RUN_POLL_TIMEOUT');
}
// 1) switch OFF -> capability DISABLED + run DISABLED without execution
let off=structuredClone(cfg.settings);off.plugins.trivy.enabled=false;
cfg=await save(off,cfg.revision);
const capsOff=await (await fetch(base+'/api/plugins')).json();
console.log('AFTER_OFF capability',JSON.stringify(capsOff.plugins.find(p=>p.pluginId==='trivy')));
const runOff=await runTrivy();
console.log('RUN_OFF',JSON.stringify({runId:runOff.runId,state:runOff.state,reason:runOff.reason,scannerExecuted:runOff.scannerExecuted,evaluationCount:runOff.evaluationCount,policyDecision:runOff.policyDecision}));
// 2) switch ON (executor not armed) -> capability BLOCKED with precise reason + run BLOCKED
let on=structuredClone(cfg.settings);on.plugins.trivy.enabled=true;
cfg=await save(on,cfg.revision);
const capsOn=await (await fetch(base+'/api/plugins')).json();
console.log('AFTER_ON capability',JSON.stringify(capsOn.plugins.find(p=>p.pluginId==='trivy')));
const runOn=await runTrivy();
console.log('RUN_ON',JSON.stringify({runId:runOn.runId,state:runOn.state,reason:runOn.reason,scannerExecuted:runOn.scannerExecuted,evaluationCount:runOn.evaluationCount,policyDecision:runOn.policyDecision}));
console.log('FINAL revision',cfg.revision,'trivyEnabled',cfg.settings.plugins.trivy.enabled);
