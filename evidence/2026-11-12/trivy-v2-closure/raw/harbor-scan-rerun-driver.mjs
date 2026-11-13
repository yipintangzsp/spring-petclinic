import {accessCredentials} from '/Users/zhangsir/code/petclinic-platform-20261011/infra/security/manager-v2/view/project-access.mjs';
import fs from 'node:fs';
const base='http://127.0.0.1:17862';
const auth='Bearer '+accessCredentials().operatorToken;
const plugins=await (await fetch(base+'/api/plugins')).json();
console.log('CAPABILITY_ARMED',JSON.stringify(plugins.plugins.find(p=>p.pluginId==='trivy')));
const H={'Content-Type':'application/json','X-CSRF-Token':plugins.csrfToken,Origin:base,Authorization:auth};
const r=await fetch(base+'/api/run',{method:'POST',headers:H,body:JSON.stringify({pluginId:'trivy',projectId:'trivy-candidate',scenarioId:'clean'})});
const v=await r.json();if(!r.ok)throw Error('RUN_FAILED '+JSON.stringify(v));
console.log('SUBMITTED',v.runId);
let last='';
for(let i=0;i<900;i++){const s=await (await fetch(base+'/api/runs/'+v.runId,{headers:{Authorization:auth}})).json();
 if(s.state!==last){console.log('STATE',s.state,s.reason||'');last=s.state;}
 if(!['QUEUED','RUNNING'].includes(s.state)){fs.writeFileSync('/tmp/rerun-run.json',JSON.stringify(s,null,1));console.log('RUN_RESULT',JSON.stringify({runId:s.runId,state:s.state,reason:s.reason,evidenceClass:s.evidenceClass,scannerExecuted:s.scannerExecuted,scannerStarted:s.scannerStarted,findingCount:s.findingCount,policyDecision:s.policyDecision,evaluationCount:s.evaluationCount,executionDiagnostic:s.executionDiagnostic,router:s.router,artifactDigest:s.artifactDigest,resultDigest:s.resultDigest,cleanup:s.cleanup,executionLocation:s.executionLocation},null,1));break;}
 await new Promise(x=>setTimeout(x,1000));}
