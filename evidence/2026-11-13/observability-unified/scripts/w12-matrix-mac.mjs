// W12 phase-3 (Mac side): Loki direct query (127.0.0.1:32189) + view read-path checks.
import fs from 'node:fs';import http from 'node:http';
import {getRun,recentRuns} from '../../../../infra/security/manager-v2/view/actions.mjs';
import {withExistingLokiChannel} from '../../../../infra/security/manager-v2/view/loki-delivery.mjs';
export const REFS={
 'gitleaks':{runId:'web-bfcb08f9-e841-4972-8ecc-858355719a83',decision:'PASS',source:'view-run record (newest REAL gitleaks view run; no recent verification.json)'},
 'semgrep':{runId:'web-d623a7b0-ced1-42a4-b0a4-7075f44d8db2',decision:'PASS',source:'view-run record (newest REAL semgrep view run)'},
 'cosign':{runId:'web-d6a525de-e630-4520-a300-12d313957078',decision:'PASS',source:'view-run record (newest REAL cosign view run)'},
 'sbom':{runId:'web-b52dbc8e-b584-4c0d-ad53-1c01ce116ddf',decision:'PASS',source:'view-run record (newest REAL sbom view run)'},
 'trivy':{runId:'web-7f2fc057-5d21-44c2-9144-ee398a8b8c33',decision:'FAIL',resultDigest:'cba4ba0363afc0f73dfa611bfe99dc5719ffbb16c8c7d8710de3737550851ee5',source:'item-6b auto-delivery run (trivy-observability-final lineage)'},
 'kyverno':{runId:'web-699261a0-ac5a-4aca-a8ff-6a8031429049',decision:'PASS',resultDigest:'9d30d4c9c048',source:'kyverno-v2 verification.json signed case'},
 'falco':{runId:'web-falco-gf2-pos2',decision:'PASS',resultDigest:'1047cce3b3241c9c',source:'falco-gf2 verification.json positiveRun'},
 'sonarqube':{runId:'web-caf26080-d320-438a-beb5-b61170c9d3e1',decision:'PASS',resultDigest:'e2c623c47a8f4ad3f5f490cb92758a3b4b689986e15d03c98b522b4d45a5bd67',source:'sonarqube-v2 verification.json clean-scan'},
 'kubescape':{runId:'web-c7f969a0-8748-4117-ae3b-d6d429e7202a',decision:'PASS',resultDigest:'8f8c3470f1cf',source:'kubescape-v2 verification.json cluster-audit'},
 'zap':{runId:'web-6e277bfd-e875-407e-92b8-6fe9be8bdbcd',decision:'PASS',resultDigest:'0800f06bdff6',source:'zap-v2 verification.json clean'},
 'provenance':{runId:'web-e8a79056-0b07-4f3b-8073-6d050952bbea',decision:'PASS',resultDigest:'eb700a542373',source:'provenance-v2 verification.json historical-candidate'},
 'build-provenance':{runId:'web-8973a0d3-7d2f-48d7-95ba-b99933b0dc7d',decision:'PASS',resultDigest:'3cfb365db85d',source:'build-provenance-v2 verification.json historical-build'},
 'sops':{runId:'web-0ec63caa-60db-4ad6-b8d8-3cc00695f3db',decision:'PASS',resultDigest:'ef8ab10dcac9',source:'sops-v2 verification.json compliant'},
};
function lokiDirect(runId){
 return new Promise(resolve=>{
  const q=`{service_name="security-manager-v2",environment="validation",schema_version="1",job="devsecops-security-v2"} | json | runId="${runId}"`;
  const end=BigInt(Date.now())*1000000n,start=end-BigInt(8*24*3600)*1000000000n;
  const path='/loki/api/v1/query_range?'+new URLSearchParams({query:q,start:String(start),end:String(end),limit:'50'});
  const req=http.get({hostname:'127.0.0.1',port:32189,path,timeout:20000},res=>{const c=[];res.on('data',x=>c.push(x));res.on('end',()=>{let matched=0,ev=null;try{const d=JSON.parse(Buffer.concat(c).toString());for(const s of d?.data?.result??[]){matched+=s.values?.length??0;const v=s.values?.[0]?.[1];if(v&&!ev)ev=JSON.parse(v);}}catch{}resolve({httpStatus:res.statusCode,matched,eventIdentity:ev?.eventIdentity??null,resultDigest:ev?.resultDigest??null,policyDecision:ev?.policyDecision??null,pluginId:ev?.pluginId??null});});});
  req.on('timeout',()=>req.destroy(Error('TIMEOUT')));req.on('error',e=>resolve({error:e.message,matched:0}));
 });
}
const out={lokiDirect:{},webView:{}};
await withExistingLokiChannel(async()=>{
 for(const [pid,ref] of Object.entries(REFS)){
  out.lokiDirect[pid]={refRunId:ref.runId,...await lokiDirect(ref.runId)};
  console.log('LOKI',pid,out.lokiDirect[pid].matched,out.lokiDirect[pid].policyDecision??out.lokiDirect[pid].error??'');
 }
});
// web view: reference run if it is a view run; plus W12 view-driver clean runs for wired plugins
const driverRuns={};
for(const k of ['kyverno','sonarqube','kubescape','zap','provenance','build-provenance','sops']){
 try{const d=JSON.parse(fs.readFileSync(new URL(`../raw/view-driver-${k}.json`,import.meta.url)));driverRuns[k]=d.runs.clean;}catch{}
}
let allView=[];try{allView=recentRuns();}catch(e){out.webViewError=e.message;}
for(const [pid,ref] of Object.entries(REFS)){
 const inView=allView.find(r=>r.runId===ref.runId);
 const drv=driverRuns[pid];
 const alt=!inView&&drv?(()=>{try{const r=getRun(drv.runId);return {runId:r.runId,state:r.state,policyDecision:r.policyDecision,via:'w12-view-driver-run'};}catch(e){return {error:e.message,via:'w12-view-driver-run'};}})():null;
 const legacyNewest=!inView&&!alt?(()=>{const c=allView.filter(r=>r.pluginId===pid&&r.evidenceClass==='REAL'&&r.state==='COMPLETED').sort((a,b)=>String(b.completedAt).localeCompare(String(a.completedAt)))[0];return c?{runId:c.runId,state:c.state,policyDecision:c.policyDecision,via:'newest-view-run-of-plugin'}:null;})():null;
 out.webView[pid]={refRunVisible:!!inView,refRunPolicy:inView?.policyDecision??null,check:alt??legacyNewest??(inView?{runId:inView.runId,state:inView.state,policyDecision:inView.policyDecision,via:'reference-run'}:null)};
 console.log('VIEW',pid,JSON.stringify(out.webView[pid]));
}
fs.writeFileSync(new URL('../raw/matrix-mac.json',import.meta.url),JSON.stringify(out,null,2)+'\n');
console.log('MATRIX_MAC_DONE');
