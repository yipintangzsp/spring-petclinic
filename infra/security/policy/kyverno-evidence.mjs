const absent=reason=>({decision:null,status:'NOT_CONFIGURED',reason});
// Consume observed admission results, never evaluate a workload or an exception.
export function admissionEvidence(raw){
 if(!raw||typeof raw.expectedDenial!=='boolean'||typeof raw.result?.allowed!=='boolean'||typeof raw.result?.diagnostic!=='string')return absent('Observed admission result/expectation absent');
 if(raw.executionError)return {decision:'FAIL',status:'FAIL',reason:'execution error',rawEvidence:structuredClone(raw)};
 const matches=raw.expectedDenial?!raw.result.allowed&&/devsecops-workload-contract|devsecops-production-baseline/.test(raw.result.diagnostic):raw.result.allowed;
 return {decision:matches?'PASS':'FAIL',status:matches?'PASS':'FAIL',admissionDisposition:raw.result.allowed?'ALLOWED':'DENIED',rawEvidence:structuredClone(raw)};
}
// Exact existing rbac-contract.mjs predicates. No privilege inference or new RBAC rules.
export function rbacEvidence(raw){
 if(raw?.executionError)return {decision:'FAIL',status:'FAIL',reason:'execution error'};
 if(!raw?.deployment?.status||!Array.isArray(raw.readChecks)||raw.readChecks.length!==2||!Array.isArray(raw.role?.rules)||!raw.application?.status?.sync||!raw.application?.status?.health)return absent('RBAC raw observations incomplete');
 let ok;try{ok=raw.deployment.status.availableReplicas===1&&raw.readChecks.every(x=>typeof x.value==='string'&&x.value.trim()==='yes')&&raw.role.rules.some(r=>r.apiGroups.includes('apiextensions.k8s.io')&&r.resources.includes('customresourcedefinitions')&&r.verbs.includes('get'))&&raw.application.status.sync.status==='Synced'&&raw.application.status.health.status==='Healthy';}catch{ok=false;}
 return {decision:ok?'PASS':'FAIL',status:ok?'PASS':'FAIL',rawEvidence:structuredClone(raw)};
}
