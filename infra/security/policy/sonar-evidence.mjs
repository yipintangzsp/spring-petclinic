const fail=message=>{throw Error('POLICY_ERROR: Sonar '+message);};
// Consume Sonar's authoritative decision. Never evaluate comparator/threshold locally.
export function sonarEvidence(raw){
 const task=raw?.task?.task,gate=raw?.gate?.projectStatus,binding=raw?.binding;
 if(!task||!gate||!binding||typeof binding.projectKey!=='string'||!binding.projectKey||
  task.componentKey!==binding.projectKey||typeof task.id!=='string'||task.id!==binding.taskId||
  typeof task.analysisId!=='string'||!task.analysisId||task.analysisId!==binding.requestedAnalysisId||task.status!=='SUCCESS')
  fail('task/project/analysis binding incomplete or mismatched');
 if(!['OK','ERROR'].includes(gate.status))fail('unsupported or missing authoritative Gate status');
 if(!Array.isArray(gate.conditions))fail('condition list missing');
 for(const condition of gate.conditions){
  if(typeof condition.metricKey!=='string'||!condition.metricKey||!['OK','ERROR','NO_VALUE'].includes(condition.status)||
   typeof condition.comparator!=='string'||typeof condition.errorThreshold!=='string'||typeof condition.actualValue!=='string')
   fail('condition details incomplete');
 }
 return {component:'sonarqube',status:'success',projectKey:task.componentKey,taskId:task.id,analysisId:task.analysisId,
  authoritativeStatus:gate.status,conditions:structuredClone(gate.conditions),rawEvidence:structuredClone(raw)};
}
export function sonarDecision(raw){
 const evidence=sonarEvidence(raw);
 return {decision:evidence.authoritativeStatus==='OK'?'PASS':'FAIL',evidence};
}
