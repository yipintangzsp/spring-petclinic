// Read existing CE task and exact analysis only. Never starts analysis, invokes
// Policy, or rebinds a historical analysis to the current source/candidate.
import fs from 'node:fs';import {pathToFileURL} from 'node:url';
export async function observeExistingSonar({origin,token,request=fetch}){
 const record={classification:'REAL_READ_ONLY_EXISTING_ANALYSIS_OBSERVATION',credentialRef:'sonar-token',origin,requests:[],policyEvaluations:0,newAnalysis:0};
 if(!token)return {...record,status:'RUNTIME_OBSERVATION_BLOCKED',reason:'Existing credential unavailable'};
 const binding=origin.binding;
 if(!binding||!/^[\w-]+$/.test(binding.taskId??'')||!/^[\w-]+$/.test(binding.requestedAnalysisId??''))throw Error('Sonar origin binding malformed');
 const base='http'+'://sonarqube-sonarqube.sonarqube.svc.cluster.local:9000';
 const paths=['/api/ce/task?id='+encodeURIComponent(binding.taskId),'/api/qualitygates/project_status?analysisId='+encodeURIComponent(binding.requestedAnalysisId)],raw=[];
 for(const path of paths){
  const response=await request(base+path,{method:'GET',headers:{Authorization:'Basic '+Buffer.from(token+':').toString('base64')},signal:AbortSignal.timeout(15000)});
  record.requests.push({method:'GET',path,httpStatus:response.status});
  if(response.status!==200)return {...record,status:'RUNTIME_OBSERVATION_BLOCKED',reason:'Existing identity rejected read-only request'};
  raw.push(await response.json());
 }
 const task=raw[0]?.task,gate=raw[1]?.projectStatus;
 if(task?.id!==binding.taskId||task.analysisId!==binding.requestedAnalysisId||task.componentKey!==binding.projectKey||task.status!=='SUCCESS'||!gate||!Array.isArray(gate.conditions))
  return {...record,status:'FACT_CONTRACT_INCOMPLETE',reason:'Task/analysis/project/condition binding mismatch'};
 return {...record,status:'OBSERVED_EXISTING_ANALYSIS_ONLY',raw:{binding,task:raw[0],gate:raw[1]},canonicalAdmission:'BLOCKED_PENDING_CURRENT_SOURCE_CANDIDATE_LINEAGE'};
}
if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href){
 const origin=JSON.parse(fs.readFileSync('runtime-sonar-origin.json'));let observation;
 try{observation=await observeExistingSonar({origin,token:process.env.RUNTIME_SONAR_TOKEN});}
 catch{observation={classification:'REAL_READ_ONLY_EXISTING_ANALYSIS_OBSERVATION',status:'RUNTIME_OBSERVATION_BLOCKED',reason:'Read-only request failed; credential and response diagnostic content suppressed',policyEvaluations:0,newAnalysis:0};}
 const output='.devsecops/runtime-facts/build-'+process.env.BUILD_NUMBER;fs.mkdirSync(output,{recursive:true});
 fs.writeFileSync(output+'/sonar-readonly-observation.json',JSON.stringify(observation,null,2),{mode:0o600});
 console.log(JSON.stringify({sonarObservation:observation.status,canonicalAdmission:observation.canonicalAdmission??'NOT_ADMITTED',policyEvaluations:0,newAnalysis:0}));
}
