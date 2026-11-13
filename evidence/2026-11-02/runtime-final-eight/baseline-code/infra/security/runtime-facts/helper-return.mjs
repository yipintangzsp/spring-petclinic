// Real Jenkins CPS return capture. Only the unchanged helpers' default no-op
// branch is supported here. No guessed skip, credential, signing or verifier.
import fs from 'node:fs';import {collectRuntimeFacts} from './collector.mjs';import {sha,fail} from '../summary-v2/codec.mjs';
const sources={provenance:'vars/securityProvenance.groovy','build-provenance':'vars/securityBuildProvenance.groovy'};
export function collectHelperReturn({sourceId,binding,path}){
 const original=sources[sourceId];if(!original)fail('Unsupported CPS source');
 const b=fs.readFileSync(path),observation=JSON.parse(b),producer=observation.producer;
 if(observation.schema!==1||observation.sourceId!==sourceId||observation.job!==binding.job||observation.build!==binding.build||
   observation.environment?.BUILD_NUMBER!==String(binding.build)||producer?.path!==original||
   producer.sha256!==sha(fs.readFileSync(original))||producer.libraryRevision!=='9a78cc89f22fa98fb1ffcc43e2ae279299471793')fail('CPS observation binding/source mismatch');
 if(!observation.configuration||!observation.parameters||!observation.environment||!observation.returned||observation.returned.tool!==sourceId)fail('CPS observation incomplete');
 // Do not silently choose a different optional branch or invent absent steps.
 if(Object.keys(observation.configuration).length||Object.keys(observation.parameters).length||
   Object.keys(observation.environment).some(k=>k!=='BUILD_NUMBER')||observation.returned.status!=='skipped')
   fail('FACT_CONTRACT_INCOMPLETE: only actual unchanged default helper return is collected');
 const payload={workflow:true,cfg:observation.configuration,params:observation.parameters,environment:observation.environment,
  git:{},operations:{},steps:{},observedReturn:observation.returned,producer};
 return collectRuntimeFacts({sourceId,binding,execution:{kind:'JENKINS_CPS_FUNCTION',command:original+':call',exitStatus:null,signal:null,errorClass:null,returnStatus:'RETURNED'},payload,
  reports:[{path,bytes:b.length,sha256:sha(b)}],evidence:[{classification:'REAL_JENKINS_CPS_DEFAULT_RETURN',producer,observedReturn:observation.returned,enabledBranchExecuted:false}]});
}
