import fs from 'node:fs';import crypto from 'node:crypto';import {provenanceParent} from './provenance-parent.mjs';
export function provenanceWorkflow(raw){
 const version=JSON.parse(fs.readFileSync(new URL('./versions/provenance-parent-baseline-v1.json',import.meta.url)));
 for(const [p,h]of Object.entries(version.workflowSourceHashes))if(crypto.createHash('sha256').update(fs.readFileSync(new URL('../../../'+p,import.meta.url))).digest('hex')!==h)throw Error('POLICY_ERROR: frozen Provenance workflow changed');
 if(!raw?.workflow||!raw.cfg||!raw.params||!raw.environment||!raw.git||!raw.operations||!raw.steps)return {decision:null,status:'NOT_CONFIGURED',reason:'Complete Provenance workflow observations absent'};
 const truth=x=>Array.isArray(x)?x.length>0:x&&typeof x==='object'?Object.keys(x).length>0:!!x;
 const cfg=raw.cfg,env=raw.environment,params=raw.params,mode=truth(cfg.mode)?cfg.mode:'enforce';let report,decision,reason,missing=false;const invoked=[],operations=[];
 const step=key=>{if(!Object.hasOwn(raw.steps,key)){missing=true;throw Error('Missing workflow observation: '+key);}if(raw.steps[key].error)throw Error(raw.steps[key].error);};
 const git=key=>{if(!Object.hasOwn(raw.git,key)){missing=true;throw Error('Missing git observation: '+key);}const value=raw.git[key];if(value.error)throw Error(value.error);return value.value.trim();};
 try{
  if(!['off','audit','enforce'].includes(mode))throw Error('Invalid provenance mode');
  const enabled=Object.hasOwn(params,'ENABLE_PROVENANCE')?params.ENABLE_PROVENANCE===true:env.ENABLE_PROVENANCE!=null?env.ENABLE_PROVENANCE==='true':cfg.enableProvenance===true;
  if(!enabled||mode==='off')return {decision:null,status:'SKIPPED',report:{tool:'provenance',status:'skipped'},invoked,operations,rawEvidence:structuredClone(raw)};
  step('source-withEnv');const repository=truth(cfg.repository)?cfg.repository:git('repository'),commit=git('commit');
  // Groovy toInteger() rejects non-integer strings; unlike JS Number it does not truncate or accept decimals.
  if(typeof env.BUILD_NUMBER!=='string'||!/^[-+]?\d+$/.test(env.BUILD_NUMBER.trim())||Number(env.BUILD_NUMBER)<-2147483648||Number(env.BUILD_NUMBER)>2147483647)throw Error('Invalid build integer');
  report={tool:'provenance',status:'success',build:Number(env.BUILD_NUMBER),mode};let failed=false;
  step('operations-withEnv');
  const candidate=truth(cfg.candidateImage)?cfg.candidateImage:truth(params.AUDIT_CANDIDATE_IMAGE)?params.AUDIT_CANDIDATE_IMAGE:truth(cfg.image)?cfg.image:'';
  for(const action of ['generate','create','verify']){
   step('stage-'+action);if(failed)continue;
   if(action!=='generate')step('credentials-'+action);
   if(!Object.hasOwn(raw.operations,action)){missing=true;throw Error('Missing operation: '+action);}
   if(raw.operations[action].action!==action){missing=true;throw Error('Operation/action binding absent: '+action);}
   const facts=structuredClone(raw.operations[action]);facts.environment={...env,PROVENANCE_CANDIDATE:candidate,PROVENANCE_REPOSITORY:repository,PROVENANCE_COMMIT:commit};
   const result=provenanceParent(facts);invoked.push(action);operations.push({action,decision:result.decision,status:result.status,expectedIdentity:result.normalizedFacts?.expectedIdentity});
   if(result.decision===null){missing=true;throw Error('Incomplete operation evidence: '+action);}
   if(result.decision!=='PASS'){failed=true;report.status=mode==='audit'?'warn':'failed';}
  }
  step('status-write');decision=failed?(mode==='audit'?'WARN':'FAIL'):'PASS';
 }catch(error){decision=missing?null:'FAIL';reason=error.message;}
 return {decision,status:decision??'NOT_TESTED',reason,report,invoked,operations,rawEvidence:structuredClone(raw)};
}
