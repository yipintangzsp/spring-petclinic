import fs from 'node:fs';import crypto from 'node:crypto';import {buildProvenanceEvidence} from './build-provenance-evidence.mjs';
export function buildProvenanceWorkflow(raw){
 const version=JSON.parse(fs.readFileSync(new URL('./versions/build-provenance-baseline-v1.json',import.meta.url)));
 for(const [p,h]of Object.entries(version.workflowSourceHashes))if(crypto.createHash('sha256').update(fs.readFileSync(new URL('../../../'+p,import.meta.url))).digest('hex')!==h)throw Error('POLICY_ERROR: frozen Build Provenance workflow changed');
 if(!raw?.workflow||!raw.cfg||!raw.environment||!raw.steps)return {decision:null,status:'NOT_CONFIGURED',reason:'Workflow observations absent'};
 const cfg=raw.cfg,env=raw.environment,mode=cfg.mode||'enforce';let decision,report,reason,missing=false,invoked=false;
 const step=key=>{if(!Object.hasOwn(raw.steps,key)){missing=true;throw Error('Missing step evidence: '+key);}if(raw.steps[key].error)throw Error(raw.steps[key].error);};
 try{
  if(!['off','audit','enforce'].includes(mode))throw Error('Invalid build provenance mode');
  if(mode==='off'||cfg.enabled!==true)return {decision:null,status:'SKIPPED',report:{tool:'build-provenance',status:'skipped'},invoked,rawEvidence:structuredClone(raw)};
  if(typeof env.BUILD_NUMBER!=='string'||!/^[-+]?\d+$/.test(env.BUILD_NUMBER.trim())||Number(env.BUILD_NUMBER)<-2147483648||Number(env.BUILD_NUMBER)>2147483647)throw Error('Invalid build integer');
  report={tool:'build-provenance',status:'success',build:Number(env.BUILD_NUMBER),mode};
  step('stage');step('withEnv');step('credentials');
  const facts=raw.verificationFacts;if(!facts){missing=true;throw Error('Verified operation facts absent');}
  const requested={image:String(cfg.image||''),commit:String(cfg.commit||''),repository:String(cfg.repository||''),builder:String(cfg.builder||''),buildNumber:String(cfg.buildNumber||'')};
  if(facts.phase!=='verify'||Object.entries(requested).some(([k,v])=>facts.inputIdentity?.requestedVerification?.[k]!==v)){missing=true;throw Error('Verification facts not bound to workflow inputs');}
  invoked=true;const result=buildProvenanceEvidence(facts);if(result.decision===null){missing=true;throw Error('Incomplete verification facts');}
  if(result.decision!=='PASS')report.status=mode==='audit'?'warn':'failed';
  step('status-write');decision=report.status==='warn'?'WARN':report.status==='failed'?'FAIL':'PASS';
 }catch(e){reason=e.message;decision=missing?null:'FAIL';}
 return {decision,status:decision??'NOT_TESTED',report,reason,invoked,rawEvidence:structuredClone(raw)};
}
