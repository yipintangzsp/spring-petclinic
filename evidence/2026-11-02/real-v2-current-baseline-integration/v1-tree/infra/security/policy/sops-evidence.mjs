import fs from 'node:fs';
import {isDeepStrictEqual} from 'node:util';
const missing=reason=>({component:'sops',status:'not_configured',reason});
// In-memory inputs only. Never return decrypted stdout/data, credential paths or stderr.
// These are the existing secrets-gate comparisons, not SOPS/age cryptography.
export function sopsFacts(raw){
 if(!raw||!raw.prerequisites||!Array.isArray(raw.targets))return missing('SOPS execution observations absent');
 const source=fs.readFileSync(new URL('../secrets-gate.mjs',import.meta.url),'utf8');
 const scope=JSON.parse(source.match(/const targets=(\[\[.*?\]\]);/)[1].replaceAll("'",'"'));
 if(raw.expectedTargetCount!==scope.length||raw.targets.some((t,i)=>t&&JSON.stringify([t.expected?.namespace,t.expected?.name])!==JSON.stringify(scope[i])))return missing('Frozen target scope mismatch');
 const facts={component:'sops',status:'success',checks:[],failureKind:null};
 const check=(id,passed,kind)=>{facts.checks.push({id,passed});if(!passed){facts.failureKind=kind;return false;}return true;};
 const p=raw.prerequisites;
 for(const [name,kind]of [['manifest','validation failure'],['lease','execution error'],['tools','validation failure']]){
  if(typeof p[name]!=='boolean')return missing('Missing prerequisite observation: '+name);
  if(!check(name,p[name],kind))return facts;
 }
 if(typeof p.credentialPresent!=='boolean')return missing('Credential observation absent');
 if(!check('credential',p.credentialPresent,'missing credential'))return facts;
 if(typeof raw.sourceReadSucceeded!=='boolean')return missing('Source read observation absent');
 if(!check('source-read',raw.sourceReadSucceeded,'execution error'))return facts;
 if(!Number.isInteger(raw.expectedTargetCount)||raw.expectedTargetCount<1)return missing('Expected target scope absent');
 for(let i=0;i<raw.expectedTargetCount;i++){
  const t=raw.targets[i];if(!t||!t.expected||!Number.isInteger(t.decrypt?.exitStatus))return missing('Target/decrypt observation absent');
  if(!check('decrypt-'+i,t.decrypt.exitStatus===0,'execution error'))return facts;
  let desired;try{desired=JSON.parse(t.decrypt.stdout);}catch{check('decode-'+i,false,'validation failure');return facts;}
  if(!check('scope-'+i,desired?.kind==='Secret'&&desired.metadata?.namespace===t.expected.namespace&&desired.metadata?.name===t.expected.name&&!!desired.data&&!desired.stringData,'validation failure'))return facts;
  if(typeof t.readSucceeded!=='boolean')return missing('Live read observation absent');
  if(!check('read-'+i,t.readSucceeded,'execution error'))return facts;
  if(!t.actual)return missing('Actual object absent');
  if(!check('data-type-'+i,isDeepStrictEqual(t.actual.data,desired.data)&&t.actual.type===desired.type,'validation failure'))return facts;
  if(raw.readOnly!==true){if(typeof t.applySucceeded!=='boolean')return missing('Apply outcome absent');if(!check('apply-'+i,t.applySucceeded,'execution error'))return facts;}
  if(typeof t.afterReadSucceeded!=='boolean')return missing('Second read outcome absent');
  if(!check('after-read-'+i,t.afterReadSucceeded,'execution error'))return facts;
  if(!t.after)return missing('Second object absent');
  if(!check('identity-values-'+i,t.after.metadata?.uid===t.actual.metadata?.uid&&isDeepStrictEqual(t.after.data,t.actual.data),'validation failure'))return facts;
 }
 for(const [name,allowed]of [['rbac',['knownGet','knownRegistryGet']],['verifierRbac',['ownCredentialGet']]]){
  const required=name==='rbac'?['knownRegistryGet','registryForeignGet','registryList','registryCreate','knownGet','foreignGet','createSecret','listSecrets','otherNamespace']:['ownCredentialGet','oldCrossGet','businessDatabaseGet','businessSecretList'];
  const map=raw[name];if(!map||!required.every(k=>Object.hasOwn(map,k)))return missing('Permission observations absent');
  if(!check(name,allowed.every(k=>map[k]==='yes')&&!Object.entries(map).some(([k,v])=>!allowed.includes(k)&&v!=='no'),'validation failure'))return facts;
 }
 if(typeof raw.reportWriteSucceeded!=='boolean')return missing('Final report write outcome absent');
 check('report-write',raw.reportWriteSucceeded,'execution error');return facts;
}
export function sopsDecision(facts){
 if(facts.status==='not_configured')return {status:'NOT_CONFIGURED',decision:null,reason:facts.reason};
 const decision=facts.checks.some(c=>!c.passed)?'FAIL':'PASS';
 return {status:decision,decision,failureKind:facts.failureKind,checks:structuredClone(facts.checks),severity:null};
}
