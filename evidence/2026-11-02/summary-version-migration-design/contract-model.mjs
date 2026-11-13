// DESIGN HARNESS ONLY. Not imported by production. No Summary V2 implementation.
import crypto from 'node:crypto';
import {isDeepStrictEqual} from 'node:util';
const fail=message=>{throw Error('POLICY_ERROR: '+message);};
const object=x=>x!==null&&typeof x==='object'&&!Array.isArray(x);
const json=x=>JSON.stringify(x);
export const sha=x=>crypto.createHash('sha256').update(x).digest('hex');
export function freeze(x){
 if(object(x)||Array.isArray(x)){Object.values(x).forEach(freeze);Object.freeze(x);}
 return x;
}
const keys=['policyVersion','securityLevel','profile','effectivePolicy','appliedOverrides','status','decision'];
export function projectResult(result){
 return Object.fromEntries(keys.map(key=>{if(!Object.hasOwn(result,key))fail('missing Engine field '+key);return [key,structuredClone(result[key])];}));
}
export function singleSourceOwner(engine){
 // This is deliberately ONE SOURCE, not a fabricated whole-pipeline evaluate API.
 let current=null,identity=null;
 return {
  run(facts,config,binding){
   const input=sha(json({facts,config,binding}));
   if(current){if(identity!==input)fail('cannot reuse evaluation owner for different input');return current;}
   identity=input;
   current=(async()=>{
    let result=null,error=null;
    try{result=projectResult(await engine(facts,config));}
    catch(e){if(!String(e.message).startsWith('POLICY_ERROR:'))throw e;error={status:'POLICY_ERROR',message:e.message};}
    return freeze({schema:1,binding:structuredClone(binding),factsSha256:sha(json(facts)),configSha256:sha(json(config)),result,error});
   })();
   return current;
  }
 };
}
export function encode(resolved){
 const bytes=json(resolved);
 return {bytes,digest:sha(bytes)};
}
export function consume(packet,expected){
 if(!packet||typeof packet.bytes!=='string')fail('result missing');
 // Expected digest/binding must come from trusted owner context, NOT packet itself.
 if(sha(packet.bytes)!==expected.digest)fail('handoff digest mismatch');
 let v;try{v=JSON.parse(packet.bytes);}catch{fail('malformed JSON');}
 if(!object(v)||v.schema!==1||!object(v.binding)||!Object.hasOwn(v,'result')||!Object.hasOwn(v,'error'))fail('malformed envelope');
 if(!isDeepStrictEqual(v.binding,expected.binding))fail('result binding mismatch');
 if(v.factsSha256!==expected.factsSha256||v.configSha256!==expected.configSha256)fail('input snapshot mismatch');
 if(v.result===null){
  if(!object(v.error)||v.error.status!=='POLICY_ERROR'||typeof v.error.message!=='string'||!v.error.message.startsWith('POLICY_ERROR:'))fail('invalid error receipt');
 }else{
  if(v.error!==null||!object(v.result)||keys.some(k=>!Object.hasOwn(v.result,k)))fail('malformed Engine result');
  const r=v.result;
  if(r.policyVersion!==expected.binding.policyVersion)fail('wrong policyVersion');
  if(!['low','standard','strict'].includes(r.securityLevel)||typeof r.profile!=='string'||!object(r.effectivePolicy)||!Array.isArray(r.appliedOverrides))fail('malformed Policy metadata');
  if(!['PASS','WARN','FAIL','ERROR','SKIPPED','DISABLED','NOT_CONFIGURED','NOT_TESTED'].includes(r.status)||![null,'PASS','WARN','FAIL'].includes(r.decision))fail('malformed result status');
 }
 return freeze(v);
}
export function gateView(resolved){
 if(resolved.error)return {status:'POLICY_ERROR',decision:null};
 return {status:resolved.result.status,decision:resolved.result.decision};
}
export function metadataView(resolved){
 // Pure projection. It has no evaluator argument/import and creates no Summary file.
 if(resolved.error)return {status:'POLICY_ERROR',error:structuredClone(resolved.error)};
 const {decision,...metadata}=resolved.result;
 return structuredClone(metadata);
}
export function migrationCheck(producer,selectedContract,metadataValid=true){
 // A model registry is supplied by the test, never installed as an accepted hash.
 if(!object(producer)||!producer.identity||!producer.sha256)fail('producer identity missing');
 if(producer.identity!==selectedContract.producer.identity||producer.sha256!==selectedContract.producer.sha256)fail('unsupported producer tuple');
 if(selectedContract.generation===2&&!metadataValid)fail('malformed V2 Policy metadata');
 return 'ACCEPT';
}
