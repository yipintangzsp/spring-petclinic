// Frozen external observations only. No subprocess, network, credential lookup or filesystem mutation.
import crypto from 'node:crypto';
export class MissingCosignEvidence extends Error {}
export function cosignObservations(raw){
 const counts={},trace=[];
 const need=(map,key)=>{if(!map||!Object.hasOwn(map,key))throw new MissingCosignEvidence('Missing Cosign observation: '+key);return map[key];};
 const io=key=>{const r=need(raw.io,key);trace.push({type:'io',key});if(r.error)throw Error(r.error);return r.value;};
 const file=p=>{const r=need(raw.files,p);trace.push({type:'file',path:p});if(r.error)throw Error(r.error);return need(r,'value');};
 const command=(tool,args)=>{const key=tool+':'+args[0],index=counts[key]??0;counts[key]=index+1;const value=need(need(raw.commands,key),index);need(value,'status');if(!value.error){need(value,'stdout');need(value,'stderr');}trace.push({type:'command',tool,args:[...args],result:structuredClone(value)});return value;};
 let registryIndex=0,admissionIndex=0;
 const registry=(url,options={})=>{const r=need(raw.registry,registryIndex++);trace.push({type:'registry',url,method:options.method??'GET',bodySha256:options.body?crypto.createHash('sha256').update(options.body).digest('hex'):null});if(r.error)throw Error(r.error);return r;};
 const admission=(args,input)=>{const r=need(raw.admissions,admissionIndex++);trace.push({type:'admission',args,input,result:structuredClone(r)});return r;};
 return {need,io,file,command,registry,admission,trace};
}
