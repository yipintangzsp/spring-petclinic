// Read frozen external observations; never spawn, decrypt, sign, or contact a registry.
export class MissingProvenanceEvidence extends Error {}
export function provenanceObservations(raw){
 const counts={},trace=[];
 const need=(map,key)=>{if(!map||!Object.hasOwn(map,key))throw new MissingProvenanceEvidence('Missing Provenance observation: '+key);return map[key];};
 const io=key=>{const r=need(raw.io,key);trace.push({type:'io',key});if(r.error)throw Error(r.error);return r.value;};
 const file=key=>{const r=need(raw.files,key);trace.push({type:'file',key});if(r.error)throw Error(r.error);return need(r,'value');};
 const command=(tool,args)=>{const key=tool+':'+args[0],index=counts[key]??0;counts[key]=index+1;const r=need(need(raw.commands,key),index);need(r,'status');if(r.status===0)need(r,'stdout');trace.push({type:'command',tool,args:[...args],result:structuredClone(r)});return r;};
 return {need,io,file,command,trace};
}
