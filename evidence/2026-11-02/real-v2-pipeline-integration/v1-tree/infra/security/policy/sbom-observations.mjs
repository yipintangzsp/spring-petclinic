// Frozen observations only; no filesystem/network/process operations.
export class MissingSbomEvidence extends Error {}
export function sbomObservations(raw){
 const trace=[];const need=(map,key)=>{if(!map||!Object.hasOwn(map,key))throw new MissingSbomEvidence('Missing SBOM observation: '+key);return map[key];};
 const file=p=>{const r=need(raw.files,p);trace.push({type:'file',path:p});if(r.error)throw Error(r.error);return need(r,'value');};
 const io=key=>{const r=need(raw.io,key);trace.push({type:'io',key});if(r.error)throw Error(r.error);};
 return {trace,need,file,io};
}
