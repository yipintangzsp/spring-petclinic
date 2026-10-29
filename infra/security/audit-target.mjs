export function resolveAuditTarget(runtimeImage,candidate=''){
 const value=String(candidate).trim();
 if(value&&!/^core\.harbor\.domain\/petclinic\/petclinic@sha256:[a-f0-9]{64}$/.test(value))throw Error('Candidate must be a pinned Harbor PetClinic SHA256 digest; tags and other repositories are forbidden');
 return {runtimeImage,auditTargetImage:value||runtimeImage,targetScope:value?'candidate':'live'};
}
export async function transportFetch(url,options={},fetchImpl=globalThis.fetch,sleep=ms=>new Promise(r=>setTimeout(r,ms))){
 for(let attempt=0;attempt<3;attempt++){
  let r;try{r=await fetchImpl(url,{...options,signal:AbortSignal.timeout(20000)});}catch(e){if(attempt===2||!['TypeError','TimeoutError','AbortError'].includes(e.name))throw e;await sleep((attempt+1)*2000);continue;}
  if([408,429,502,503,504].includes(r.status)&&attempt<2){await r.arrayBuffer();await sleep((attempt+1)*2000);continue;}return r;
 }
}
