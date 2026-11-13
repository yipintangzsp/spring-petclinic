export function highAlerts(data){
 if(!Array.isArray(data.site)||!data.site.length)throw Error('ZAP report has no visited site');
 return data.site.flatMap(s=>s.alerts??[]).filter(a=>{
  const risk=Number(a.riskcode);if(!Number.isInteger(risk)||risk<0||risk>3)throw Error('Invalid DAST risk code');return risk>=3;
 });
}
export function requireSignedRelease({signing,proof,image,source}){
 if(signing.status!=='success'||signing.mode!=='release'||signing.source!==source||!signing.artifactSignatureVerified||!signing.temporaryPrivateFilesRemoved||!proof.signed||proof.source!==source||proof.imageDigest!==image)throw Error('Signed release/source evidence required');
 if(!signing.images?.some(x=>x.verified&&x.image==='core.harbor.domain/petclinic/petclinic@'+image))throw Error('Verified image index signature required');
}
