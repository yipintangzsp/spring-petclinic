// Exact byte/format/ref requirements originally frozen from sbom-verify.mjs.
// U6 (user decision 2026-11-13): specVersion acceptance widened to CycloneDX 1.6 and 1.7. No generation or I/O.
export function sbomEvidence(raw){
 if(!raw||typeof raw.packagedBase64!=='string'||typeof raw.mavenBase64!=='string')throw Error('POLICY_ERROR: SBOM byte evidence required');
 const evidence=structuredClone(raw),bytes=Buffer.from(raw.packagedBase64,'base64');
 try{
  if(!bytes.equals(Buffer.from(raw.mavenBase64,'base64')))throw Error('Packaged SBOM differs from Maven output');
  const bom=JSON.parse(bytes);
  if(bom.bomFormat!=='CycloneDX'||!['1.6','1.7'].includes(bom.specVersion)||!Array.isArray(bom.components)||bom.components.length<10||!bom.dependencies?.length)throw Error('Nonempty CycloneDX 1.6/1.7 dependency inventory required');
  const refs=bom.components.map(x=>x['bom-ref']);if(refs.some(x=>!x)||new Set(refs).size!==refs.length)throw Error('SBOM component references must be unique');
  return {decision:'PASS',rawEvidence:evidence};
 }catch(error){return {decision:'FAIL',reason:error.message,rawEvidence:evidence};}
}
