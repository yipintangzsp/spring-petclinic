// Consume the existing Gate report, not Kubescape's admission/scanning algorithm.
export function kubescapeEvidence(raw){
 const r=raw?.report;
 if(!r||r.mode!=='AUDIT'||!['success','failed'].includes(r.status))return {status:'NOT_CONFIGURED',decision:null,reason:'Complete frozen AUDIT report required'};
 if(r.status==='failed')return {status:'FAIL',decision:'FAIL',auditDisposition:null,rawEvidence:structuredClone(raw)};
 if(!Array.isArray(r.scans)||r.scans.length!==4||r.scans.some(s=>s.status!=='success'||s.mode!=='AUDIT')||!Number.isInteger(r.findings)||r.findings<0)
  return {status:'NOT_CONFIGURED',decision:null,reason:'Four successful scans and findings evidence required'};
 return {status:'PASS',decision:'PASS',auditDisposition:r.findings?'WARN':'PASS',findings:r.findings,rawEvidence:structuredClone(raw),scope:'Frozen report classification only; tool/RBAC/capability/cleanup prerequisites not reconstructed'};
}
