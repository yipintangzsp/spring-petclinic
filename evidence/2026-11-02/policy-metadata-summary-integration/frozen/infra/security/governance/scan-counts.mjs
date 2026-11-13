// Keep complete vulnerability evidence visible when the unchanged policy correctly fails.
// Engine failures and partial scans must not become fabricated zero counts.
export function trivyCounts(report){
 if(!report||!['success','failed'].includes(report.status)||report.status==='failed'&&!report.failures?.length||!report.scans?.length)return null;
 const counts={Critical:0,High:0,Medium:0,Low:0};
 for(const s of report.scans){
  if(s.scan?.scan_status!=='Success'||!s.raw||typeof s.raw!=='object'||Array.isArray(s.raw))return null;
  const results=Object.values(s.raw);if(!results.length)return null;
  for(const r of results){if(!r||!('vulnerabilities'in r)||r.vulnerabilities!==null&&!Array.isArray(r.vulnerabilities))return null;
   for(const v of r.vulnerabilities??[]){const k=Object.keys(counts).find(k=>k.toUpperCase()===String(v.severity).toUpperCase());if(k)counts[k]++;}
  }
 }
 return Object.fromEntries(Object.entries(counts).map(([k,v])=>['trivy_'+k.toLowerCase(),v]));
}
