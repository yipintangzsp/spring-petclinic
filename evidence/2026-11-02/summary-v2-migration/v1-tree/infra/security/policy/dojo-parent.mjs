import fs from 'node:fs';import crypto from 'node:crypto';import {dojoFrozenIO} from './dojo-frozen-io.mjs';
// Governance acceptance only. This does not scan, reclassify or suppress vulnerabilities.
export async function dojoParent(raw){
 const binding=JSON.parse(fs.readFileSync(new URL('./versions/dojo-parent-baseline-v1.json',import.meta.url)));
 for(const [p,sha]of Object.entries(binding.sourceHashes)){if(crypto.createHash('sha256').update(fs.readFileSync(new URL('../'+p.replace('infra/security/',''),import.meta.url))).digest('hex')!==sha)throw Error('POLICY_ERROR: Dojo frozen source changed');}
 if(!raw?.files||!raw?.target||!raw?.api||!raw?.credentials)return {status:'NOT_CONFIGURED',decision:null,reason:'Complete Dojo facts unavailable'};
 const io=dojoFrozenIO(raw),imports=[],proofs=[];let failure,counts;
 const read=p=>JSON.parse(String(io.fs.readFileSync(p))),write=(p,v)=>io.fs.writeFileSync(p,JSON.stringify(v));
 try{
  io.fs.mkdirSync('.devsecops/governance');const source=String(io.fs.readFileSync('.git-sha')).trim();
  if(!raw.credentials.dojo||!raw.credentials.sonar)throw Error('Bound credentials absent');
  const target=read('infra/security/governance/dojo-target.json'),client=new io.Client(target.baseUrl,'FIXTURE_CREDENTIAL_NOT_TRANSMITTED');
  await client.request('/api/v2/products/'+target.product+'/');
  const tasks=[{title:'Gitleaks exact source',scanType:'Gitleaks Scan',file:'.devsecops/gitleaks-native.json'},{title:'Semgrep Java source',scanType:'Semgrep JSON Report',file:'.devsecops/semgrep-native.json'},{title:'ZAP business passive',scanType:'ZAP Scan',file:'.devsecops/zap-business-report.xml'}];
  const trivy=read('.devsecops/trivy-audit.json');if(!trivy.scans?.length||trivy.scans.some(s=>s.scan?.scan_status!=='Success'||!s.raw)||(trivy.status!=='success'&&!trivy.failures?.length))throw Error('Complete actual reports required');
  for(const s of trivy.scans){const file='.devsecops/governance/trivy-'+s.digest.split(':')[1]+'.json';write(file,s.raw);tasks.push({title:'Trivy ['+trivy.targetScope+'] '+s.digest,scanType:'Harbor Vulnerability Scan',file});}
  const ks=read('.devsecops/kubescape-gate.json');if(ks.status!=='success'||ks.source!==source||ks.scans.length!==4)throw Error('Four source-bound reports required');
  for(const s of ks.scans)tasks.push({title:'Kubescape '+s.scope+' '+s.framework,scanType:'Kubescape JSON Importer',file:s.reportFile});
  const sonar=await io.fetch('http://sonarqube-sonarqube.sonarqube.svc.cluster.local:9000/api/issues/search?componentKeys=petclinic&types=VULNERABILITY&ps=500');
  if(!sonar.ok)throw Error('Sonar native export unavailable');const sd=await sonar.json();if(!Array.isArray(sd.issues)||sd.paging?.total!==sd.issues.length)throw Error('Incomplete issues');write('.devsecops/governance/sonarqube-native.json',sd);tasks.push({title:'SonarQube vulnerabilities',scanType:'SonarQube Scan',file:'.devsecops/governance/sonarqube-native.json'});
  for(const t of tasks){t.title='[audit-run '+trivy.targetScope+'] '+t.title;if(!io.fs.existsSync(t.file))throw Error('Native report missing');imports.push(await client.importNative({...t,engagement:target.engagement,build:Number(raw.build),source,auditContext:{runtimeImage:trivy.runtimeImage,auditTargetImage:trivy.auditTargetImage,targetScope:trivy.targetScope,scannerScope:t.scanType==='Harbor Vulnerability Scan'?'audit target image':t.scanType==='ZAP Scan'?'live business read-only GET':t.scanType==='Kubescape JSON Importer'?'live cluster and repository YAML':'checked-out source'}}));write('.devsecops/defectdojo-import.json',{imports});}
  const src=read('.devsecops/source-gate.json');if(src.status!=='success'&&!src.sourceScan?.blockingFindings?.length)throw Error('Complete source evidence required');
  const gt=imports.find(x=>x.scanType==='Gitleaks Scan'),findings=await client.findings(gt.testId);
  for(const f of findings){const p=(src.sourceScan.verifiedFalsePositives??[]).find(e=>(e.file===f.file_path||f.title?.endsWith('found in '+e.file))&&e.line===f.line&&f.description?.includes('**Rule Id:** '+e.rule)&&/^[a-f0-9]{64}$/.test(e.line_sha256));if(p){if(f.active||!f.false_p)await client.request('/api/v2/findings/'+f.id+'/',{method:'PATCH',body:{active:false,false_p:true,verified:false}});proofs.push({findingId:f.id,lineSha256:p.line_sha256,reason:p.reason});}}
  counts=io.counts(await client.list('/api/v2/findings/?limit=200&test__engagement__product='+target.product));
 }catch(error){failure=error.message;}
 try{write('.devsecops/defectdojo-import.json',{imports,counts,proofs});}catch(error){failure=error.message;}
 return {status:failure?'FAIL':'PASS',decision:failure?'FAIL':'PASS',integrationStatus:failure?'failed':'success',reason:failure,imports,counts,reviewedFalsePositives:proofs,requests:io.requests,rawEvidence:structuredClone(raw),scope:'Dojo integration acceptance; no vulnerability verdict'};
}
