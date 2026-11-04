// Candidate consumer only. No Policy/scanner import, HTTP client or credentials.
import fs from 'node:fs';import path from 'node:path';
import {canonical,digest,sha,freeze} from '../../summary-v2/codec.mjs';
import {verifyArtifact,verifyResult,artifactStore} from '../result.mjs';
export const MAPPING=freeze(JSON.parse(fs.readFileSync(new URL('./dojo-mapping-v1.json',import.meta.url))));
export const PROJECTS=freeze(JSON.parse(fs.readFileSync(new URL('./dojo-projects-v1.json',import.meta.url))));
export const DEFINITION=freeze({consumerId:'defectdojo-candidate',consumerVersion:MAPPING.consumerVersion,enabled:true,supportedSchemaVersions:[1],requiredInputs:['SECURITY_SUMMARY','CANDIDATE_ARTIFACT'],inputSchema:'SecuritySummaryCandidate/v1',transform:'dojo-generic-v1',validate:'dojo-generic-v1',prepareDelivery:'offline-plan-v1',publish:'defectdojo-dry-run',verify:'payload-digest/v1',receipt:'offline-receipt-v1',cleanup:'OWNED_TEMPORARY_PREPARATION_ONLY',errorPolicy:'RECORD_AND_BLOCK'});
export class ConsumerError extends Error{constructor(code){super(code);this.code=code;}}
const reject=code=>{throw new ConsumerError(code);};
const must=(x,code)=>{if(!x)reject(code);};
const same=(a,b)=>canonical(a)===canonical(b);
const hex=x=>typeof x==='string'&&/^[a-f0-9]{64}$/.test(x);
const credentialPattern=/(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|AKIA[A-Z0-9]{16}|-----BEGIN (?:ENCRYPTED |EC |OPENSSH )?PRIVATE KEY-----|Bearer\s+\S+|Authorization\s*[:=]|\b(?:password|api_token|access_token)\s*[:=]\s*[^\s,}]+)/i;
function safe(s,max=250){must(typeof s==='string'&&s.length>0&&s.length<=max&&!/[\x00-\x1f\x7f]/.test(s)&&!credentialPattern.test(s),'UNSAFE_METADATA');return s;}
export function validateProjectCatalog(c){
 must(c?.schemaVersion===1&&c.autoCreateContext===false&&c.productionProductId1Excluded===true,'INVALID_PROJECT_MAPPING');
 const products=new Set(),engagements=new Set();
 for(const [id,p]of Object.entries(c.projects??{})){
  safe(id,80);must(/^[a-z0-9-]+$/.test(id)&&['java-web','container-service','python-api'].includes(p.profile),'INVALID_PROJECT_MAPPING');
  for(const k of ['productAlias','engagementAlias'])must(/^candidate-[a-z0-9-]+$/.test(p[k]),'INVALID_PROJECT_MAPPING');
  // This round has no authorized remote context. Numeric production IDs are
  // deliberately not accepted through project/config/CLI parameters.
  must(p.productId===null&&p.engagementId===null&&p.remoteApproved===false,'UNAPPROVED_PRODUCT_TARGET');
  must(!products.has(p.productAlias)&&!engagements.has(p.engagementAlias),'CROSS_PROJECT_MAPPING_COLLISION');products.add(p.productAlias);engagements.add(p.engagementAlias);
 }
 must(products.size>0,'INVALID_PROJECT_MAPPING');return true;
}
validateProjectCatalog(PROJECTS);
export function projectTarget(projectId,profile){
 const p=PROJECTS.projects[projectId];if(!p)return null;
 must(p.profile===profile,'PROJECT_PROFILE_MISMATCH');return p;
}
function readReport(dir,name,seal){
 must(Object.hasOwn(seal.files,name),'RAW_OR_FACT_REFERENCE_MISSING');const full=path.join(dir,name),s=fs.lstatSync(full);
 must(s.isFile()&&!s.isSymbolicLink()&&s.nlink===1&&s.size<=2*1024*1024&&fs.realpathSync(full)===full,'REPORT_BOUNDARY');
 const bytes=fs.readFileSync(full);must(sha(bytes)===seal.files[name].sha256,'RAW_REPORT_DIGEST_MISMATCH');
 try{return {data:JSON.parse(bytes),bytes:bytes.toString()};}catch{reject('REPORT_JSON_MALFORMED');}
}
function relativeFile(file,prefix){
 must(typeof prefix==='string'&&file?.startsWith(prefix+'/'),'SOURCE_SCOPE_MISSING');const rel=file.slice(prefix.length+1);
 safe(rel,220);must(!rel.startsWith('/')&&!rel.includes('\\')&&!rel.split('/').some(x=>['..','.',''].includes(x)),'FINDING_PATH_BOUNDARY');return rel;
}
const positiveInt=x=>Number.isSafeInteger(x)&&x>0&&x<10000000;
export function findingIdentity({projectId,pluginId,scanScope,rule,relativeFile,line,column=null}){
 [projectId,pluginId,scanScope,rule,relativeFile].forEach(x=>safe(x));must(positiveInt(line)&& (column===null||positiveInt(column)),'FINDING_LOCATION');
 return 'smv2-'+digest({version:MAPPING.mappingVersion,projectId,pluginId,scanScope,rule,relativeFile,line,column});
}
function normalizedFindings(result,fact,raw){
 must(fact.status==='success','UNTRUSTED_SCAN_STATE');
 const plugin=result.pluginId,source=result.runtimeFacts?.sourceDir?.path;let observations;
 if(plugin==='gitleaks'){
  must(fact.component==='gitleaks'&&Array.isArray(fact.raw?.findings)&&Array.isArray(raw),'UNSUPPORTED_RAW_SCHEMA');
  observations=fact.raw.findings.map(f=>{
   const n=raw.find(n=>n.RuleID===f.rule&&n.File===f.file&&n.StartLine===f.line);must(n,'NATIVE_FACT_MISMATCH');
   must(!Object.hasOwn(n,'Severity')&&!Object.hasOwn(f,'severity'),'GITLEAKS_SEVERITY_MAPPING_NOT_CONFIGURED');
   return {rule:f.rule,file:f.file,line:f.line,column:positiveInt(n.StartColumn)?n.StartColumn:null,severity:MAPPING.severityMappings.gitleaks.dojoSeverity,sourceSeverity:null};
  });
  must(observations.length===raw.length,'NATIVE_FACT_MISMATCH');
 }else{
  must(fact.component==='semgrep'&&Array.isArray(fact.raw?.findings)&&raw.kind==='SemgrepNativeReportCollection'&&Array.isArray(raw.reports)&&Array.isArray(raw.nativeReportTexts),'UNSUPPORTED_RAW_SCHEMA');
  must(same(raw.reports,raw.nativeReportTexts.map(t=>{must(sha(t.bytesUtf8)===t.sha256,'RAW_REPORT_DIGEST_MISMATCH');return JSON.parse(t.bytesUtf8);})), 'NATIVE_FACT_MISMATCH');
  must(same(raw.reports.flatMap(r=>{must(Array.isArray(r.results)&&Array.isArray(r.errors)&&!r.errors.length,'UNTRUSTED_SCAN_STATE');return r.results;}),fact.raw.findings),'NATIVE_FACT_MISMATCH');
  observations=fact.raw.findings.map(f=>{const sourceSeverity=f.extra?.severity;must(typeof sourceSeverity==='string','MISSING_SCANNER_SEVERITY');const severity=MAPPING.severityMappings.semgrep.values[sourceSeverity.toUpperCase()];must(severity,'UNSUPPORTED_SCANNER_SEVERITY');return {rule:f.check_id,file:f.path,line:f.start?.line,column:f.start?.col??null,severity,sourceSeverity};});
 }
 return observations.map(f=>{
  safe(f.rule,96);must(/^[a-zA-Z0-9_.-]+$/.test(f.rule),'UNSAFE_RULE_ID');must(positiveInt(f.line)&&(f.column===null||positiveInt(f.column)),'FINDING_LOCATION');
  const rel=relativeFile(f.file,source),scanScope='directory-no-git-history',id=findingIdentity({projectId:result.projectId,pluginId:plugin,scanScope,rule:f.rule,relativeFile:rel,line:f.line,column:f.column});
  const title='['+result.projectId+'/'+plugin+'] '+f.rule;
  // No Match, Secret, source line, metadata message, fingerprint text, command
  // stderr, author, email, or arbitrary scanner description is ever copied.
  const description='Source: '+plugin+'; rule: '+f.rule+'; scope: '+scanScope+'. Raw content omitted. Governance mapping '+MAPPING.mappingVersion+'.';
  const evidence={mappingVersion:MAPPING.mappingVersion,pluginId:plugin,ruleId:f.rule,sourceSeverity:f.sourceSeverity,column:f.column,rawReportDigest:result.rawReportDigest,factDigest:result.factDigest,resultDigest:result.resultDigest,rulesDigest:plugin==='semgrep'?result.runtimeFacts?.rules?.sha256:null};
  must(plugin!=='semgrep'||hex(evidence.rulesDigest),'RULESET_IDENTITY_MISSING');
  const finding={title,severity:f.severity,description,severity_justification:plugin==='gitleaks'?'Native Gitleaks severity absent; fixed installed current-parser default High (versioned governance display mapping).':'Installed Semgrep parser severity conversion; original value preserved in evidence references.',file_path:rel,line:f.line,unique_id_from_tool:id,vuln_id_from_tool:plugin+':'+f.rule,references:canonical(evidence),static_finding:true,dynamic_finding:false,active:true,verified:false,nb_occurences:1};
  return {finding,evidence};
 });
}
export function validatePayload(p){
 must(p&&same(Object.keys(p).sort(),['name','type','version','findings'].sort())&&p.type==='Generic Findings Import'&&p.version===MAPPING.mappingVersion&&Array.isArray(p.findings)&&p.findings.length<=256,'PAYLOAD_SCHEMA');safe(p.name);
 const seen=new Set();
 for(const f of p.findings){
  must(same(Object.keys(f).sort(),[...MAPPING.parser.allowedFindingFieldsSubset].sort()),'PAYLOAD_FIELDS');
  for(const k of ['title','description','severity_justification','file_path','unique_id_from_tool','vuln_id_from_tool','references'])safe(f[k],k==='references'?1600:500);
  must(['Critical','High','Medium','Low','Info'].includes(f.severity)&&positiveInt(f.line)&&/^smv2-[a-f0-9]{64}$/.test(f.unique_id_from_tool),'PAYLOAD_FINDING_VALUE');
  must(f.static_finding===true&&f.dynamic_finding===false&&f.active===true&&f.verified===false&&positiveInt(f.nb_occurences),'FINDING_LIFECYCLE_MUTATION');
  must(!seen.has(f.unique_id_from_tool),'DUPLICATE_FINDING_ID');seen.add(f.unique_id_from_tool);
 }
 must(!credentialPattern.test(canonical(p)),'SECRET_REDACTION_FAILED');return true;
}
export function prepareDefectDojo({run,artifactDirectory,expectedSealDigest}){
 const dir=path.resolve(artifactDirectory);must(fs.realpathSync(dir)===dir&&!fs.lstatSync(dir).isSymbolicLink(),'ARTIFACT_BOUNDARY');
 verifyArtifact(dir,expectedSealDigest);const seal=JSON.parse(fs.readFileSync(path.join(dir,'candidate-seal.json'))),summary=run.summary;
 must(summary?.kind==='SecuritySummaryCandidate'&&summary.schemaVersion===1&&summary.productionEvidence===false&&summary.promotion?.status==='BLOCKED','SUMMARY_SCHEMA');
 must(same(JSON.parse(fs.readFileSync(path.join(dir,'candidate-summary.json'))),summary),'SUMMARY_DIGEST_MISMATCH');safe(summary.projectId,80);safe(summary.runId,100);
 const target=projectTarget(summary.projectId,summary.profile),records=[],imports=[];
 for(const r of summary.pluginResults){
  verifyResult(r);safe(r.pluginId,60);must([r.rawReportDigest,r.factDigest].every(x=>x===null||hex(x)),'RESULT_EVIDENCE_DIGEST');must(r.projectId===summary.projectId&&r.runId===summary.runId,'RESULT_PROJECT_BINDING');
  const record={pluginId:r.pluginId,executionStatus:r.executionStatus,policyDecision:r.policyDecision,evaluationCount:r.evaluationCount,factDigest:r.factDigest,resultDigest:r.resultDigest,rawReportDigest:r.rawReportDigest,findingCount:0,autoCloseHistoricalFindings:false};
  if(!target){records.push({...record,mappingStatus:'NOT_CONFIGURED',reason:'PROJECT_MAPPING_NOT_CONFIGURED'});continue;}
  if(r.executionStatus!=='COMPLETED'){records.push({...record,mappingStatus:'NO_IMPORT',reason:'NONCOMPLETED_STATE_PRESERVES_HISTORY'});continue;}
  if(r.pluginId==='cosign'){records.push({...record,mappingStatus:'UNSUPPORTED',reason:r.policyDecision==='PASS'?'VERIFIED_SIGNATURE_IS_NOT_A_FINDING':'SUPPLY_CHAIN_VIOLATION_WITHOUT_APPROVED_FINDING_MAPPING'});continue;}
  if(!['gitleaks','semgrep'].includes(r.pluginId)){records.push({...record,mappingStatus:'NOT_CONFIGURED',reason:'FUTURE_PLUGIN_MAPPING_NOT_IMPLEMENTED'});continue;}
  try{
   must(r.evaluationCount===1&&r.policy?.factDigest===r.factDigest&&r.policy.evaluation?.decision===r.policyDecision,'POLICY_RESULT_BINDING');
   must(r.runtimeFacts?.validationRunId===summary.runId&&r.runtimeFacts?.projectId===summary.projectId&&r.runtimeFacts?.rawReportDigest===r.rawReportDigest&&r.runtimeFacts?.factDigest===r.factDigest,'RUNTIME_RESULT_BINDING');
   const raw=readReport(dir,r.pluginId+'.raw.json',seal),fact=readReport(dir,r.pluginId+'.facts.json',seal);must(sha(raw.bytes)===r.rawReportDigest&&digest(fact.data)===r.factDigest,'RAW_FACT_RESULT_DIGEST_MISMATCH');
   const mapped=normalizedFindings(r,fact.data,raw.data),byId=new Map();
   for(const m of mapped){const id=m.finding.unique_id_from_tool;if(byId.has(id))byId.get(id).nb_occurences++;else byId.set(id,m.finding);}
   const title='Security Manager '+summary.projectId+' '+r.pluginId+' directory-no-git-history';
   const payload={name:title,type:'Generic Findings Import',version:MAPPING.mappingVersion,findings:[...byId.values()].sort((a,b)=>a.unique_id_from_tool.localeCompare(b.unique_id_from_tool))};validatePayload(payload);
   const payloadDigest=digest(payload),idempotencyKey=digest({version:MAPPING.mappingVersion,projectId:summary.projectId,pluginId:r.pluginId,runId:summary.runId,resultDigest:r.resultDigest,payloadDigest});
   const parameters={scan_type:'Generic Findings Import',test_title:title,minimum_severity:'Info',active:true,verified:false,close_old_findings:false,close_old_findings_product_scope:false,auto_create_context:false,push_to_jira:false,do_not_reactivate:true};
   imports.push({pluginId:r.pluginId,payload,payloadDigest,idempotencyKey,target:{...target,testTitle:title},parameters,apiRequestReady:false,remoteContextStatus:'NOT_CONFIGURED',factDigest:r.factDigest,resultDigest:r.resultDigest});records.push({...record,mappingStatus:'PREPARED',findingCount:payload.findings.length,payloadDigest,idempotencyKey});
  }catch(e){records.push({...record,mappingStatus:'ERROR',reason:e instanceof ConsumerError?e.code:'REPORT_OR_MAPPING_ERROR'});}
 }
 const body={schemaVersion:1,kind:'DefectDojoOfflineDeliveryPlan',consumerVersion:MAPPING.consumerVersion,mappingVersion:MAPPING.mappingVersion,sourceSchemaVersion:summary.schemaVersion,projectId:summary.projectId,profile:summary.profile,runId:summary.runId,inputSummaryDigest:digest(summary),artifactSealDigest:expectedSealDigest,records,imports,historyActions:[],remoteRequests:0,remoteDelivery:'NOT_TESTED',remoteIdempotency:'NOT_TESTED',promotionAllowed:false};
 return freeze({...body,planDigest:digest(body)});
}
export function validatePlan(plan){
 must(plan&&same(Object.keys(plan).sort(),['schemaVersion','kind','consumerVersion','mappingVersion','sourceSchemaVersion','projectId','profile','runId','inputSummaryDigest','artifactSealDigest','records','imports','historyActions','remoteRequests','remoteDelivery','remoteIdempotency','promotionAllowed','planDigest'].sort()),'PLAN_FIELDS');
 must(plan.schemaVersion===1&&plan.sourceSchemaVersion===1&&plan.consumerVersion===MAPPING.consumerVersion&&plan.mappingVersion===MAPPING.mappingVersion&&hex(plan.inputSummaryDigest)&&hex(plan.artifactSealDigest)&&plan.promotionAllowed===false,'PLAN_IDENTITY');safe(plan.projectId,80);safe(plan.runId,100);
 must(Array.isArray(plan.imports)&&plan.imports.length<=2&&Array.isArray(plan.records)&&new Set(plan.records.map(r=>r.pluginId)).size===plan.records.length,'PLAN_COLLECTIONS');
 for(const r of plan.records){
  must(Object.keys(r).every(k=>['pluginId','executionStatus','policyDecision','evaluationCount','factDigest','resultDigest','rawReportDigest','findingCount','autoCloseHistoricalFindings','mappingStatus','reason','payloadDigest','idempotencyKey'].includes(k)),'RECORD_FIELDS');safe(r.pluginId,60);
  must(hex(r.resultDigest)&&[r.rawReportDigest,r.factDigest,r.payloadDigest??null,r.idempotencyKey??null].every(x=>x===null||hex(x))&&r.autoCloseHistoricalFindings===false&&[0,1].includes(r.evaluationCount)&&[null,'PASS','WARN','FAIL'].includes(r.policyDecision),'RECORD_IDENTITY');
  must(['COMPLETED','DISABLED','SKIPPED','NOT_CONFIGURED','UNSUPPORTED','ERROR','POLICY_ERROR'].includes(r.executionStatus)&&['NO_IMPORT','NOT_CONFIGURED','PREPARED','UNSUPPORTED','ERROR'].includes(r.mappingStatus),'RECORD_STATUS');
  if(r.reason!==undefined)must(typeof r.reason==='string'&&/^[A-Z_]{3,80}$/.test(r.reason),'RECORD_DIAGNOSTIC');
 }
 const {planDigest,...body}=plan;must(digest(body)===planDigest,'PAYLOAD_DIGEST_MISMATCH');
 must(plan.kind==='DefectDojoOfflineDeliveryPlan'&&plan.remoteRequests===0&&plan.remoteDelivery==='NOT_TESTED'&&plan.remoteIdempotency==='NOT_TESTED'&&Array.isArray(plan.historyActions)&&!plan.historyActions.length,'REMOTE_OR_HISTORY_ACTION_PROHIBITED');
 for(const i of plan.imports){
  must(same(Object.keys(i).sort(),['pluginId','payload','payloadDigest','idempotencyKey','target','parameters','apiRequestReady','remoteContextStatus','factDigest','resultDigest'].sort())&&['gitleaks','semgrep'].includes(i.pluginId),'IMPORT_FIELDS');
  const title='Security Manager '+plan.projectId+' '+i.pluginId+' directory-no-git-history';
  const expectedParameters={scan_type:'Generic Findings Import',test_title:title,minimum_severity:'Info',active:true,verified:false,close_old_findings:false,close_old_findings_product_scope:false,auto_create_context:false,push_to_jira:false,do_not_reactivate:true};
  must(same(i.parameters,expectedParameters)&&i.target.testTitle===title&&i.payload.name===title&&i.remoteContextStatus==='NOT_CONFIGURED','IMPORT_CONTEXT');
  const record=plan.records.find(r=>r.pluginId===i.pluginId);must(record?.mappingStatus==='PREPARED'&&record.resultDigest===i.resultDigest&&record.factDigest===i.factDigest&&record.payloadDigest===i.payloadDigest,'IMPORT_RESULT_BINDING');
  must(digest({version:MAPPING.mappingVersion,projectId:plan.projectId,pluginId:i.pluginId,runId:plan.runId,resultDigest:i.resultDigest,payloadDigest:i.payloadDigest})===i.idempotencyKey,'IDEMPOTENCY_IDENTITY');
  validatePayload(i.payload);must(digest(i.payload)===i.payloadDigest,'PAYLOAD_DIGEST_MISMATCH');must(same(projectTarget(plan.projectId,plan.profile),Object.fromEntries(Object.entries(i.target).filter(([k])=>k!=='testTitle'))),'INVALID_PROJECT_MAPPING');must(i.parameters.close_old_findings===false&&i.parameters.close_old_findings_product_scope===false&&i.parameters.auto_create_context===false&&i.apiRequestReady===false,'HISTORY_CLOSE_PROHIBITED');}
 return true;
}
export function publishDefectDojo(plan,{output,mode='dry-run',destination=null,token=null}={}){
 must(mode==='dry-run'&&destination===null&&token===null,'REMOTE_DESTINATION_OR_CREDENTIAL_PROHIBITED');validatePlan(plan);
 const key=digest({consumerId:DEFINITION.consumerId,planDigest:plan.planDigest}),root=path.resolve(output);must(fs.realpathSync(root)===root,'OUTPUT_BOUNDARY');
 const target=path.join(root,'defectdojo-'+key);let reused=false,seal;
 if(fs.existsSync(target)){
  const s=fs.lstatSync(target);must(s.isDirectory()&&!s.isSymbolicLink(),'OUTPUT_BOUNDARY');const prior=JSON.parse(fs.readFileSync(path.join(target,'offline-plan.json')));must(prior.planDigest===plan.planDigest&&same(prior,plan),'OFFLINE_IDEMPOTENCY_CONFLICT');
  const priorSeal=JSON.parse(fs.readFileSync(path.join(target,'candidate-seal.json')));verifyArtifact(target,digest(priorSeal));seal={sealDigest:digest(priorSeal)};reused=true;
 }else{
  const temp=fs.mkdtempSync(path.join(root,'.dojo-prepare-')),original=fs.lstatSync(temp),sealed=path.join(temp,'sealed');
  try{const store=artifactStore(sealed);store.put('offline-plan.json',plan);for(const i of plan.imports)store.put(i.pluginId+'.generic.json',i.payload);seal=store.finish();verifyArtifact(sealed,seal.sealDigest);must(!fs.existsSync(target),'OFFLINE_IDEMPOTENCY_CONFLICT');fs.renameSync(sealed,target);}
  finally{const now=fs.lstatSync(temp);must(now.ino===original.ino&&now.dev===original.dev&&!now.isSymbolicLink(),'PREPARATION_CLEANUP_OWNERSHIP');fs.rmSync(temp,{recursive:true});must(!fs.existsSync(temp),'PREPARATION_CLEANUP_FAILED');}
 }
 const status=!projectTarget(plan.projectId,plan.profile)?'NOT_CONFIGURED':plan.records.some(r=>r.mappingStatus==='ERROR')?'PARTIAL_ERROR':'PREPARED_OFFLINE';
 return freeze({deliveryDecision:status==='NOT_CONFIGURED'?'NOT_CONFIGURED':status==='PARTIAL_ERROR'?'ERROR':'OFFLINE_PAYLOAD_PREPARED',receiptSeal:seal.sealDigest,error:status==='PARTIAL_ERROR'?'PARTIAL_REPORT_MAPPING_FAILURE':status==='NOT_CONFIGURED'?'PROJECT_MAPPING_NOT_CONFIGURED':null,consumerVersion:MAPPING.consumerVersion,planDigest:plan.planDigest,idempotencyKey:key,reusedOfflinePayload:reused,payloadDigests:Object.fromEntries(plan.imports.map(i=>[i.pluginId,i.payloadDigest])),factDigests:Object.fromEntries(plan.records.map(r=>[r.pluginId,r.factDigest])),resultDigests:Object.fromEntries(plan.records.map(r=>[r.pluginId,r.resultDigest])),mappingRecords:plan.records,planStatus:status,temporaryPreparationRemoved:true,remoteDelivery:'NOT_TESTED',remoteIdempotency:'NOT_TESTED',httpRequestCount:0,historyActions:[],productionDelivery:false,promotionAllowed:false});
}
