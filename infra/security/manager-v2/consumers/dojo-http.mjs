// Candidate HTTP protocol only: no real destination, scanner or Policy evaluation.
import fs from 'node:fs';
import path from 'node:path';
import http from 'node:http';
import {canonical,digest,sha,freeze} from '../../summary-v2/codec.mjs';
import {prepareDefectDojo,validatePlan} from './defectdojo.mjs';

export const TARGETS=freeze(JSON.parse(fs.readFileSync(new URL('./dojo-http-targets-v1.json',import.meta.url))));
export const HTTP_CONSUMER=freeze({consumerId:'defectdojo-http-candidate',consumerVersion:'1.0.0-http-candidate.1',defaultEnabled:false,realDeliveryApproved:false});
const transports=new WeakMap();
const own=(o,allowed)=>o&&typeof o==='object'&&!Array.isArray(o)&&Object.keys(o).every(k=>allowed.includes(k));
const must=(yes,code)=>{if(!yes){const e=Error(code);e.code=code;throw e;}};
const id=x=>Number.isSafeInteger(x)&&x>1;
const delay=ms=>new Promise(r=>setTimeout(r,ms));
const safeCode=e=>/^[A-Z_]{3,80}$/.test(e?.code??'')?e.code:'HTTP_CONSUMER_INPUT_REJECTED';
const within=(a,b)=>a===b||a.startsWith(b+path.sep);
function privateDirectory(name){
 must(typeof name==='string'&&path.isAbsolute(name),'PRIVATE_DIRECTORY_REQUIRED');
 const p=path.resolve(name),s=fs.lstatSync(p);
 must(!s.isSymbolicLink()&&s.isDirectory()&&fs.realpathSync(p)===p&&s.uid===process.getuid()&&(s.mode&0o077)===0,'PRIVATE_DIRECTORY_REQUIRED');
 return {path:p,inode:s.ino,device:s.dev};
}
function checkDirectory(d){const s=fs.lstatSync(d.path);must(s.isDirectory()&&!s.isSymbolicLink()&&s.ino===d.inode&&s.dev===d.device&&s.uid===process.getuid()&&(s.mode&0o077)===0,'JOURNAL_DIRECTORY_REPLACED');}
function credential(name,target){
 must(typeof name==='string'&&path.isAbsolute(name)&&fs.realpathSync(name)===name,'PROTECTED_CREDENTIAL_REQUIRED');
 privateDirectory(path.dirname(name));const fd=fs.openSync(name,fs.constants.O_RDONLY|fs.constants.O_NOFOLLOW|fs.constants.O_NONBLOCK);
 try{
  const s=fs.fstatSync(fd);must(s.isFile()&&s.nlink===1&&s.uid===process.getuid()&&(s.mode&0o077)===0&&s.size>=24&&s.size<=256,'PROTECTED_CREDENTIAL_REQUIRED');
  const token=fs.readFileSync(fd,'utf8').trim();must((target.classification==='REAL_CONTROLLED_NONPRODUCTION'?/^[a-f0-9]{40}$/.test(token):token.startsWith(target.credentialPrefix)&&/^[A-Za-z0-9_-]{24,250}$/.test(token)),'TARGET_CREDENTIAL_FORMAT_INVALID');return token;
 }finally{fs.closeSync(fd);}
}
export function createHttpTransport(options={}){
 must(own(options,['enabled','targetId','credentialFile','timeoutMs','maxGetAttempts','backoffMs']),'HTTP_CONFIG_FIELDS');
 const {enabled=false,targetId=null,credentialFile=null,timeoutMs=2000,maxGetAttempts=3,backoffMs=25}=options;
 must(typeof enabled==='boolean','HTTP_CONFIG_FIELDS');
 const handle=Object.freeze({kind:'DefectDojoCandidateHttpTransport',enabled});
 if(!enabled){transports.set(handle,{enabled:false});return handle;}
 must(Object.hasOwn(TARGETS.targets,targetId??''),'TARGET_NOT_ALLOWLISTED');
 const target=TARGETS.targets[targetId];
 const real=targetId==='dojo-demo-java-v1'&&TARGETS.realTargets.includes(targetId)&&target.classification==='REAL_CONTROLLED_NONPRODUCTION'&&target.origin==='http://192.168.64.11:18095'&&target.productId===7&&target.engagementId===4&&target.credentialIdentity==='security-manager-v2-demo';
 must(real||target.classification==='MOCK_PROTOCOL_ONLY'&&target.origin==='http://127.0.0.1:32185'&&id(target.productId)&&id(target.engagementId),'TARGET_APPROVAL_REQUIRED');
 must(Number.isInteger(timeoutMs)&&timeoutMs>=20&&timeoutMs<=10000&&Number.isInteger(maxGetAttempts)&&maxGetAttempts>=1&&maxGetAttempts<=3&&Number.isInteger(backoffMs)&&backoffMs>=1&&backoffMs<=1000,'HTTP_BUDGET_INVALID');
 const token=credential(credentialFile,target);
 transports.set(handle,{enabled:true,targetId,target,token,timeoutMs,maxGetAttempts,backoffMs});return handle;
}
function request(state,method,endpoint,body=null){
 must(method==='GET'||method==='POST','HTTP_METHOD_FORBIDDEN');
 must(/^\/api\/v2\/(?:products\/\d+\/|engagements\/\d+\/|tests\/\d+\/|tests\/\?limit=100&engagement=\d+|findings\/\?limit=100&test=\d+|import-scan\/)$/.test(endpoint),'HTTP_PATH_FORBIDDEN');
 return new Promise(resolve=>{
  let settled=false,connected=false;const chunks=[];let size=0;
  const finish=x=>{if(!settled){settled=true;clearTimeout(timer);resolve(x);}};
  const u=new URL(endpoint,state.target.origin);
  const req=http.request({hostname:u.hostname,port:Number(u.port),path:u.pathname+u.search,method,agent:false,maxHeaderSize:8192,headers:{Authorization:'Token '+state.token,Accept:'application/json',...(body?{'Content-Type':body.contentType,'Content-Length':body.bytes.length}:{})}},res=>{
   res.on('data',chunk=>{size+=chunk.length;if(size>128*1024){finish({status:res.statusCode,error:'HTTP_RESPONSE_TOO_LARGE',connected});res.destroy();req.destroy();}else chunks.push(chunk);});
   res.on('aborted',()=>finish({status:res.statusCode,error:'HTTP_RESPONSE_LOST',connected}));
   res.on('error',()=>finish({status:res.statusCode,error:'HTTP_RESPONSE_LOST',connected}));
   res.on('end',()=>{
    // Never follow Location or pagination URLs. Never copy a remote diagnostic.
    const status=res.statusCode;let data=null,error=null;
    try{data=JSON.parse(Buffer.concat(chunks).toString('utf8'));}catch{error='HTTP_RESPONSE_MALFORMED';}
    if(!String(res.headers['content-type']??'').toLowerCase().startsWith('application/json'))error='HTTP_RESPONSE_CONTENT_TYPE_INVALID';
    finish({status,data,error,connected});
   });
  });
  const timer=setTimeout(()=>{finish({status:null,error:'HTTP_TIMEOUT',connected});req.destroy();},state.timeoutMs);
  req.on('socket',socket=>socket.once('connect',()=>{connected=true;}));
  req.on('error',e=>finish({status:null,error:e.code==='ECONNREFUSED'?'HTTP_CONNECTION_REFUSED':'HTTP_CONNECTION_FAILED',connected}));
  if(body)req.end(body.bytes);else req.end();
 });
}
function bodyFor(item,target,requestDigest,plan){
 const title=item.parameters.test_title+' ['+requestDigest.slice(0,20)+']';must(title.length<=200,'HTTP_TITLE_LIMIT');
 // Import serializer has no do_not_reactivate field. It belongs to reimport;
 // this stage never reimports and never uses implicit close-old defaults.
 const fields={engagement:String(target.engagementId),scan_type:'Generic Findings Import',test_title:title,minimum_severity:'Info',active:'true',verified:'false',close_old_findings:'false',close_old_findings_product_scope:'false',auto_create_context:'false',push_to_jira:'false',deduplication_execution_mode:'sync',build_id:'smv2-'+requestDigest,version:item.payloadDigest};
 if(target.classification==='REAL_CONTROLLED_NONPRODUCTION'){fields.branch_tag=plan.runId;fields.commit_hash=item.resultDigest;}
 const boundary='smv2-'+requestDigest;const pieces=[];
 for(const [k,v]of Object.entries(fields))pieces.push(Buffer.from('--'+boundary+'\r\nContent-Disposition: form-data; name="'+k+'"\r\n\r\n'+v+'\r\n'));
 pieces.push(Buffer.from('--'+boundary+'\r\nContent-Disposition: form-data; name="file"; filename="'+item.pluginId+'.generic.json"\r\nContent-Type: application/json\r\n\r\n'+canonical(item.payload)+'\r\n--'+boundary+'--\r\n'));
 const bytes=Buffer.concat(pieces);must(bytes.length<=80*1024,'HTTP_REQUEST_TOO_LARGE');return {bytes,contentType:'multipart/form-data; boundary='+boundary,title,buildId:fields.build_id,version:fields.version};
}
function journal(root,key){
 checkDirectory(root);const prefix='dojo-http-'+key;
 function entries(){
  checkDirectory(root);const names=fs.readdirSync(root.path).filter(n=>n.startsWith(prefix+'-')&&n.endsWith('.json')).sort(),out=[];
  for(const name of names){
   must(new RegExp('^'+prefix+'-[0-9]{5}\\.json$').test(name),'JOURNAL_ENTRY_INVALID');const fd=fs.openSync(path.join(root.path,name),fs.constants.O_RDONLY|fs.constants.O_NOFOLLOW|fs.constants.O_NONBLOCK);
   try{const s=fs.fstatSync(fd);must(s.isFile()&&s.nlink===1&&s.uid===process.getuid()&&(s.mode&0o077)===0&&s.size<32768,'JOURNAL_ENTRY_INVALID');const r=JSON.parse(fs.readFileSync(fd)),{receiptDigest,...body}=r;must(digest(body)===receiptDigest&&r.requestDigest===key&&r.sequence===out.length+1&&r.previousReceiptDigest===(out.at(-1)?.receiptDigest??null),'JOURNAL_CHAIN_INVALID');out.push(r);}finally{fs.closeSync(fd);}
  }
  return out;
 }
 function append(body){const prior=entries();must(prior.length<99999,'JOURNAL_LIMIT');checkDirectory(root);const value={...body,sequence:prior.length+1,previousReceiptDigest:prior.at(-1)?.receiptDigest??null},r={...value,receiptDigest:digest(value)},fd=fs.openSync(path.join(root.path,prefix+'-'+String(value.sequence).padStart(5,'0')+'.json'),fs.constants.O_WRONLY|fs.constants.O_CREAT|fs.constants.O_EXCL|fs.constants.O_NOFOLLOW,0o400);try{fs.writeFileSync(fd,canonical(r)+'\n');fs.fsyncSync(fd);}finally{fs.closeSync(fd);}checkDirectory(root);const dirfd=fs.openSync(root.path,fs.constants.O_RDONLY);try{fs.fsyncSync(dirfd);}finally{fs.closeSync(dirfd);}return freeze(r);}
 return {entries,append,lock:path.join(root.path,prefix+'.lock')};
}
function targetIdentity(state){return {catalogVersion:TARGETS.version,targetId:state.targetId,classification:state.target.classification,origin:state.target.origin,productId:state.target.productId,engagementId:state.target.engagementId,credentialIdentity:state.target.credentialIdentity};}
function requestIdentity(plan,item,state){return digest({version:'dojo-http-request-v1',target:targetIdentity(state),planDigest:plan.planDigest,pluginId:item.pluginId,resultDigest:item.resultDigest,payloadDigest:item.payloadDigest});}
async function deliverItem(plan,item,state,root){
 must(item.payload.findings.length<=32&&Buffer.byteLength(canonical(item.payload))<=64*1024,'HTTP_PAYLOAD_LIMIT');
 const target=targetIdentity(state),requestDigest=requestIdentity(plan,item,state),body=bodyFor(item,state.target,requestDigest,plan),j=journal(root,requestDigest);
 const common={schemaVersion:1,kind:'DefectDojoHttpDeliveryReceipt',...HTTP_CONSUMER,runId:plan.runId,projectId:plan.projectId,pluginId:item.pluginId,targetIdentity:target,requestDigest,resultDigest:item.resultDigest,factDigest:item.factDigest,payloadDigest:item.payloadDigest,planDigest:plan.planDigest,deliveryAttempt:0,httpStatus:null,remoteObjectReference:null,retryState:'NONE',redactedError:null,classification:state.target.classification==='REAL_CONTROLLED_NONPRODUCTION'?'REAL_NONPRODUCTION_HTTP':'MOCK_HTTP_PROTOCOL_ONLY',realRemoteDelivery:'NOT_TESTED',remoteIdempotency:'NOT_TESTED',productionDelivery:false,promotionAllowed:false,historyActions:[]};
 const make=(deliveryState,extra={})=>({...common,deliveryState,timestamp:new Date().toISOString(),...extra});
 let previous=j.entries(),locked=false,lockStat;
 if(fs.existsSync(j.lock)){const r=make('NOT_SENT',{retryState:'LOCKED_REQUIRES_OPERATOR_REVIEW',redactedError:'DELIVERY_LOCK_HELD'});return freeze({...r,receiptDigest:digest(r)});}
 try{fs.mkdirSync(j.lock,{mode:0o700});locked=true;lockStat=fs.lstatSync(j.lock);}catch{must(false,'DELIVERY_LOCK_UNAVAILABLE');}
 try{
  previous=j.entries();const oldAck=previous.findLast(r=>r.deliveryState==='ACKNOWLEDGED');
  if(oldAck){must(oldAck.resultDigest===item.resultDigest&&oldAck.payloadDigest===item.payloadDigest,'JOURNAL_BINDING_MISMATCH');return j.append(make('ACKNOWLEDGED',{deliveryAttempt:oldAck.deliveryAttempt,httpStatus:oldAck.httpStatus,remoteObjectReference:oldAck.remoteObjectReference,retryState:'LOCAL_ACK_RECEIPT_REUSED_NO_HTTP',acknowledgedAt:oldAck.acknowledgedAt??oldAck.timestamp,remoteReferenceSource:'VERIFIED_PRIOR_LOCAL_ACK_RECEIPT',httpRequestCount:0}));}
  const priorSent=previous.some(r=>r.deliveryState==='SENT');let httpCount=0;
  const get=async endpoint=>{
   let r;
   for(let n=1;n<=state.maxGetAttempts;n++){
    r=await request(state,'GET',endpoint);httpCount++;
    const retry=r.status===429||[500,502,503,504].includes(r.status)||r.status===null;
    j.append(make('PREPARED',{httpStatus:r.status,retryState:retry&&n<state.maxGetAttempts?'READ_ONLY_RETRY_SCHEDULED':'NONE',redactedError:r.error??(retry?'HTTP_READ_RETRYABLE':null),operation:'READ_ONLY_VERIFY',readAttempt:n,httpRequestCount:httpCount}));
    if(!retry||n===state.maxGetAttempts)break;await delay(Math.min(state.backoffMs*2**(n-1),1000));
   }
   return r;
  };
  const unknown=(code,status=null,extra={})=>j.append(make('UNKNOWN_REMOTE_STATE',{deliveryAttempt:1,httpStatus:status,redactedError:code,retryState:'NO_MUTATION_RETRY_READ_ONLY_RECONCILIATION_REQUIRED',httpRequestCount:httpCount,...extra}));
  const rejectGet=r=>{
   const transient=r.status===null||[429,500,502,503,504].includes(r.status);
   return j.append(make(priorSent?'UNKNOWN_REMOTE_STATE':transient?'RETRYABLE_FAILURE':'REJECTED',{httpStatus:r.status,redactedError:r.error??(r.status>=300&&r.status<400?'UNAPPROVED_REDIRECT':'HTTP_CONTEXT_REJECTED'),retryState:priorSent?'NO_MUTATION_RETRY_READ_ONLY_RECONCILIATION_REQUIRED':transient?'READ_ONLY_RETRIES_EXHAUSTED':'NOT_RETRYABLE',httpRequestCount:httpCount}));
  };
  j.append(make('PREPARED',{retryState:priorSent?'RECOVER_PREVIOUS_SEND_READ_ONLY':'NONE'}));
  for(const [endpoint,check] of [
   ['/api/v2/products/'+state.target.productId+'/',x=>x?.id===state.target.productId&&x.name===state.target.productName],
   ['/api/v2/engagements/'+state.target.engagementId+'/',x=>x?.id===state.target.engagementId&&x.name===state.target.engagementName&&x.product===state.target.productId]
  ]){const r=await get(endpoint);if(r.status!==200||r.error)return rejectGet(r);if(!check(r.data))return j.append(make(priorSent?'UNKNOWN_REMOTE_STATE':'REJECTED',{redactedError:'TARGET_CONTEXT_BINDING_MISMATCH',httpRequestCount:httpCount}));}
  const tests=await get('/api/v2/tests/?limit=100&engagement='+state.target.engagementId);
  if(tests.status!==200||tests.error)return rejectGet(tests);
  if(!Array.isArray(tests.data?.results)||tests.data.next!==null||!Number.isInteger(tests.data.count)||tests.data.count!==tests.data.results.length||tests.data.results.length>100)return j.append(make(priorSent?'UNKNOWN_REMOTE_STATE':'NOT_SENT',{redactedError:'INCOMPLETE_TEST_QUERY',httpRequestCount:httpCount}));
  const matches=tests.data.results.filter(t=>t.title===body.title);
  async function verify(testId){
   const detail=await get('/api/v2/tests/'+testId+'/');
   if(detail.status!==200||detail.error||detail.data?.id!==testId||detail.data.engagement!==state.target.engagementId||detail.data.title!==body.title||detail.data.build_id!==body.buildId||detail.data.version!==body.version||detail.data.test_type_name!=='Generic Findings Import')return false;
   const findings=await get('/api/v2/findings/?limit=100&test='+testId),d=findings.data;
   if(findings.status!==200||findings.error||!Array.isArray(d?.results)||d.next!==null||d.count!==d.results.length||d.results.length!==item.payload.findings.length)return false;
   const seen=new Set();return d.results.every(f=>{const expected=item.payload.findings.find(e=>e.unique_id_from_tool===f.unique_id_from_tool);if(!expected||seen.has(f.unique_id_from_tool)||f.test!==testId)return false;seen.add(f.unique_id_from_tool);return ['title','severity','description','file_path','line','unique_id_from_tool','vuln_id_from_tool','references'].every(k=>{
    if(k==='title'&&state.target.classification==='REAL_CONTROLLED_NONPRODUCTION'){
     // Exact two fixed-fixture titles observed from installed Finding.normalize_title (titlecase).
     const installedTitles={'[java-fixture/semgrep] java-runtime-exec':'[Java-Fixture/Semgrep] Java-Runtime-Exec','[java-fixture/semgrep] java-weak-cipher':'[Java-Fixture/Semgrep] Java-Weak-Cipher'};
     return f[k]===(installedTitles[expected[k]]??expected[k]);
    }return f[k]===expected[k];});});
  }
  if(matches.length||priorSent){
   const one=matches.length===1&&id(matches[0].id),matched=one&&await verify(matches[0].id);
   if(matched&&state.target.classification==='REAL_CONTROLLED_NONPRODUCTION'&&previous.some(r=>r.deliveryState==='SENT'&&r.requestBodyDigest===sha(body.bytes))&&previous.some(r=>r.deliveryState==='UNKNOWN_REMOTE_STATE'&&[200,201].includes(r.httpStatus))){
    return j.append(make('ACKNOWLEDGED',{deliveryAttempt:1,httpStatus:201,realRemoteDelivery:'VERIFIED',remoteObjectReference:{kind:'DefectDojoTest',id:matches[0].id,engagementId:state.target.engagementId},retryState:'PRIOR_HTTP_ACK_RECONCILED_READ_ONLY',httpRequestCount:httpCount}));
   }
   return unknown(matched?'REMOTE_MATCH_OBSERVED_ACK_NOT_PROVEN':matches.length>1?'AMBIGUOUS_REMOTE_TESTS':priorSent?'PREVIOUS_SEND_UNRESOLVED':'EXISTING_REMOTE_TEST_NOT_PROVEN',null,{recoveryStatus:matched?'EXACT_TEST_AND_FINDINGS_OBSERVED_READ_ONLY':'NOT_PROVEN',observedRemoteTestId:matched?matches[0].id:null});
  }
  // Durable SENT intent precedes dispatch. A crash cannot cause silent replay.
  // If persisting any later receipt fails, the next invocation remains blocked.
  j.append(make('SENT',{deliveryAttempt:1,retryState:'AUTOMATIC_MUTATION_RETRY_DISABLED',requestBodyDigest:sha(body.bytes)}));
  const r=await request(state,'POST','/api/v2/import-scan/',body);httpCount++;
  if([400,401,403,404].includes(r.status))return j.append(make('REJECTED',{deliveryAttempt:1,httpStatus:r.status,redactedError:'HTTP_IMPORT_REJECTED',retryState:'NOT_RETRYABLE',httpRequestCount:httpCount}));
  if(r.status===429)return j.append(make('RETRYABLE_FAILURE',{deliveryAttempt:1,httpStatus:429,redactedError:'HTTP_RATE_LIMITED',retryState:'READ_ONLY_RECONCILIATION_BEFORE_ANY_MUTATION_RETRY',httpRequestCount:httpCount}));
  if(r.error||![200,201].includes(r.status))return unknown(r.error??(r.status>=300&&r.status<400?'UNAPPROVED_REDIRECT':r.status===409?'HTTP_CONFLICT_NOT_SUCCESS':'HTTP_IMPORT_ACK_NOT_PROVEN'),r.status);
  const testId=typeof r.data?.test==='object'?r.data.test?.id:r.data?.test;
  if(!id(testId))return unknown('HTTP_RESPONSE_TEST_ID_MISSING',r.status);
  if(!await verify(testId))return unknown('HTTP_SUCCESS_NOT_BOUND_TO_EXPECTED_FACTS',r.status);
  return j.append(make('ACKNOWLEDGED',{realRemoteDelivery:state.target.classification==='REAL_CONTROLLED_NONPRODUCTION'?'VERIFIED':'NOT_TESTED',deliveryAttempt:1,httpStatus:r.status,remoteObjectReference:{kind:'DefectDojoTest',id:testId,engagementId:state.target.engagementId},retryState:'NONE',httpRequestCount:httpCount}));
 }finally{
  if(locked){const s=fs.lstatSync(j.lock);must(!s.isSymbolicLink()&&s.ino===lockStat.ino&&s.dev===lockStat.dev,'DELIVERY_LOCK_REPLACED');fs.rmdirSync(j.lock);}
 }
}
export async function deliverHttpCandidate({run,artifactDirectory,expectedSealDigest,transport,journalDirectory}){
 const state=transports.get(transport);must(state,'TRUSTED_HTTP_TRANSPORT_REQUIRED');
 const plan=prepareDefectDojo({run,artifactDirectory,expectedSealDigest});validatePlan(plan);
 const base={consumerId:HTTP_CONSUMER.consumerId,consumerVersion:HTTP_CONSUMER.consumerVersion,runId:plan.runId,projectId:plan.projectId,inputSummaryDigest:plan.inputSummaryDigest,planDigest:plan.planDigest,resultDigests:Object.fromEntries(plan.records.map(r=>[r.pluginId,r.resultDigest])),mappingRecords:plan.records,realRemoteDelivery:'NOT_TESTED',remoteIdempotency:'NOT_TESTED',productionDelivery:false,promotionAllowed:false,policyEvaluations:0,scannersStarted:0,historyActions:[]};
 if(!state.enabled)return freeze({...base,deliveryState:'NOT_SENT',redactedError:'HTTP_DISABLED_BY_DEFAULT',receipts:[],httpRequestCount:0});
 must(plan.projectId===state.target.projectId&&plan.profile===state.target.profile,'HTTP_TARGET_PROJECT_MISMATCH');
 const root=privateDirectory(journalDirectory),source=path.resolve(artifactDirectory);must(!within(root.path,source)&&!within(source,root.path),'HTTP_JOURNAL_OVERLAPS_ARTIFACT');
 const receipts=[];
 for(const item of plan.imports){
  try{receipts.push(await deliverItem(plan,item,state,root));}
  catch(e){const b={...base,pluginId:item.pluginId,targetIdentity:targetIdentity(state),requestDigest:requestIdentity(plan,item,state),resultDigest:item.resultDigest,deliveryAttempt:0,httpStatus:null,remoteObjectReference:null,deliveryState:'UNKNOWN_REMOTE_STATE',retryState:'OPERATOR_REVIEW_REQUIRED',timestamp:new Date().toISOString(),redactedError:safeCode(e)};receipts.push(freeze({...b,receiptDigest:digest(b)}));}
 }
 return freeze({...base,deliveryState:receipts.length===0?'NOT_SENT':receipts.every(r=>r.deliveryState==='ACKNOWLEDGED')?'ACKNOWLEDGED':receipts.some(r=>r.deliveryState==='UNKNOWN_REMOTE_STATE')?'UNKNOWN_REMOTE_STATE':'INCOMPLETE',redactedError:receipts.length===0?'NO_CONFIGURED_FINDING_PAYLOAD':null,receipts,httpRequestCount:receipts.reduce((n,r)=>n+(r.httpRequestCount??0),0)});
}
