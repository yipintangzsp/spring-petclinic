// Passive observation of frozen scanner parents. No replay, classifier or Policy.
import fs from 'node:fs';import cp from 'node:child_process';import crypto from 'node:crypto';import {syncBuiltinESMExports} from 'node:module';
const id=process.env.RUNTIME_FACT_SOURCE;
if(['gitleaks','semgrep-command-audit','zap'].includes(id)){
 const original={read:fs.readFileSync,write:fs.writeFileSync,mkdir:fs.mkdirSync,spawn:cp.spawnSync,asyncSpawn:cp.spawn};
 const text=x=>x==null?'':Buffer.isBuffer(x)?x.toString():String(x),hash=x=>crypto.createHash('sha256').update(x).digest('hex');
 const reports={},observations=[],sourceLines=[];let reviewed,reviewRead=false,confirmationText,approvalObject;
 const originalParse=JSON.parse;
 if(id==='zap')JSON.parse=function(v,...a){const r=originalParse(v,...a);if(confirmationText!==undefined&&String(v)===confirmationText)approvalObject=r;return r;};
 const stage=['gitleaks','zap'].includes(id)?'parent':process.argv[1]?.endsWith('/command-audit.mjs')?'command-audit':'semgrep';
 fs.readFileSync=function(p,...a){try{const r=original.read(p,...a);const name=String(p);observations.push({type:'io',key:'read:'+name,ok:true,sha256:hash(r)});
  if(id==='zap'&&name==='infra/security/zap-confirmations.json')confirmationText=text(r);
  if(name==='infra/security/reviewed-false-positives.json'){reviewRead=true;try{reviewed=JSON.parse(text(r)).entries;}catch{}}
  return r;}catch(e){observations.push({type:'io',key:'read:'+String(p),ok:false,error:e.code??e.name});throw e;}};
 fs.writeFileSync=function(p,v,...a){try{const r=original.write(p,v,...a);observations.push({type:'io',key:'write:'+String(p),ok:true,sha256:hash(v)});if(String(p).startsWith('.devsecops/')&&String(p).endsWith('.json'))reports[String(p)]=text(v);return r;}catch(e){observations.push({type:'io',key:'write:'+String(p),ok:false,error:e.code??e.name});throw e;}};
 fs.mkdirSync=function(p,...a){try{const r=original.mkdir(p,...a);observations.push({type:'io',key:'mkdir:'+String(p),ok:true});return r;}catch(e){observations.push({type:'io',key:'mkdir:'+String(p),ok:false,error:e.code??e.name});throw e;}};
 cp.spawnSync=function(bin,args,opts){const startedAt=Date.now(),r=original.spawn(bin,args,opts);let key=String(bin);
  const argv=[...args],a=bin==='kubectl'?argv.slice(argv.indexOf('--')+1):argv;
  if(bin==='kubectl'&&argv.includes('exec')&&a[0]==='gitleaks')key='scan:'+a[2];
  if(bin==='kubectl'&&argv.includes('exec')&&a[0]==='cat'&&a[1]?.startsWith('/work/source/'))text(r.stdout).split(/\r?\n/).forEach((line,i)=>sourceLines.push({path:a[1].slice('/work/source/'.length),line:i+1,sha256:hash(line)}));
  const stdout=bin==='git'&&args[0]==='archive'?undefined:text(r.stdout);
  observations.push({type:'command',key,bin:String(bin),args:argv,startedAt,completedAt:Date.now(),result:{status:r.status,signal:r.signal??null,error:r.error?{code:r.error.code??r.error.name}:null,...(stdout===undefined?{stdoutBytes:r.stdout?.length??0,stdoutSha256:hash(r.stdout??'') }:{stdout}),stderr:text(r.stderr)}});return r;};
 cp.spawn=function(bin,args,opts){const startedAt=Date.now(),p=original.asyncSpawn(bin,args,opts);p.once('error',e=>observations.push({type:'async-command',bin,args,error:e.code??e.name}));p.once('close',(status,signal)=>observations.push({type:'async-command',bin,args,status,signal,startedAt,completedAt:Date.now()}));return p;};
 syncBuiltinESMExports();process.once('exit',exitStatus=>{
  let findings=[];try{findings=JSON.parse(reports['.devsecops/source-gate.json']).sourceScan?.findings??[];}catch{}
  let zapClassifier;
  if(id==='zap'&&approvalObject){try{const r=originalParse(reports['.devsecops/zap-gate.json']);zapClassifier={report:originalParse(reports['.devsecops/zap-business-report.json']),context:{targetImage:r.targetImage,reportSha256:r.reportSha256},approved:approvalObject};}catch{}}
  const raw=id==='zap'?{schema:1,stage:'parent',complete:true,command:'node infra/security/zap-gate.mjs',execution:{exitStatus},reports,observations,...(zapClassifier?{classifierInput:zapClassifier}:{})}:id==='gitleaks'?{schema:1,stage:'parent',complete:true,command:'node infra/security/source-gate.mjs',execution:{exitStatus},reports,observations,classifierInput:reviewRead?{sourcePrefix:'/work/source/',findings,reviewedEntries:reviewed,sourceLines}:null}:{stage,execution:{exitStatus},observations,reports};
  try{original.write(3,JSON.stringify({schema:1,sourceId:id,adapterPayload:raw,events:[]})+'\n');}catch{process.exitCode=process.exitCode||74;}
 });
}
