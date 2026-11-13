// Dedicated, explicitly authorized new analysis. Original Maven Gate command
// and server-owned Quality Gate remain unchanged. No local metric re-evaluation.
import fs from 'node:fs';import path from 'node:path';import {spawn} from 'node:child_process';
import {collectRuntimeFacts} from './collector.mjs';import {sha,fail} from '../summary-v2/codec.mjs';
const command='nice -n 10 ./mvnw -B org.sonarsource.scanner.maven:sonar-maven-plugin:5.8.0.7211:sonar -Dsonar.projectKey=petclinic -Dsonar.qualitygate.wait=true -Dsonar.qualitygate.timeout=300';
export async function runMaven(command,{cwd,env,onOutput}){
 const start=Date.now(),p=spawn('/bin/sh',['-c',command],{cwd,env,stdio:['ignore','pipe','pipe']});let stdout='',stderr='',errorClass=null;
 const add=(kind,b)=>{if(kind==='stdout')stdout+=b;else stderr+=b;if(Buffer.byteLength(stdout)+Buffer.byteLength(stderr)>16*1024*1024)p.kill('SIGTERM');onOutput(kind,Buffer.from(String(b).split(env.SONAR_TOKEN??'\u0000').join('[REDACTED]')));};
 p.stdout.on('data',b=>add('stdout',b));p.stderr.on('data',b=>add('stderr',b));p.on('error',e=>{errorClass=e.code??e.name;});
 const end=await new Promise(resolve=>p.once('close',(exitStatus,signal)=>resolve({exitStatus,signal})));
 return {...end,errorClass,startedAtMs:start,completedAtMs:Date.now(),stdoutSha256:sha(stdout),stderrSha256:sha(stderr)};
}
export function taskProperties(text){const r={};for(const line of text.split(/\r?\n/)){if(!line||line.startsWith('#'))continue;const i=line.indexOf('=');if(i>0){const key=line.slice(0,i);if(Object.hasOwn(r,key))fail('Duplicate Sonar task property');r[key]=line.slice(i+1);}}return r;}
export function lineageFacts({binding,properties,task,gate,execution,sourceIdentity,reportSha256,reportMtimeMs}){
 const t=task?.task;
 if(sourceIdentity!==binding.source||properties.projectKey!==binding.project||!properties.ceTaskId||t?.id!==properties.ceTaskId||t.componentKey!==binding.project||t.status!=='SUCCESS'||!t.analysisId||
   Date.parse(t.submittedAt)<execution.startedAtMs-2000||reportMtimeMs<execution.startedAtMs-2000||!['OK','ERROR'].includes(gate?.projectStatus?.status))fail('SONAR_RUNTIME_LINEAGE_BLOCKED: current build/task/source binding missing');
 const status=gate.projectStatus.status,expected=status==='OK'?0:1;
 if((status==='OK'&&execution.exitStatus!==0)||(status==='ERROR'&&execution.exitStatus===0)||execution.signal||execution.errorClass)fail('SONAR_RUNTIME_LINEAGE_BLOCKED: original Maven Gate and authoritative status disagree');
 return {binding:{projectKey:binding.project,taskId:t.id,requestedAnalysisId:t.analysisId},task,gate,
  lineage:{validationBinding:binding,sourceRevision:sourceIdentity,reportSha256,reportMtimeMs,analysisCreatedByCurrentCommand:true,execution,
   candidateScope:'Pinned runtime target is the audit context; Sonar analyzes this verified source checkout. No image-content attestation or new image/source Gate is asserted.',expectedProcessSuccess:expected===0}};
}
export async function captureNewSonar({binding,cwd,env,onOutput,productionCommand,request=fetch}){
 if(productionCommand!==command)fail('Sonar production command identity changed');
 if(!env.SONAR_TOKEN||!env.SONAR_HOST_URL)fail('SONAR_RUNTIME_LINEAGE_BLOCKED: scoped existing credential/endpoint absent');
 const sourceIdentity=fs.readFileSync(path.join(cwd,'.git-sha'),'utf8').trim();
 if(sourceIdentity!==binding.source)fail('Sonar source checkout mismatch');
 const report=path.join(cwd,'target/sonar/report-task.txt');if(fs.existsSync(report))fail('Sonar refuses stale report-task');
 // Fresh coverage comes from this checkout, never historical Jacoco files.
 const prerequisite=await runMaven('nice -n 10 ./mvnw -B test jacoco:report',{cwd,env,onOutput});
 if(prerequisite.exitStatus!==0||prerequisite.signal||prerequisite.errorClass)fail('SONAR_RUNTIME_LINEAGE_BLOCKED: real current-source test/coverage prerequisite failed');
 const execution=await runMaven(command,{cwd,env,onOutput});
 if(!fs.existsSync(report))fail('SONAR_RUNTIME_LINEAGE_BLOCKED: fresh report-task absent');
 const bytes=fs.readFileSync(report),properties=taskProperties(String(bytes));
 if(!/^[\w-]+$/.test(properties.ceTaskId??''))fail('Malformed fresh task identity');
 const base=env.SONAR_HOST_URL,headers={Authorization:'Basic '+Buffer.from(env.SONAR_TOKEN+':').toString('base64')},queries=[];
 async function get(p){const r=await request(base+p,{method:'GET',headers,signal:AbortSignal.timeout(15000)});queries.push({method:'GET',path:p,httpStatus:r.status});if(r.status!==200)fail('Sonar exact-analysis GET rejected: '+r.status);return r.json();}
 const task=await get('/api/ce/task?id='+encodeURIComponent(properties.ceTaskId));
 if(!task.task?.analysisId)fail('Sonar task has no analysis identity');
 const gate=await get('/api/qualitygates/project_status?analysisId='+encodeURIComponent(task.task.analysisId));
 const raw=lineageFacts({binding,properties,task,gate,execution,sourceIdentity,reportSha256:sha(bytes),reportMtimeMs:fs.statSync(report).mtimeMs});
 return {envelope:collectRuntimeFacts({sourceId:'sonarqube',binding,execution:{command,exitStatus:execution.exitStatus,signal:execution.signal,errorClass:execution.errorClass},payload:raw,
  reports:[{path:'target/sonar/report-task.txt',bytes:bytes.length,sha256:sha(bytes)}],evidence:[{classification:'REAL_DEDICATED_NONRELEASE_NEW_ANALYSIS',prerequisite,queries,sourceRevision:sourceIdentity,compatibilityNegative:'DEFERRED_REAL_NEGATIVE_EVIDENCE'}]}),exitStatus:execution.exitStatus};
}
