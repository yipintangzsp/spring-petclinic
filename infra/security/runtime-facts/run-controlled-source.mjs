// Sequential transaction for a newly authorized source. No production entry import.
import fs from 'node:fs';import os from 'node:os';import path from 'node:path';import {spawnSync} from 'node:child_process';
import {captureStage} from './execute.mjs';import {createRuntimeOwner} from './owner.mjs';import {prepareSbomBuildRoot} from './sbom-build-root.mjs';import {sha} from '../summary-v2/codec.mjs';
const id=process.argv[2];if(!['gitleaks','semgrep-command-audit'].includes(id))throw Error('Source not authorized by this controlled boundary');
const run=JSON.parse(fs.readFileSync('runtime-validation-run.json')),n=Number(process.env.BUILD_NUMBER),output='.devsecops/runtime-controlled/build-'+n;fs.mkdirSync(output,{recursive:true,mode:0o700});
const adminKube=(...a)=>{const r=spawnSync('kubectl',['--request-timeout=20s',...a],{encoding:'utf8',timeout:30000});if(r.status!==0)throw Error('Read-only execution preflight failed');return JSON.parse(r.stdout);};
const deployment=adminKube('-n','petclinic','get','deployment','petclinic','-o','json'),candidate=deployment.spec.template.spec.containers.find(c=>c.name==='petclinic').image;
const binding={job:process.env.JOB_NAME,build:n,project:'petclinic',source:fs.readFileSync('.git-sha','utf8').trim(),candidate,targetScope:'runtime',runId:process.env.JOB_NAME+'#'+n};
const temp=fs.mkdtempSync('/tmp/runtime-six-'+run.validationRunId+'-');fs.chmodSync(temp,0o700);
const input='/tmp/runtime-six-credentials-'+run.validationRunId,kubeconfig=input+'/executor.kubeconfig';if(!fs.existsSync(kubeconfig))throw Error('No explicit validation-only kubeconfig; no default fallback');
const config=JSON.parse(fs.readFileSync(input+'/public-binding.json'));if(config.validationRunId!==run.validationRunId)throw Error('Validation identity mismatch');
const clean=prepareSbomBuildRoot();fs.mkdirSync(path.join(clean.directory,'.git/refs'),{recursive:true});
const owner=createRuntimeOwner({binding,directory:path.join(output,'results')}),plan=JSON.parse(fs.readFileSync('resources/security-manager/petclinic-adapter.json'));
const command=plan.find(p=>p.id===(id==='semgrep-command-audit'?'semgrep':id)).command;
const real=spawnSync('sh',['-c','command -v kubectl'],{encoding:'utf8'}).stdout.trim();if(!real.startsWith('/'))throw Error('Missing real kubectl');
const file=temp+'/contract.json',ledger=file+'.objects',audit=file+'.audit';
const lock=JSON.parse(fs.readFileSync('infra/security/tools-lock.json')),tools=JSON.parse(fs.readFileSync('infra/security/scanner-tools.json')),image=JSON.parse(fs.readFileSync('infra/messaging/dependencies.json')).runtime;
const c={schema:1,validationRunId:run.validationRunId,sourceId:id,build:n,kubeconfig,workspace:temp,realKubectl:real,server:'https://kubernetes.default.svc',namespace:'devsecops-execution',allowedImages:id==='gitleaks'?[lock.gitleaks.image]:[tools.baseImage,image],release:false,rollout:false};
fs.writeFileSync(file,JSON.stringify(c),{mode:0o600});fs.mkdirSync(temp+'/bin');fs.writeFileSync(temp+'/bin/kubectl','#!/bin/sh\nunset NODE_OPTIONS RUNTIME_FACT_SOURCE\nexec '+process.execPath+' '+path.resolve('infra/security/runtime-facts/guarded-kubectl.mjs')+' "$@"\n',{mode:0o700});
let failure=null,receipt;const startedAt=new Date().toISOString();
try{
 const rg=fs.openSync(path.join(output,'regression.log'),'wx',0o600);
 try{const r=await captureStage({sourceId:'regression',command:plan.find(p=>p.id==='regression').command,binding,onOutput:(_k,b)=>fs.writeSync(rg,b)});await owner.accept(r.envelope);owner.reuseForGate('regression',r.exitStatus===0?'success':'failed');if(r.exitStatus!==0)throw Error('Current Regression failed before source writes');}finally{fs.closeSync(rg);}
 // Execute checked-out parent bytes unchanged in exact tracked HEAD workspace.
 // Only collector observers/guard are loaded from the approved bundle outside it.
 for(const p of ['infra/security/source-gate.mjs','infra/security/command-audit.mjs','infra/security/semgrep-gate.mjs','infra/security/scanner-runtime.mjs'])if(sha(fs.readFileSync(path.join(clean.directory,p)))!==sha(fs.readFileSync(p)))throw Error('Frozen parent checkout mismatch');
 fs.mkdirSync(path.join(clean.directory,'.devsecops'),{recursive:true});
 const env={PATH:temp+'/bin:'+process.env.PATH,HOME:temp,KUBECONFIG:kubeconfig,HEAVY_HOLDER:'runtime-six-'+run.validationRunId,BUILD_NUMBER:String(n),RUNTIME_SIDE_EFFECT_CONTRACT:file,NODE_OPTIONS:'--import='+path.resolve('infra/security/runtime-facts/controlled-preload.mjs')};
 const log=fs.openSync(path.join(output,id+'.log'),'wx',0o600);
 let observed;try{observed=await captureStage({sourceId:id,command,binding,env,cwd:clean.directory,onOutput:(_k,b)=>fs.writeSync(log,b)});}finally{fs.closeSync(log);}
 const result=await owner.accept(observed.envelope),gate=owner.reuseForGate(id,observed.exitStatus===0?'success':'failed');
 const objects=fs.existsSync(ledger)?JSON.parse(fs.readFileSync(ledger)):[],ops=fs.existsSync(audit)?fs.readFileSync(audit,'utf8').trim().split('\n').filter(Boolean).map(JSON.parse):[];
 const data=observed.envelope.facts.raw;
 const operationReports=id==='gitleaks'?data.reports:Object.assign({},...data.operations.map(o=>o.reports));
 receipt={sourceId:id,executionScope:'CONTROLLED_NON_RELEASE',validationRunId:run.validationRunId,binding,inputIdentity:clean.identity,oldExit:observed.exitStatus,oldDecision:observed.exitStatus===0?'PASS':'FAIL',policyDecision:result.result.decision,rawFactDigest:result.rawFactDigest,resultDigest:result.resultDigest,gateResultDigest:gate.resultDigest,evaluationCount:owner.snapshot().evaluationCounts[id],writeOperations:ops,objects,rawOutputs:Object.entries(operationReports).map(([p,b])=>({path:p,bytes:Buffer.byteLength(b),sha256:sha(b)})),startedAt,completedAt:new Date().toISOString(),cleanupRequired:true,cleanupCompleted:false,sourceFactsPresent:true,productionReleaseMutations:0,rollout:0};
 // Redacted native reports are validation-only outputs, never copied to active V1.
 for(const [p,b] of Object.entries(operationReports)){fs.writeFileSync(path.join(output,path.basename(p)),b,{mode:0o600});}
 fs.writeFileSync(path.join(output,'owner-snapshot.json'),JSON.stringify(owner.snapshot()));
}catch(e){failure=e.message;}
finally{
 const objects=fs.existsSync(ledger)?JSON.parse(fs.readFileSync(ledger)):[],ops=fs.existsSync(audit)?fs.readFileSync(audit,'utf8').trim().split('\n').filter(Boolean).map(JSON.parse):[];
 fs.writeFileSync(path.join(output,'external-object-ledger.json'),JSON.stringify({objects,operations:ops}));
 let cleanObjects=true;for(const o of objects){const r=spawnSync(real,['--kubeconfig',kubeconfig,'-n',o.namespace,'get','pod',o.name,'--ignore-not-found','-o','name'],{encoding:'utf8',timeout:25000});if(r.status!==0||r.stdout.trim())cleanObjects=false;}
 clean.cleanup();fs.rmSync(temp,{recursive:true,force:true});
 if(receipt)receipt.cleanupCompleted=cleanObjects&&!fs.existsSync(temp)&&!fs.existsSync(clean.directory);
 fs.writeFileSync(path.join(output,'transaction-receipt.json'),JSON.stringify({...(receipt??{sourceId:id,executionScope:'CONTROLLED_NON_RELEASE',validationRunId:run.validationRunId,binding}),failure,cleanupCompleted:cleanObjects&&!fs.existsSync(temp)&&!fs.existsSync(clean.directory),productionSummaryActivated:false},null,2));
 if(!cleanObjects)throw Error('CLEANUP_FAILED_STOP_ITERATION');
}
if(failure)throw Error(failure);if(receipt.oldExit!==0)process.exitCode=1;console.log(JSON.stringify({sourceId:id,oldDecision:receipt.oldDecision,policyDecision:receipt.policyDecision,evaluationCount:1,gateDigestReused:receipt.resultDigest===receipt.gateResultDigest,cleanup:receipt.cleanupCompleted}));
