#!/usr/bin/env node
import fs from 'node:fs';import {spawnSync} from 'node:child_process';import {authorizeKubectl,validateContract} from './side-effect-contract.mjs';
const file=process.env.RUNTIME_SIDE_EFFECT_CONTRACT,c=validateContract(JSON.parse(fs.readFileSync(file))),ledgerFile=file+'.objects',auditFile=file+'.audit';
const args=process.argv.slice(2),needsInput=args.includes('-f')&&args[args.indexOf('-f')+1]==='-'||args.includes('exec')&&args.includes('-i');
const input=needsInput?fs.readFileSync(0):undefined,ledger=fs.existsSync(ledgerFile)?JSON.parse(fs.readFileSync(ledgerFile)):[];
let auth;try{auth=authorizeKubectl(args,input,c,ledger);}catch(e){fs.appendFileSync(auditFile,JSON.stringify({action:'DENIED',message:e.message})+'\n');throw e;}
const invoke=a=>spawnSync(c.realKubectl,['--kubeconfig',c.kubeconfig,...a],{input,encoding:null,maxBuffer:128*1024*1024,timeout:190000,env:{PATH:'/usr/local/bin:/usr/bin:/bin',HOME:c.workspace}});
if(['exec','delete','wait','read-pod'].includes(auth.action)){
 const p=spawnSync(c.realKubectl,['--kubeconfig',c.kubeconfig,'-n',c.namespace,'get','pod',auth.name,'-o','json'],{encoding:'utf8',timeout:25000});
 if(p.status!==0||JSON.parse(p.stdout).metadata.uid!==ledger.find(o=>o.name===auth.name)?.uid)throw Error('FOREIGN_OR_MISSING_VALIDATION_POD');
}
const r=invoke(args);
if(auth.action==='create'&&r.status===0){const p=JSON.parse(r.stdout);ledger.push({name:auth.name,namespace:c.namespace,uid:p.metadata.uid,validationRunId:c.validationRunId});fs.writeFileSync(ledgerFile,JSON.stringify(ledger),{mode:0o600});}
fs.appendFileSync(auditFile,JSON.stringify({...auth,exitStatus:r.status,startedByRun:c.validationRunId})+'\n',{mode:0o600});
if(r.stdout)process.stdout.write(r.stdout);if(r.stderr)process.stderr.write(r.stderr);process.exitCode=r.status??1;
