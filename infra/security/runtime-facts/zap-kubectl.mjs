import fs from 'node:fs';import {spawnSync,spawn} from 'node:child_process';import {mapZapCall,validateZapBoundary} from './zap-boundary.mjs';
const file=process.env.RUNTIME_ZAP_BOUNDARY,c=validateZapBoundary(JSON.parse(fs.readFileSync(file))),ledger=file+'.objects',audit=file+'.audit';
const args=process.argv.slice(2),needs=(args.includes('-f')&&args[args.indexOf('-f')+1]==='-'),input=needs?fs.readFileSync(0):undefined,objects=fs.existsSync(ledger)?JSON.parse(fs.readFileSync(ledger)):[];
let call;try{call=mapZapCall(args,input,c,objects);}catch(e){fs.appendFileSync(audit,JSON.stringify({action:'DENIED',error:e.message})+'\n');throw e;}
const env={PATH:'/usr/local/bin:/usr/bin:/bin',HOME:c.workspace};
if(call.uid&&call.action!=='delete'){
 const v=spawnSync(c.realKubectl,['--kubeconfig',c.kubeconfig,'-n',c.namespace,'get','pod',call.name,'--ignore-not-found','-o','json'],{encoding:'utf8',env,timeout:25000});const absent=v.status===0&&!v.stdout.trim();if(v.status!==0||absent&&!call.args.includes('--ignore-not-found')||!absent&&JSON.parse(v.stdout).metadata.uid!==call.uid)throw Error('ZAP_BOUNDARY_ERROR: replacement or unexpectedly absent Pod');
}
const r=call.action==='exec'?await new Promise(resolve=>{const p=spawn(c.realKubectl,['--kubeconfig',c.kubeconfig,...call.args],{stdio:'inherit',env});p.once('error',()=>resolve({status:1}));p.once('close',(status)=>resolve({status}));}):spawnSync(c.realKubectl,['--kubeconfig',c.kubeconfig,...call.args],{input:call.input,encoding:null,maxBuffer:32*1024*1024,timeout:250000,env});
if(call.action==='create'&&r.status===0){const p=JSON.parse(r.stdout);objects.push({namespace:c.namespace,name:p.metadata.name,uid:p.metadata.uid,validationRunId:c.validationRunId});fs.writeFileSync(ledger,JSON.stringify(objects),{mode:0o600});}
if(call.action==='read-target'&&r.status===0){const v=JSON.parse(r.stdout);if(v.metadata.namespace!==c.namespace||(v.kind==='Service'&&v.spec.clusterIP!==c.targetServiceIP)||(v.kind==='Deployment'&&v.spec.template.spec.containers[0].image!==c.targetImage))throw Error('ZAP_BOUNDARY_ERROR: target identity drift');}
fs.appendFileSync(audit,JSON.stringify({action:call.action,name:call.name,logicalNamespace:args.includes('-n')?args[args.indexOf('-n')+1]:null,physicalNamespace:call.namespace??null,exitStatus:r.status,uid:call.uid??null,at:new Date().toISOString()})+'\n',{mode:0o600});
if(r.stdout)process.stdout.write(r.stdout);if(r.stderr)process.stderr.write(r.stderr);process.exitCode=r.status??1;
