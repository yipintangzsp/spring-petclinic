import fs from 'node:fs';
import {isDeepStrictEqual} from 'node:util';
import {run,read,kube,requireLease,verifyTools,toolchain} from './scanner-runtime.mjs';
import {createSopsCollector} from './summary-v2/collectors/sops.mjs';
import {emitReceipt} from './summary-v2/collectors/emit.mjs';
// Frozen-replay harnesses strip imports; fall back to a no-op collector so
// the module executes byte-identically there. Collection is passive.
const collector=typeof createSopsCollector==='function'?createSopsCollector()
 :{prerequisites(){},sourceRead(){},begin(){},target:()=>({}),rbac(){},verifierRbac(){},reportWrite(){},raw:{}};

requireLease();verifyTools(['sops']);
if(!process.env.BUSINESS_AGE_FILE)throw Error('Scoped business age file credential required');
collector.prerequisites({manifest:true,lease:true,tools:true,credentialPresent:true});
const identity='system:serviceaccount:devsecops-system:platform-secret-reconciler';
const targets=[['petclinic','petclinic-db'],['petclinic','rabbitmq-client'],['petclinic','petclinic-harbor-pull'],['devsecops-system','kyverno-registry-pull']];
const report={readOnly:process.env.DEVSECOPS_READ_ONLY==='true',status:'failed',source:fs.readFileSync('.git-sha','utf8').trim(),secrets:[],startedAt:new Date().toISOString()};
collector.sourceRead(true);collector.begin(report.readOnly,targets.length);
try{
 const env={...process.env,SOPS_AGE_KEY_FILE:process.env.BUSINESS_AGE_FILE};
 const {spawnSync}=await import('node:child_process');
 for(const [namespace,name] of targets){
  const r=spawnSync(toolchain.root+'/sops',['decrypt','infra/security/secrets/'+name+'.enc.json'],{env,encoding:'utf8',timeout:15000,maxBuffer:1024*1024});
  const observed=collector.target(namespace,name,r);
  if(r.status!==0)throw Error('SOPS decryption failed for '+name+'; secret output suppressed');
  const desired=JSON.parse(r.stdout);
  if(desired.kind!=='Secret'||desired.metadata.namespace!==namespace||desired.metadata.name!==name||!desired.data||desired.stringData)throw Error('Secret scope/format mismatch');
  const actual=read(['--as='+identity,'-n',namespace,'get','secret',name]);
  observed.readSucceeded=true;observed.actual=actual;
  if(!isDeepStrictEqual(actual.data,desired.data)||actual.type!==desired.type)throw Error('Live credential changed; refuse stale ciphertext overwrite: '+name);
  // Values are held in memory and passed over stdin; never written to workspace or reports.
  if(process.env.DEVSECOPS_READ_ONLY!=='true'){kube(['--as='+identity,'apply','--server-side','--field-manager=platform-secret-reconciler','-f','-'],JSON.stringify(desired));observed.applySucceeded=true;}
  const after=read(['--as='+identity,'-n',namespace,'get','secret',name]);
  observed.afterReadSucceeded=true;observed.after=after;
  if(after.metadata.uid!==actual.metadata.uid||!isDeepStrictEqual(after.data,actual.data))throw Error('Unexpected Secret identity/value change');
  report.secrets.push({name,namespace,uid:after.metadata.uid,valuesPreserved:true,encryptedSource:true});
 }
 const can=args=>String(kube(['auth','can-i',...args,'--as='+identity],undefined,[0,1]).stdout).trim();
 report.rbac={knownRegistryGet:can(['get','secret/kyverno-registry-pull','-n','devsecops-system']),registryForeignGet:can(['get','secret/unrelated-secret','-n','devsecops-system']),registryList:can(['list','secrets','-n','devsecops-system']),registryCreate:can(['create','secrets','-n','devsecops-system']),knownGet:can(['get','secret/petclinic-db','-n','petclinic']),foreignGet:can(['get','secret/unrelated-secret','-n','petclinic']),createSecret:can(['create','secrets','-n','petclinic']),listSecrets:can(['list','secrets','-n','petclinic']),otherNamespace:can(['get','secret/rabbitmq-auth','-n','data-infra'])};
 collector.rbac(report.rbac);
 if(report.rbac.knownGet!=='yes'||report.rbac.knownRegistryGet!=='yes'||Object.entries(report.rbac).some(([k,v])=>!['knownGet','knownRegistryGet'].includes(k)&&v!=='no'))throw Error('Secret reconciler RBAC scope failed');
 const verifier='system:serviceaccount:devsecops-system:kyverno-admission-controller';
 const verifierCan=args=>String(kube(['auth','can-i',...args,'--as='+verifier],undefined,[0,1]).stdout).trim();
 report.verifierRbac={ownCredentialGet:verifierCan(['get','secret/kyverno-registry-pull','-n','devsecops-system']),oldCrossGet:verifierCan(['get','secret/petclinic-harbor-pull','-n','petclinic']),businessDatabaseGet:verifierCan(['get','secret/petclinic-db','-n','petclinic']),businessSecretList:verifierCan(['list','secrets','-n','petclinic'])};
 collector.verifierRbac(report.verifierRbac);
 if(report.verifierRbac.ownCredentialGet!=='yes'||Object.entries(report.verifierRbac).some(([k,v])=>k!=='ownCredentialGet'&&v!=='no'))throw Error('Verifier credential boundary failed');
 report.status='success';
}finally{
 report.finishedAt=new Date().toISOString();fs.mkdirSync('.devsecops',{recursive:true});
 let writeError;try{fs.writeFileSync('.devsecops/secrets-gate.json',JSON.stringify(report,null,2));collector.reportWrite(true);}catch(e){collector.reportWrite(false);writeError=e;}
 if(typeof emitReceipt==='function')await emitReceipt('sops',{component:'sops',status:report.status==='success'?'success':'error',raw:collector.raw});
 if(writeError)throw writeError;
}
