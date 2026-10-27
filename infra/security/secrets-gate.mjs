import fs from 'node:fs';
import {isDeepStrictEqual} from 'node:util';
import {run,read,kube,requireLease,verifyTools,toolchain} from './scanner-runtime.mjs';

requireLease();verifyTools(['sops']);
if(!process.env.BUSINESS_AGE_FILE)throw Error('Scoped business age file credential required');
const identity='system:serviceaccount:devsecops-system:platform-secret-reconciler';
const targets=[['petclinic','petclinic-db'],['petclinic','rabbitmq-client'],['petclinic','petclinic-harbor-pull'],['devsecops-system','kyverno-registry-pull']];
const report={status:'failed',source:fs.readFileSync('.git-sha','utf8').trim(),secrets:[],startedAt:new Date().toISOString()};
try{
 const env={...process.env,SOPS_AGE_KEY_FILE:process.env.BUSINESS_AGE_FILE};
 const {spawnSync}=await import('node:child_process');
 for(const [namespace,name] of targets){
  const r=spawnSync(toolchain.root+'/sops',['decrypt','infra/security/secrets/'+name+'.enc.json'],{env,encoding:'utf8',timeout:15000,maxBuffer:1024*1024});
  if(r.status!==0)throw Error('SOPS decryption failed for '+name+'; secret output suppressed');
  const desired=JSON.parse(r.stdout);
  if(desired.kind!=='Secret'||desired.metadata.namespace!==namespace||desired.metadata.name!==name||!desired.data||desired.stringData)throw Error('Secret scope/format mismatch');
  const actual=read(['--as='+identity,'-n',namespace,'get','secret',name]);
  if(!isDeepStrictEqual(actual.data,desired.data)||actual.type!==desired.type)throw Error('Live credential changed; refuse stale ciphertext overwrite: '+name);
  // Values are held in memory and passed over stdin; never written to workspace or reports.
  kube(['--as='+identity,'apply','--server-side','--field-manager=platform-secret-reconciler','-f','-'],JSON.stringify(desired));
  const after=read(['--as='+identity,'-n',namespace,'get','secret',name]);
  if(after.metadata.uid!==actual.metadata.uid||!isDeepStrictEqual(after.data,actual.data))throw Error('Unexpected Secret identity/value change');
  report.secrets.push({name,namespace,uid:after.metadata.uid,valuesPreserved:true,encryptedSource:true});
 }
 const can=args=>String(kube(['auth','can-i',...args,'--as='+identity],undefined,[0,1]).stdout).trim();
 report.rbac={knownRegistryGet:can(['get','secret/kyverno-registry-pull','-n','devsecops-system']),registryForeignGet:can(['get','secret/unrelated-secret','-n','devsecops-system']),registryList:can(['list','secrets','-n','devsecops-system']),registryCreate:can(['create','secrets','-n','devsecops-system']),knownGet:can(['get','secret/petclinic-db','-n','petclinic']),foreignGet:can(['get','secret/unrelated-secret','-n','petclinic']),createSecret:can(['create','secrets','-n','petclinic']),listSecrets:can(['list','secrets','-n','petclinic']),otherNamespace:can(['get','secret/rabbitmq-auth','-n','data-infra'])};
 if(report.rbac.knownGet!=='yes'||report.rbac.knownRegistryGet!=='yes'||Object.entries(report.rbac).some(([k,v])=>!['knownGet','knownRegistryGet'].includes(k)&&v!=='no'))throw Error('Secret reconciler RBAC scope failed');
 const verifier='system:serviceaccount:devsecops-system:kyverno-admission-controller';
 const verifierCan=args=>String(kube(['auth','can-i',...args,'--as='+verifier],undefined,[0,1]).stdout).trim();
 report.verifierRbac={ownCredentialGet:verifierCan(['get','secret/kyverno-registry-pull','-n','devsecops-system']),oldCrossGet:verifierCan(['get','secret/petclinic-harbor-pull','-n','petclinic']),businessDatabaseGet:verifierCan(['get','secret/petclinic-db','-n','petclinic']),businessSecretList:verifierCan(['list','secrets','-n','petclinic'])};
 if(report.verifierRbac.ownCredentialGet!=='yes'||Object.entries(report.verifierRbac).some(([k,v])=>k!=='ownCredentialGet'&&v!=='no'))throw Error('Verifier credential boundary failed');
 report.status='success';
}finally{
 report.finishedAt=new Date().toISOString();fs.mkdirSync('.devsecops',{recursive:true});fs.writeFileSync('.devsecops/secrets-gate.json',JSON.stringify(report,null,2));
}
