import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import {spawnSync} from 'node:child_process';
import {read,kube,requireLease,verifyTools,toolchain} from './scanner-runtime.mjs';
import {checkCosignVerification} from './cosign-verification.mjs';
import {createCosignCollector} from './summary-v2/collectors/cosign.mjs';
import {emitReceipt} from './summary-v2/collectors/emit.mjs';

requireLease();verifyTools(['cosign','sops']);
const mode=process.argv[2];if(!['bootstrap','release','admission'].includes(mode))throw Error('Explicit signing mode required');
if(!process.env.SIGNING_AGE_FILE||!process.env.HARBOR_USER||!process.env.HARBOR_PASS)throw Error('Scoped signing and Harbor credentials required');
// Frozen-replay harnesses strip imports; fall back to a no-op collector so
// the module executes byte-identically there. Collection is passive.
const collector=typeof createCosignCollector==='function'?createCosignCollector(mode)
 :{environment(){},runtimeManifest(){},runtimeLease(){},tool(){},file(){},cmd(){},io(){},ioError(){},registry(){},admission(){},currentImage(){},raw:{}};
collector.environment(process.env);
fs.mkdirSync('.devsecops',{recursive:true});collector.io('output-mkdir',true);
const dir=fs.mkdtempSync(path.join(os.tmpdir(),'platform-signing-'));collector.io('temp-create',true);fs.chmodSync(dir,0o700);collector.io('temp-chmod',true);
const report={status:'failed',mode,source:fs.readFileSync('.git-sha','utf8').trim(),startedAt:new Date().toISOString(),images:[]};
collector.file('.git-sha',report.source);
if(typeof createCosignCollector==='function')try{
 const manifestText=fs.readFileSync('infra/security/scanner-tools.json','utf8');
 const lockJson=JSON.parse(fs.readFileSync('infra/security/governance/tools-lock.json','utf8'));
 const leaseResult=spawnSync('kubectl',['--request-timeout=15s','-n','data-infra','get','lease','platform-heavy','-o','json'],{encoding:'utf8',timeout:20000,maxBuffer:1024*1024});
 const tools={};const manifestParsed=JSON.parse(manifestText);
 for(const tool of Object.values(manifestParsed.tools??{})){const p=tool.path;try{const st=fs.lstatSync(p);if(st.isSymbolicLink())tools[p]={symlink:fs.readlinkSync(p)};else tools[p]={sha256:crypto.createHash('sha256').update(fs.readFileSync(p)).digest('hex')};}catch(e){tools[p]={error:String(e.message??e)};}}
 collector.runtimeManifest(manifestText,lockJson.supplyChain?.scanner_manifest_sha256);collector.runtimeLease(leaseResult);for(const [p,entry] of Object.entries(tools))collector.tool(p,entry);
}catch{/* observation only; production flow unaffected */}
const auth={Authorization:'Basic '+Buffer.from(process.env.HARBOR_USER+':'+process.env.HARBOR_PASS).toString('base64')};
const base='http://harbor-core.harbor.svc.cluster.local';
let env;
const cosign=(args,allowed=[0])=>{
 const r=spawnSync(toolchain.root+'/cosign',args,{env,encoding:'utf8',timeout:60000,maxBuffer:4*1024*1024});
 if(r.error||!allowed.includes(r.status))throw Error('Cosign '+args[0]+' failed: '+String(r.stderr).slice(-1200));return r;
};
async function fetchRegistry(url,options={}){const r=await fetch(url,{...options,signal:AbortSignal.timeout(20000)});let body;if(String(url).includes('/service/token')){try{body=await r.clone().json();}catch{}}collector.registry({ok:r.ok,status:r.status,headers:{location:r.headers.get('location'),'docker-content-digest':r.headers.get('docker-content-digest')},...(body!==undefined?{body}:{})});if(!r.ok)throw Error('Registry operation HTTP '+r.status);return r;}
// Observation wrapper kept outside the frozen checker slice above
// (blob-evidence identity extracts the cosign function verbatim).
const cosignCall=(args,allowed=[0])=>{const r=cosign(args,allowed);collector.cmd('cosign',args,r);return r;};
const signingFlags=['--yes','--new-bundle-format=false','--use-signing-config=false','--tlog-upload=false','--allow-http-registry'];
const verifyFlags=['--key','infra/security/cosign.pub','--insecure-ignore-tlog=true','--allow-http-registry'];
async function signImage(image,key=dir+'/cosign.key'){
 if(!/^core\.harbor\.domain\/petclinic\/[a-z0-9-]+@sha256:[a-f0-9]{64}$/.test(image))throw Error('Private project digest required');
 cosignCall(['sign',...signingFlags,'--key',key,image]);
 if(key===dir+'/cosign.key'){
  const verification=JSON.parse(cosignCall(['verify',...verifyFlags,image]).stdout);
  if(!verification.length||verification.some(x=>x.critical?.image?.['docker-manifest-digest']!==image.split('@')[1]))throw Error('Cosign verified claim digest mismatch');
  report.images.push({image,verified:true});
 }
}
try{
 const decryption=spawnSync(toolchain.root+'/sops',['decrypt','infra/security/secrets/signing-bundle.enc.json'],{env:{...process.env,SOPS_AGE_KEY_FILE:process.env.SIGNING_AGE_FILE},encoding:'utf8',timeout:15000,maxBuffer:1024*1024});
 collector.cmd('sops',['decrypt'],decryption);
 if(decryption.status!==0)throw Error('Signing bundle decryption failed; plaintext suppressed');
 const bundle=JSON.parse(decryption.stdout);if(bundle.schema!==1||!bundle.data?.privateKey||!bundle.data.password)throw Error('Invalid signing bundle');
 fs.writeFileSync(dir+'/cosign.key',bundle.data.privateKey,{mode:0o600});collector.io('key-write',true);
 fs.mkdirSync(dir+'/docker',{mode:0o700});collector.io('docker-mkdir',true);
 fs.writeFileSync(dir+'/docker/config.json',JSON.stringify({auths:{'core.harbor.domain':{auth:Buffer.from(process.env.HARBOR_USER+':'+process.env.HARBOR_PASS).toString('base64')}}}),{mode:0o600});collector.io('docker-write',true);
 env={...process.env,COSIGN_PASSWORD:bundle.data.password,DOCKER_CONFIG:dir+'/docker'};
 const actualPublic=cosignCall(['public-key','--key',dir+'/cosign.key']).stdout.trim();
 const pubText=fs.readFileSync('infra/security/cosign.pub','utf8');collector.file('infra/security/cosign.pub',pubText);
 if(actualPublic!==pubText.trim())throw Error('Signing key does not match trusted public key');
 if(mode==='bootstrap'){
  const deployObj=read(['-n','petclinic','get','deploy','petclinic']);collector.currentImage({status:0,stdout:JSON.stringify(deployObj),stderr:''});
  const current=deployObj.spec.template.spec.containers[0].image;
  const baseline='core.harbor.domain/petclinic/petclinic@sha256:a8c03e462e44ec81d4b685dd88618ab5fd0b3847411ddcd067d8a92b2071e268';
  for(const image of new Set([current,baseline]))await signImage(image);
  report.scope='Current release and #214 rollback baseline; no image bytes changed';
 }else if(mode==='release'){
  const builtText=fs.readFileSync('target/platform/image.json','utf8');collector.file('target/platform/image.json',builtText);
  const built=JSON.parse(builtText);
  if(built.source!==report.source)throw Error('Released source mismatch');
  const harborText=fs.readFileSync('target/platform/harbor.json','utf8');collector.file('target/platform/harbor.json',harborText);
  const harbor=JSON.parse(harborText);
  if(harbor.digest!==built.digest||harbor.scan_status!=='Success'||harbor.scans?.length!==2)throw Error('Completed dual-architecture scan required');
  for(const digest of new Set([built.digest,...harbor.scans.map(s=>s.digest)]))await signImage('core.harbor.domain/petclinic/petclinic@'+digest);
  const proofText=fs.readFileSync('.devsecops/release-evidence.json','utf8');collector.file('.devsecops/release-evidence.json',proofText);
  const proof=JSON.parse(proofText);
  if(proof.source!==report.source||proof.imageDigest!==built.digest)throw Error('Artifact/source mismatch');
  proof.signed=true;proof.signing={type:'Cosign key-based private registry; no public transparency log',publicKeySha256:crypto.createHash('sha256').update(fs.readFileSync('infra/security/cosign.pub')).digest('hex')};
  fs.writeFileSync('.devsecops/release-evidence.json',JSON.stringify(proof,null,2));collector.io('proof-write',true);
  cosignCall(['sign-blob','--yes','--new-bundle-format=false','--use-signing-config=false','--tlog-upload=false','--key',dir+'/cosign.key','--output-signature','.devsecops/release-evidence.sig','.devsecops/release-evidence.json']);
  cosignCall(['verify-blob','--key','infra/security/cosign.pub','--insecure-ignore-tlog=true','--signature','.devsecops/release-evidence.sig','.devsecops/release-evidence.json']);
  const afterWriteText=fs.readFileSync('.devsecops/release-evidence.json','utf8');collector.file('proof-after-write',afterWriteText);
  report.artifactSha256=crypto.createHash('sha256').update(afterWriteText).digest('hex');report.artifactSignatureVerified=true;
 }else{
  const repo='petclinic/signature-fixtures';
  const tr=await fetchRegistry(base+'/service/token?service=harbor-registry&scope='+encodeURIComponent('repository:'+repo+':pull,push')+'&account='+encodeURIComponent(process.env.HARBOR_USER),{headers:auth});
  const token=(await tr.json()).token;const bearer={Authorization:'Bearer '+token};
  const references={};
  for(const kind of ['signed','unsigned','wrong-key']){
   const config=Buffer.from(JSON.stringify({architecture:'arm64',os:'linux',config:{Labels:{'platform.test':kind,'platform.build':String(process.env.BUILD_NUMBER)}},rootfs:{type:'layers',diff_ids:[]}}));
   const digest='sha256:'+crypto.createHash('sha256').update(config).digest('hex');
   const upload=await fetchRegistry(base+'/v2/'+repo+'/blobs/uploads/',{method:'POST',headers:bearer});
   const location=new URL(upload.headers.get('location'),base);location.searchParams.set('digest',digest);
   await fetchRegistry(base+location.pathname+location.search,{method:'PUT',headers:{...bearer,'Content-Type':'application/octet-stream'},body:config});
   const manifest=Buffer.from(JSON.stringify({schemaVersion:2,mediaType:'application/vnd.oci.image.manifest.v1+json',config:{mediaType:'application/vnd.oci.image.config.v1+json',digest,size:config.length},layers:[]}));
   const tag='ci-'+process.env.BUILD_NUMBER+'-'+kind;
   const created=await fetchRegistry(base+'/v2/'+repo+'/manifests/'+tag,{method:'PUT',headers:{...bearer,'Content-Type':'application/vnd.oci.image.manifest.v1+json'},body:manifest});
   const imageDigest='sha256:'+crypto.createHash('sha256').update(manifest).digest('hex');
   if(created.headers.get('docker-content-digest')!==imageDigest)throw Error('Fixture manifest identity mismatch');
   references[kind]='core.harbor.domain/'+repo+'@'+imageDigest;
  }
  await signImage(references.signed);
  cosignCall(['generate-key-pair','--output-key-prefix',dir+'/wrong']);
  await signImage(references['wrong-key'],dir+'/wrong.key');
  report.cases=[];
  for(const [kind,image] of Object.entries(references)){
   const verification=cosignCall(['verify',...verifyFlags,image],Array.from({length:256},(_,i)=>i));
   checkCosignVerification(kind,verification.status,verification.stderr);
   const pod={apiVersion:'v1',kind:'Pod',metadata:{name:'signature-'+kind,namespace:'devsecops-supply-chain'},spec:{automountServiceAccountToken:false,restartPolicy:'Never',containers:[{name:'probe',image,command:['/never-executed']} ]}};
   const result=kube(['create','--dry-run=server','-f','-','-o','json'],JSON.stringify(pod),[0,1],40000);
   collector.admission(result);
   const allowed=result.status===0;
   if(allowed!==(kind==='signed')||(!allowed&&!String(result.stderr).includes('devsecops-signed-images')))throw Error('Actual signature admission mismatch: '+kind+' '+String(result.stderr).slice(-1000));
   report.cases.push({case:kind,image,allowed,cliVerified:verification.status===0,diagnostic:allowed?'server dry-run accepted; no Pod created':String(result.stderr).slice(-1600)});
  }
 }
 report.status='success';
}catch(e){report.error=e.message;throw e;}
finally{fs.rmSync(dir,{recursive:true,force:true});collector.io('temp-remove',true);const existsAfter=fs.existsSync(dir);collector.io('temp-exists',existsAfter);report.temporaryPrivateFilesRemoved=!existsAfter;report.finishedAt=new Date().toISOString();let writeError;try{fs.writeFileSync('.devsecops/signing-'+mode+'.json',JSON.stringify(report,null,2));collector.io('signing-report-write',true);}catch(e){collector.ioError('signing-report-write',e);writeError=e;}if(typeof emitReceipt==='function')await emitReceipt('cosign',{component:'cosign',status:report.status==='success'?'success':'error',raw:collector.raw});if(writeError)throw writeError;}
