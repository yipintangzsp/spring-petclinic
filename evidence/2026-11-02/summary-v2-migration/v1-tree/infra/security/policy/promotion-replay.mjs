// Execute unchanged validation/approval/promotion scripts ONLY against in-memory OS/Git/registry doubles.
// Imported exclusively by compatibility tests. Never by Policy Engine or production Jenkins.
import fs from 'node:fs';import path from 'node:path';import vm from 'node:vm';import crypto from 'node:crypto';import {pathToFileURL} from 'node:url';
import {validateGate,approvedRelease,promotionInput} from '../promotion/contract.mjs';import {requireSignedRelease} from '../gate-contract.mjs';import {hardenManifest} from '../hardening.mjs';
const clean=p=>fs.readFileSync(p,'utf8').replace(/^import .*;\s*$/gm,'').replaceAll('export ',''),runtime=clean('infra/security/scanner-runtime.mjs'),evidence=clean('infra/security/promotion/evidence.mjs');
const scripts={'sign-approve':clean('infra/security/promotion/sign-approve.mjs'),'dry-run':clean('infra/security/promotion/promote.mjs'),deploy:clean('infra/security/promotion/promote.mjs'),'candidate-sbom':evidence,'private-main':clean('infra/observability/promote-private.mjs').replaceAll('import.meta.url','"file:///fixture/promote-private.mjs"')};
const response=(stdout='',status=0,stderr='')=>({status,stdout:typeof stdout==='string'?stdout:JSON.stringify(stdout),stderr});
export async function replayPromotion(raw){
 const observations=[],reports={},memory={...raw.files};let clock=raw.now,verifyIndex=0,published=false,rollback=false,committed=false,mode=raw.stage;
 const io=k=>{observations.push({type:'io',key:k});if(raw.io[k])throw Error(raw.io[k]);};
 const file=p=>p.startsWith('/tmp/promotion-frozen/repo/k8s/')?'/manifest':p;
 const fsFake={readFileSync:(p,encoding)=>{
  const k=file(p);observations.push({type:'read',path:p});if(raw.fileErrors[p])throw Error(raw.fileErrors[p]);
  if(p==='infra/security/scanner-tools.json')return raw.runtime.manifest;if(p==='infra/security/tools-lock.json')return JSON.stringify({supplyChain:{scanner_manifest_sha256:raw.runtime.expectedManifestSha256}});
  const root=JSON.parse(raw.runtime.manifest).root;if(p.startsWith(root+'/')){const x=raw.runtime.tools[p.slice(root.length+1)];if(!x||x.error)throw Error('Tool unavailable');return {observedHash:x.sha256};}
  if(k==='/manifest'||p==='k8s/production/petclinic.yaml')return raw.git.manifest;
  if(p==='/tmp/promotion-frozen/app.jar')return Buffer.from('SYNTHETIC_JAR_BYTES');
  if(!Object.hasOwn(memory,p))throw Error('ENOENT: '+p);return encoding?memory[p]:Buffer.from(memory[p]);
 },readlinkSync:()=>'',mkdtempSync:()=>{io('temp-create');return '/tmp/promotion-frozen';},chmodSync:()=>io('temp-chmod'),mkdirSync:p=>io('mkdir:'+p),existsSync:()=>{io('temp-stat');return raw.tempExists;},rmSync:()=>io('temp-remove'),writeFileSync:(p,v)=>{if(typeof v!=='string'&&!ArrayBuffer.isView(v))throw Error('Invalid write data');io('write:'+p);memory[p]=String(v);if(p.startsWith('.devsecops/')||p.startsWith('target/platform/'))reports[p]=String(v);},renameSync:(a,b)=>{io('rename:'+b);if(!Object.hasOwn(memory,a))throw Error('Missing pending memory artifact');memory[b]=memory[a];delete memory[a];reports[b]=memory[b];},copyFileSync:(a,b)=>{io('copy:'+b);if(!Object.hasOwn(memory,a)&&a.endsWith('.sig'))memory[a]='SYNTHETIC_SIGNATURE';if(!Object.hasOwn(memory,a))throw Error('Missing memory copy artifact');memory[b]=memory[a];}};
 const spawnSync=(bin,args)=>{
  let result;const tool=path.basename(bin),verb=args[0];
  if(bin==='kubectl'){
   if(args.includes('lease'))result=response({spec:{holderIdentity:raw.runtime.leaseOwned?'fixture-holder':'foreign'}});
   else if(args.includes('application')){const revision=rollback?raw.git.rollbackCommit:raw.git.commit,ok=rollback?raw.app.rollbackConverged:raw.app.converged;result=response({metadata:{uid:published&&!raw.app.identitySame?'replaced':raw.app.uid},spec:{source:{repoURL:raw.app.repo,targetRevision:raw.app.target}},status:{sync:{revision,status:ok?'Synced':'OutOfSync'},health:{status:ok?'Healthy':'Degraded'}}});}
   else if(args.includes('deployment'))result=response({spec:{replicas:3,selector:{matchLabels:{app:'petclinic'}},template:{spec:{containers:[{name:'petclinic',image:rollback?raw.approval.previousRuntimeImage:raw.environment.AUDIT_CANDIDATE_IMAGE}]}}},status:{readyReplicas:3}});
   else if(args.includes('pods'))result=response({items:Array.from({length:3},(_,i)=>({metadata:{uid:'pod-'+i},spec:{containers:[{name:'petclinic',image:rollback?raw.approval.previousRuntimeImage:raw.environment.AUDIT_CANDIDATE_IMAGE}]},status:{containerStatuses:[{name:'petclinic',ready:raw.app.podsReady!==false,imageID:'fixture-image-id'}]}}))});
   else if(args.includes('service'))result=response({spec:{clusterIP:'127.0.0.1',ports:[{port:8080}]}});else result=response('',1,'API failure');
  }else if(tool==='sops')result=raw.decrypt;
  else if(tool==='cosign'){
   if(verb==='public-key')result=response(raw.cosign.keyMatches?raw.files['infra/security/cosign.pub']:'wrong-public-key');
   else if(verb==='sign')result=response('',raw.cosign.sign?0:1);
   else if(verb==='verify')result=raw.cosign.verify?response(raw.cosign.rawVerify??JSON.stringify([{critical:{image:{'docker-manifest-digest':raw.cosign.digestMatches?args.at(-1).split('@')[1]:'sha256:'+'f'.repeat(64)}}}])):response('',1);
   else if(verb==='sign-blob'){if(raw.cosign.signBlob)memory[args[args.indexOf('--output-signature')+1]]='SYNTHETIC_SIGNATURE';result=response('',raw.cosign.signBlob?0:1);}
   else if(verb==='verify-blob')result=response('',raw.cosign.verifyBlob?0:1);else result=response('',1);
  }else if(tool==='git'){
   if(raw.git.fail.includes(verb))result=response('',1,'synthetic Git failure');
   else if(verb==='remote')result=response(raw.app.repo);
   else if(verb==='rev-parse')result=response(args[1]==='origin/main'?(raw.git.rollbackSame?(published?raw.git.commit:raw.environment.BUILD_SOURCE??raw.files['.git-sha']):'foreign'):(mode==='private-main'?raw.git.commit:rollback?raw.git.rollbackCommit:committed?raw.git.commit:raw.git.base));
   else if(verb==='ls-remote')result=response((raw.git.remoteSame?raw.git.base:'foreign')+' refs/heads/main');
   else if(verb==='diff')result=response(raw.git.patch);
   else{if(verb==='push')published=true;if(verb==='commit')committed=true;if(verb==='revert')rollback=true;result=response();}
  }else if(tool==='docker')result=response(verb==='create'?'container-fixture':'',raw.candidate[verb==='cp'?'copy':verb==='rm'?'remove':'create']?0:1);
  else if(tool==='unzip')result=raw.candidate.unzip?{status:0,stdout:Buffer.from(JSON.stringify(raw.candidate.bom)),stderr:''}:response('',1);
  else result=response('',1,'Unknown process');
  observations.push({type:'process',tool,args:[...args],result:structuredClone(result)});return result;
 };
 class FixedDate extends Date{constructor(...a){super(...(a.length?a:[clock]));}static now(){clock+=raw.clockStep??4000;return clock;}}
 const context={fs:fsFake,path,os:{tmpdir:()=>'/tmp'},crypto:{createHash:a=>({update:v=>({digest:e=>v?.observedHash??crypto.createHash(a).update(v).digest(e)})})},spawnSync,process:{argv:['node','/fixture/promote-private.mjs',raw.modeOverride??(raw.stage==='candidate-sbom'?'sbom':raw.stage)],env:{...raw.environment}},Buffer,Date:FixedDate,pathToFileURL,validateGate,approvedRelease,promotionInput,requireSignedRelease,hardenManifest,console:{log:()=>{}},transportFetch:async()=>{observations.push({type:'http-health',status:raw.app.http});if(raw.app.httpError)throw Error('synthetic health transport failure');return {status:raw.app.http,json:async()=>({status:raw.app.health})};},setTimeout:fn=>{queueMicrotask(fn);return 1;}};
 let exitStatus=0,diagnostic;
 try{
  const h=vm.runInNewContext('(function(){'+runtime+';return {requireLease,verifyTools,toolchain,read};})()',context);Object.assign(context,h);
  if(raw.stage!=='candidate-sbom')Object.assign(context,vm.runInNewContext('(function(){'+evidence+';return {gateEvidence};})()',context));
  await vm.runInNewContext('(async()=>{'+scripts[raw.stage]+'})()',context);
 }catch(error){exitStatus=1;diagnostic=error.message;}
 return {schema:1,stage:raw.stage,complete:true,classification:'CONTROLLED_REPLAY',execution:{exitStatus,...(diagnostic?{diagnostic}:{})},inputIdentity:{candidate:raw.environment.AUDIT_CANDIDATE_IMAGE,build:raw.environment.BUILD_NUMBER,source:raw.files['.git-sha'],approval:raw.files['.devsecops/approved-release.json']},reports,observations};
}
