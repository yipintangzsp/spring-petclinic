import fs from 'node:fs';import path from 'node:path';import crypto from 'node:crypto';
import {checkCosignVerification} from '../cosign-verification.mjs';
import {cosignObservations,MissingCosignEvidence} from './cosign-observations.mjs';
const sha=v=>crypto.createHash('sha256').update(v).digest('hex');
// Only frozen observations are consumed. Cosign/sshd/registry/admission are never executed here.
export function cosignParent(raw){
 const lock=JSON.parse(fs.readFileSync(new URL('./versions/cosign-parent-baseline-v1.json',import.meta.url)));
 for(const [p,h]of Object.entries(lock.sourceHashes))if(sha(fs.readFileSync(new URL('../'+p.replace('infra/security/',''),import.meta.url)))!==h)throw Error('POLICY_ERROR: frozen Cosign source changed');
 if(!raw||!raw.stage||!raw.configuration||!raw.environment||!raw.runtime||!raw.files||!raw.commands||!raw.io)return {decision:null,status:'NOT_CONFIGURED',reason:'Complete Cosign facts absent'};
 const f=cosignObservations(raw),env=raw.environment,c=raw.configuration,dir='/tmp/cosign-frozen';let phase='prerequisite',report,decision,reason,missing=false,genericWriteAttempted=false;
 const checked=(r,allowed=[0])=>{if(r.error||!allowed.includes(r.status))throw Error('Command execution failed');return r;};
 const cosign=(args,allowed=[0])=>checked(f.command('cosign',args),allowed);
 const flags=['--key','infra/security/cosign.pub','--insecure-ignore-tlog=true','--allow-http-registry'];
 const signing=['--yes','--new-bundle-format=false','--use-signing-config=false','--tlog-upload=false','--allow-http-registry'];
 const registry=(url,options)=>{const r=f.registry(url,options);if(!r.ok)throw Error('Registry operation HTTP '+r.status);return r;};
 const verifyTools=prefix=>{for(const e of tools.files.filter(x=>prefix.some(p=>x.path===p||x.path.startsWith(p+'/')))){const v=f.need(raw.runtime.tools,e.path);if(v.error||(e.symlink?v.symlink!==e.symlink:v.sha256!==e.sha256))throw Error('Tool changed');}};
 let tools;
 try{
  if(raw.runtime.manifestReadError)throw Error(raw.runtime.manifestReadError);const manifest=f.need(raw.runtime,'manifest');tools=JSON.parse(manifest);if(raw.runtime.lockReadError)throw Error(raw.runtime.lockReadError);
  if(sha(manifest)!==f.need(raw.runtime,'expectedManifestSha256'))throw Error('Locked scanner tool manifest mismatch');
  // Generic tool reads config/source before its protected body; signing reads source after its setup.
  let source;if(raw.stage==='generic'){source=f.file('.git-sha').trim();report={schema:1,tool:'cosign',status:'error',build:Number(c.build),findings:0,blocking:0,project:c.project,source};}
  const lease=checked(f.need(raw.runtime,'lease'));if(JSON.parse(lease.stdout).spec.holderIdentity!==(env.HEAVY_HOLDER||`jenkins-petclinic-${env.BUILD_NUMBER}`))throw Error('Existing outer heavy Lease required');
  verifyTools(raw.stage==='generic'?['cosign']:['cosign','sops']);
  if(raw.stage==='generic'){
   try{
    phase='reference';if(!/^[^\s]+@sha256:[a-f0-9]{64}$/.test(c.image??'')||!c.cosignPublicKey)throw Error('Fixed digest and project trust key required');
    const full=path.resolve(c.sourceRoot,c.cosignPublicKey);if(!full.startsWith(path.resolve(c.sourceRoot)+'/'))throw Error('Project path outside checkout');
    phase='signature-verification';report.verification=JSON.parse(cosign(['verify','--key',full,'--insecure-ignore-tlog=true','--allow-http-registry',c.image]).stdout);if(!report.verification.length)throw Error('No actual signature');report.image=c.image;report.status='success';
   }catch(e){if(e instanceof MissingCosignEvidence)throw e;report.error=e.message;decision='FAIL';reason=e.message;}
   phase='report-write';genericWriteAttempted=true;f.io('manager-report-write');decision??='PASS';
  }else{
   if(!['bootstrap','release','admission'].includes(raw.stage))throw Error('Explicit signing mode required');
   if(!env.SIGNING_AGE_FILE||!env.HARBOR_USER||!env.HARBOR_PASS)throw Error('Scoped signing and Harbor credentials required');
   f.io('output-mkdir');f.io('temp-create');f.io('temp-chmod');source=f.file('.git-sha').trim();report={status:'failed',mode:raw.stage,source,images:[]};
   try{
    phase='decryption';const decrypt=f.command('sops',['decrypt','infra/security/secrets/signing-bundle.enc.json']);if(decrypt.status!==0)throw Error('Signing bundle decryption failed; plaintext suppressed');
    const bundle=JSON.parse(decrypt.stdout);if(bundle.schema!==1||!bundle.data?.privateKey||!bundle.data.password)throw Error('Invalid signing bundle');
    f.io('key-write');f.io('docker-mkdir');f.io('docker-write');
    phase='key-identity';if(cosign(['public-key','--key',dir+'/cosign.key']).stdout.trim()!==f.file('infra/security/cosign.pub').trim())throw Error('Signing key does not match trusted public key');
    const signImage=image=>{
     if(!/^core\.harbor\.domain\/petclinic\/[a-z0-9-]+@sha256:[a-f0-9]{64}$/.test(image))throw Error('Private project digest required');
     phase='sign-command';cosign(['sign',...signing,'--key',dir+'/cosign.key',image]);
     phase='signature-verification';const v=JSON.parse(cosign(['verify',...flags,image]).stdout);
     phase='digest-binding';if(!v.length||v.some(x=>x.critical?.image?.['docker-manifest-digest']!==image.split('@')[1]))throw Error('Cosign verified claim digest mismatch');report.images.push({image,verified:true});
    };
    if(raw.stage==='bootstrap'){
     phase='current-image-query';const r=checked(f.need(raw,'currentImage'));const current=JSON.parse(r.stdout).spec.template.spec.containers[0].image;
     for(const image of new Set([current,'core.harbor.domain/petclinic/petclinic@sha256:a8c03e462e44ec81d4b685dd88618ab5fd0b3847411ddcd067d8a92b2071e268']))signImage(image);
    }else if(raw.stage==='release'){
     phase='release-binding';const built=JSON.parse(f.file('target/platform/image.json'));if(built.source!==source)throw Error('Released source mismatch');
     const harbor=JSON.parse(f.file('target/platform/harbor.json'));if(harbor.digest!==built.digest||harbor.scan_status!=='Success'||harbor.scans?.length!==2)throw Error('Completed dual-architecture scan required');
     for(const digest of new Set([built.digest,...harbor.scans.map(s=>s.digest)]))signImage('core.harbor.domain/petclinic/petclinic@'+digest);
     phase='artifact-binding';const proof=JSON.parse(f.file('.devsecops/release-evidence.json'));if(proof.source!==source||proof.imageDigest!==built.digest)throw Error('Artifact/source mismatch');
     proof.signed=true;proof.signing={type:'Cosign key-based private registry; no public transparency log',publicKeySha256:sha(f.file('infra/security/cosign.pub'))};f.io('proof-write');
     phase='artifact-signature';cosign(['sign-blob','--yes','--new-bundle-format=false','--use-signing-config=false','--tlog-upload=false','--key',dir+'/cosign.key','--output-signature','.devsecops/release-evidence.sig','.devsecops/release-evidence.json']);
     cosign(['verify-blob','--key','infra/security/cosign.pub','--insecure-ignore-tlog=true','--signature','.devsecops/release-evidence.sig','.devsecops/release-evidence.json']);f.file('proof-after-write');
    }else{
     phase='registry';const base='http://harbor-core.harbor.svc.cluster.local',repo='petclinic/signature-fixtures';
     const token=registry(base+'/service/token?service=harbor-registry&scope='+encodeURIComponent('repository:'+repo+':pull,push')+'&account='+encodeURIComponent(env.HARBOR_USER));if(token.jsonError)throw Error('Invalid registry token JSON');const bearerToken=token.body.token; // Existing code reads .token, without a new token validation rule.
     const references={};for(const kind of ['signed','unsigned','wrong-key']){
      const config=Buffer.from(JSON.stringify({architecture:'arm64',os:'linux',config:{Labels:{'platform.test':kind,'platform.build':String(env.BUILD_NUMBER)}},rootfs:{type:'layers',diff_ids:[]}})),digest='sha256:'+sha(config);
      const upload=registry(base+'/v2/'+repo+'/blobs/uploads/',{method:'POST'}),location=new URL(upload.headers?.location??null,base);location.searchParams.set('digest',digest);
      registry(base+location.pathname+location.search,{method:'PUT',body:config});
      const manifest=Buffer.from(JSON.stringify({schemaVersion:2,mediaType:'application/vnd.oci.image.manifest.v1+json',config:{mediaType:'application/vnd.oci.image.config.v1+json',digest,size:config.length},layers:[]}));
      const created=registry(base+'/v2/'+repo+'/manifests/ci-'+env.BUILD_NUMBER+'-'+kind,{method:'PUT',body:manifest}),imageDigest='sha256:'+sha(manifest);
      if(created.headers?.['docker-content-digest']!==imageDigest)throw Error('Fixture manifest identity mismatch');references[kind]='core.harbor.domain/'+repo+'@'+imageDigest;
     }
     signImage(references.signed);phase='wrong-key-fixture';cosign(['generate-key-pair','--output-key-prefix',dir+'/wrong']);
     if(!/^core\.harbor\.domain\/petclinic\/[a-z0-9-]+@sha256:[a-f0-9]{64}$/.test(references['wrong-key']))throw Error('Private project digest required');
     cosign(['sign',...signing,'--key',dir+'/wrong.key',references['wrong-key']]);report.cases=[];
     for(const [kind,image]of Object.entries(references)){
      phase='signature-verification';const v=cosign(['verify',...flags,image],Array.from({length:256},(_,i)=>i));
      phase='signature-classification';checkCosignVerification(kind,v.status,v.stderr);
      const pod={apiVersion:'v1',kind:'Pod',metadata:{name:'signature-'+kind,namespace:'devsecops-supply-chain'},spec:{automountServiceAccountToken:false,restartPolicy:'Never',containers:[{name:'probe',image,command:['/never-executed']}]}};
      phase='admission';const a=checked(f.admission(['create','--dry-run=server','-f','-','-o','json'],JSON.stringify(pod)),[0,1]),allowed=a.status===0;
      if(allowed!==(kind==='signed')||(!allowed&&!String(a.stderr).includes('devsecops-signed-images')))throw Error('Actual signature admission mismatch: '+kind);
      report.cases.push({case:kind,image,allowed,cliVerified:v.status===0,diagnostic:allowed?'server dry-run accepted; no Pod created':String(a.stderr).slice(-1600)});
     }
    }
    report.status='success';decision='PASS';
   }catch(e){if(e instanceof MissingCosignEvidence){missing=true;}report.error=e.message;decision='FAIL';reason=e.message;}
   finally{
    phase=decision==='FAIL'?phase:'cleanup';f.io('temp-remove');report.temporaryPrivateFilesRemoved=f.io('temp-exists')===false;f.io('signing-report-write');
   }
  }
 }catch(e){missing||=e instanceof MissingCosignEvidence;decision='FAIL';reason=e.message;}
 if(raw.stage==='generic'&&report&&!genericWriteAttempted){try{genericWriteAttempted=true;f.io('manager-report-write');}catch(e){missing||=e instanceof MissingCosignEvidence;decision='FAIL';reason=e.message;} }
 return {status:missing?'NOT_TESTED':decision,decision:missing?null:decision,reason,failurePhase:decision==='FAIL'?phase:null,report,normalizedFacts:{stage:raw.stage,source:raw.files['.git-sha'],verificationFacts:f.trace.filter(x=>x.type==='command'&&x.tool==='cosign'&&['verify','verify-blob'].includes(x.args[0])).map(x=>({command:x.args[0],imageOrArtifactRef:x.args.at(-1),keyReference:x.args[x.args.indexOf('--key')+1],exitStatus:x.result.status,executionError:x.result.error??null,stdout:x.result.stdout,stderr:x.result.stderr})),verificationObservations:structuredClone(Object.fromEntries(Object.entries(raw.commands).filter(([key])=>key.startsWith('cosign:')))),registryObservations:structuredClone(raw.registry??[]),admissionObservations:structuredClone(raw.admissions??[]),runtime:structuredClone(raw.runtime)},trace:f.trace,rawEvidence:structuredClone(raw)};
}
