import fs from 'node:fs';import crypto from 'node:crypto';
import {predicateType,validate,verifyEnvelope} from '../provenance/contract.mjs';
import {provenanceObservations,MissingProvenanceEvidence} from './provenance-observations.mjs';
const sha=v=>crypto.createHash('sha256').update(v).digest('hex');
// Existing verifier functions remain authoritative. This adapter adds no signature or identity algorithm.
export function provenanceParent(raw){
 const lock=JSON.parse(fs.readFileSync(new URL('./versions/provenance-parent-baseline-v1.json',import.meta.url)));
 for(const [p,h]of Object.entries(lock.sourceHashes))if(sha(fs.readFileSync(new URL('../'+p.replace('infra/security/',''),import.meta.url)))!==h)throw Error('POLICY_ERROR: frozen Provenance source changed');
 if(!raw?.action||!raw.environment||!raw.runtime||!raw.files||!raw.io||!raw.commands)return {status:'NOT_CONFIGURED',decision:null,reason:'Complete Provenance observations absent'};
 const f=provenanceObservations(raw),env=raw.environment,image=env.PROVENANCE_CANDIDATE;let phase='prerequisite',decision='FAIL',reason,report,generated,expectedIdentity,selectedIndex=null,verificationAttempts=[];
 const command=(tool,args)=>{const r=f.command(tool,args);if(r.status!==0)throw Error('Provenance '+tool+' '+args[0]+' failed; sensitive output suppressed');return r.stdout;};
 let tools;
 const verifyTools=prefix=>{for(const entry of tools.files.filter(x=>prefix.some(p=>x.path===p||x.path.startsWith(p+'/')))){const v=f.need(raw.runtime.tools,entry.path);if(v.error||(entry.symlink?v.symlink!==entry.symlink:v.sha256!==entry.sha256))throw Error('Tool changed: '+entry.path);}};
 const expected=()=>{
  phase='candidate-source';if(!/^core\.harbor\.domain\/[a-z0-9._/-]+@sha256:[a-f0-9]{64}$/.test(image??''))throw Error('Fixed Harbor Candidate required');
  const commit=f.file('.git-sha').trim();if(commit!==env.PROVENANCE_COMMIT||!/^[a-f0-9]{40}$/.test(commit))throw Error('Fixed source commit required');
  return {repository:env.PROVENANCE_REPOSITORY,commit,buildNumber:Number(env.BUILD_NUMBER),builderIdentity:env.JENKINS_URL+'job/'+env.JOB_NAME,pipelineIdentity:env.JOB_NAME,candidateImage:image,image};
 };
 try{
  if(raw.runtime.manifestReadError)throw Error(raw.runtime.manifestReadError);const manifest=f.need(raw.runtime,'manifest');tools=JSON.parse(manifest);
  if(raw.runtime.lockReadError)throw Error(raw.runtime.lockReadError);if(sha(manifest)!==f.need(raw.runtime,'expectedManifestSha256'))throw Error('Locked scanner tool manifest mismatch');
  f.io('output-mkdir');
  if(raw.action==='generate'){
   const x=expected();expectedIdentity=x;if(!x.repository||!env.JENKINS_URL||!Number.isInteger(x.buildNumber))throw Error('Identified builder required');
   generated={...x,buildTimestamp:new Date(f.need(raw,'now')).toISOString(),buildType:'candidate-security-validation',limitation:'This attests the current security-validation build, not the historical image compilation.'};delete generated.image;phase='report-write';f.io('provenance-write');
  }else if(raw.action==='create'){
   phase='lease';const r=f.need(raw.runtime,'lease');if(r.error||r.status!==0)throw Error('Lease query failed');if(JSON.parse(r.stdout).spec.holderIdentity!==(env.HEAVY_HOLDER||`jenkins-petclinic-${env.BUILD_NUMBER}`))throw Error('Existing outer heavy Lease required');
   phase='tools';verifyTools(['cosign','sops']);f.io('key-temp-create');f.io('key-temp-chmod');
   try{
    phase='decrypt';const b=JSON.parse(command('sops',['decrypt','infra/security/secrets/signing-bundle.enc.json']));
    // Consume only presence/type consequences the unchanged script relies on, never invent bundle schema rules.
    const privateValue=b.data.privateKey;if(typeof privateValue!=='string'&&!ArrayBuffer.isView(privateValue))throw TypeError('Invalid data for writeFileSync');f.io('key-write');f.io('docker-mkdir');f.io('docker-write');const password=b.data.password;
    phase='attest';const output=command('cosign',['attest','--yes','--new-bundle-format=false','--use-signing-config=false','--tlog-upload=false','--allow-http-registry','--key','/tmp/provenance-key-frozen/key','--predicate','.devsecops/provenance.json','--type',predicateType,image]);
    report={status:'success',candidateImage:image,outputCaptured:!!output};phase='report-write';f.io('create-report-write');
   }finally{f.io('key-temp-remove');}
  }else if(raw.action==='verify'){
   report={status:'failed',buildNumber:Number(env.BUILD_NUMBER),tests:[]};f.io('auth-temp-create');f.io('auth-temp-chmod');f.io('auth-write');
   try{
    phase='tools';verifyTools(['cosign']);phase='cli-verification';const output=command('cosign',['verify-attestation','--key','infra/security/cosign.pub','--insecure-ignore-tlog=true','--allow-http-registry','--type',predicateType,image]);
    phase='envelope-write';f.io('envelope-write');let envelopes;
    phase='parse';try{envelopes=JSON.parse(output);if(!Array.isArray(envelopes))envelopes=[envelopes];}catch{envelopes=output.trim().split('\n').map(s=>JSON.parse(s));}
    const x=expected();expectedIdentity=x;const key=f.file('infra/security/cosign.pub');let chosen;
    phase='verification';for(const [index,envelope]of envelopes.entries()){
     try{const statement=verifyEnvelope(envelope,key);validate(statement,x);chosen=envelope;selectedIndex=index;verificationAttempts.push({index,verified:true});break;}
     catch(error){verificationAttempts.push({index,verified:false,reason:error.message});}
    }
    if(!chosen)throw Error('No verified current-build attestation');report.tests.push({case:'correct',result:'PASS'});
    phase='negative-controls';for(const [name,e]of [['digest',{...x,image:x.image.slice(0,-1)+(x.image.endsWith('0')?'1':'0')}],['commit',{...x,commit:'0'.repeat(40)}]]){
     let rejected=false;try{validate(verifyEnvelope(chosen,key),e);}catch{rejected=true;}if(!rejected)throw Error('Negative control accepted');report.tests.push({case:name,result:'REJECTED'});
    }
    let rejected=false;try{verifyEnvelope({...chosen,payload:Buffer.from('tampered').toString('base64')},key);}catch{rejected=true;}if(!rejected)throw Error('Tamper accepted');report.tests.push({case:'tampered',result:'REJECTED'});
    report.status='success';report.candidateImage=image;report.commit=x.commit;report.buildNumber=x.buildNumber;
   }finally{f.io('auth-temp-remove');phase=phase==='negative-controls'?'report-write':phase;f.io('verification-report-write');}
  }else throw Error('Unknown provenance action');
  decision='PASS';
 }catch(error){reason=error.message;if(error instanceof MissingProvenanceEvidence)decision=null;}
 return {status:decision??'NOT_TESTED',decision,reason,failurePhase:decision==='FAIL'?phase:null,report,generated,normalizedFacts:{action:raw.action,expectedIdentity,verificationAttempts,selectedIndex,verificationCommands:f.trace.filter(x=>x.type==='command'&&x.tool==='cosign'),artifactInputs:structuredClone(raw.files),runtime:structuredClone(raw.runtime)},trace:f.trace,rawEvidence:structuredClone(raw)};
}
