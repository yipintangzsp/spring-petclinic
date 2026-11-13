import fs from 'node:fs';import path from 'node:path';import vm from 'node:vm';import crypto from 'node:crypto';
import {predicateType,validate,verifyEnvelope} from '../provenance/contract.mjs';import {evaluate} from './engine.mjs';import {provenanceObservations,MissingProvenanceEvidence} from './provenance-observations.mjs';
const out='evidence/2026-11-01/provenance-parent/',read=p=>JSON.parse(fs.readFileSync(p)),archive=read('evidence/2026-11-01/remaining-policy/archived-270.json'),historical=archive.reports['attestation-envelope.json'],predicate=archive.reports['provenance.json'],records=[];
const pub=fs.readFileSync('infra/security/cosign.pub','utf8'),source=fs.readFileSync('infra/security/provenance/plugin.mjs','utf8').replace(/^import .*;\s*$/gm,''),runtime=fs.readFileSync('infra/security/scanner-runtime.mjs','utf8').replace(/^import .*;\s*$/gm,'').replaceAll('export ',''),sha=x=>crypto.createHash('sha256').update(x).digest('hex');
const file=value=>({value}),response=(stdout='',status=0)=>({stdout:typeof stdout==='string'?stdout:JSON.stringify(stdout),status});
const disposable=crypto.generateKeyPairSync('ec',{namedCurve:'prime256v1'}),disposablePublic=disposable.publicKey.export({type:'spki',format:'pem'});
// Ephemeral in-memory test key only. Never export/store a private key or use a production credential.
function signStatement(statement,payloadType='application/vnd.in-toto+json'){
 const body=Buffer.from(typeof statement==='string'?statement:JSON.stringify(statement)),type=Buffer.from(payloadType),pae=Buffer.concat([Buffer.from('DSSEv1 '+type.length+' '),type,Buffer.from(' '+body.length+' '),body]);
 return {payloadType,payload:body.toString('base64'),signatures:[{sig:crypto.sign('sha256',pae,disposable.privateKey).toString('base64')}]};
}
function fixture(action){
 const manifest=fs.readFileSync('infra/security/scanner-tools.json','utf8'),tools=JSON.parse(manifest);
 return {classification:'CONTROLLED_REPLAY',artifactOrigin:'REAL_HISTORICAL_270',action,now:Date.parse(predicate.buildTimestamp),environment:{BUILD_NUMBER:'270',PROVENANCE_CANDIDATE:predicate.candidateImage,PROVENANCE_REPOSITORY:predicate.repository,PROVENANCE_COMMIT:predicate.commit,JENKINS_URL:'http://jenkins.devops.local/',JOB_NAME:'petclinic-ci',SIGNING_AGE_FILE:'/fixture/NO_REAL_AGE_KEY',HARBOR_USER:'synthetic-user',HARBOR_PASS:'synthetic-password'},runtime:{manifest,expectedManifestSha256:sha(manifest),lease:response({spec:{holderIdentity:'jenkins-petclinic-270'}}),tools:Object.fromEntries(tools.files.filter(x=>['sops','cosign'].includes(x.path)).map(x=>[x.path,{sha256:x.sha256}]))},files:{'.git-sha':file(predicate.commit),'infra/security/cosign.pub':file(pub)},io:Object.fromEntries(['output-mkdir','provenance-write','key-temp-create','key-temp-chmod','key-write','docker-mkdir','docker-write','create-report-write','key-temp-remove','auth-temp-create','auth-temp-chmod','auth-write','envelope-write','auth-temp-remove','verification-report-write'].map(k=>[k,{}])),commands:{'cosign:verify-attestation':[response(historical)],'sops:decrypt':[response({data:{privateKey:'SYNTHETIC_NOT_A_REAL_KEY',password:'SYNTHETIC_PASSWORD'}})],'cosign:attest':[response('controlled fixture response')]}};
}
function synthetic(r,change){const statement=verifyEnvelope(historical,pub);change(statement);r.files['infra/security/cosign.pub']=file(disposablePublic);r.commands['cosign:verify-attestation'][0]=response(signStatement(statement));r.artifactOrigin='SYNTHETIC_DISPOSABLE_KEY';}
function expected(r){const e=r.environment;return {repository:e.PROVENANCE_REPOSITORY,commit:e.PROVENANCE_COMMIT,buildNumber:Number(e.BUILD_NUMBER),builderIdentity:e.JENKINS_URL+'job/'+e.JOB_NAME,pipelineIdentity:e.JOB_NAME,candidateImage:e.PROVENANCE_CANDIDATE,image:e.PROVENANCE_CANDIDATE};}
async function oracle(raw){
 const f=provenanceObservations(raw),writes={},toolRoot=read('infra/security/scanner-tools.json').root;
 class FixedDate extends Date{constructor(...a){super(...(a.length?a:[raw.now]));}static now(){return raw.now;}}
 const fsFake={readFileSync:p=>{
  if(p==='infra/security/scanner-tools.json'){if(raw.runtime.manifestReadError)throw Error(raw.runtime.manifestReadError);return raw.runtime.manifest;}
  if(p==='infra/security/tools-lock.json'){if(raw.runtime.lockReadError)throw Error(raw.runtime.lockReadError);return JSON.stringify({supplyChain:{scanner_manifest_sha256:raw.runtime.expectedManifestSha256}});}
  if(p.startsWith(toolRoot+'/')){const t=f.need(raw.runtime.tools,p.slice(toolRoot.length+1));if(t.error)throw Error(t.error);return {observedHash:t.sha256};}
  return f.file(p);
 },readlinkSync:p=>f.need(raw.runtime.tools,p.slice(toolRoot.length+1)).symlink,
 mkdirSync:p=>f.io(p==='.devsecops'?'output-mkdir':'docker-mkdir'),mkdtempSync:p=>{const key=p.includes('provenance-key')?'key':'auth';f.io(key+'-temp-create');return key==='key'?'/tmp/provenance-key-frozen':'/tmp/attestation-read-frozen';},chmodSync:p=>f.io(p.includes('provenance-key')?'key-temp-chmod':'auth-temp-chmod'),rmSync:p=>f.io(p.includes('provenance-key')?'key-temp-remove':'auth-temp-remove'),writeFileSync:(p,v)=>{
  if(typeof v!=='string'&&!ArrayBuffer.isView(v))throw TypeError('Invalid data for writeFileSync');
  const k=p==='.devsecops/provenance.json'?'provenance-write':p.endsWith('/key')?'key-write':p.endsWith('/docker/config.json')?'docker-write':p.endsWith('/config.json')?'auth-write':p.endsWith('attestation-create.json')?'create-report-write':p.endsWith('attestation-envelope.json')?'envelope-write':'verification-report-write';f.io(k);if(p.startsWith('.devsecops/'))writes[p]=v;
 }};
 const spawnSync=(bin,args)=>bin==='kubectl'?raw.runtime.lease:f.command(path.basename(bin),args),cryptoFake={createHash:a=>({update:v=>({digest:e=>v?.observedHash??crypto.createHash(a).update(v).digest(e)})})};
 const context={fs:fsFake,path,os:{tmpdir:()=>'/tmp'},spawnSync,crypto:cryptoFake,process:{argv:['node','plugin',raw.action],env:{...raw.environment}},predicateType,validate,verifyEnvelope,Buffer,Date:FixedDate};
 try{
  const helpers=vm.runInNewContext('(function(){'+runtime+';return {requireLease,verifyTools,toolchain};})()',context);Object.assign(context,helpers);
  await vm.runInNewContext('(async()=>{'+source+'})()',context);return {decision:'PASS',writes,trace:f.trace};
 }catch(error){return {decision:error instanceof MissingProvenanceEvidence?null:'FAIL',reason:error.message,writes,trace:f.trace};}
}

export {fixture,oracle,synthetic,expected,archive,historical,predicate,pub,read,sha,file,response,disposablePublic,signStatement};
