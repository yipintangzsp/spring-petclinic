import fs from 'node:fs';import crypto from 'node:crypto';
import {verifyEnvelope} from '../provenance/contract.mjs';import {buildPredicateType} from '../provenance/build-contract.mjs';
const base='evidence/2026-11-01/build-provenance-parent/historical/producer-2/',read=p=>JSON.parse(fs.readFileSync(p)),sha=x=>crypto.createHash('sha256').update(x).digest('hex');
export const historical={compilation:read(base+'.devsecops/build-compilation.json'),predicate:read(base+'.devsecops/build-provenance.json'),envelope:read(base+'.devsecops/build-attestation-envelope.json'),metadata:fs.readFileSync(base+'target/platform/image-build-metadata.json','utf8'),report:read(base+'.devsecops/build-attestation-verification.json')};
const pub=fs.readFileSync('infra/security/cosign.pub','utf8'),manifest=fs.readFileSync('infra/security/scanner-tools.json','utf8'),tools=JSON.parse(manifest),key=crypto.generateKeyPairSync('ec',{namedCurve:'prime256v1'});
export const disposablePublic=key.publicKey.export({type:'spki',format:'pem'});
export function signBuild(predicate,subjectImage=predicate.candidateImage){const statement={_type:'https://in-toto.io/Statement/v0.1',predicateType:buildPredicateType,subject:[{name:subjectImage.split('@sha256:')[0],digest:{sha256:subjectImage.split('@sha256:')[1]}}],predicate},payload=Buffer.from(JSON.stringify(statement)),type=Buffer.from('application/vnd.in-toto+json'),pae=Buffer.concat([Buffer.from('DSSEv1 '+type.length+' '),type,Buffer.from(' '+payload.length+' '),payload]);return {payloadType:type.toString(),payload:payload.toString('base64'),signatures:[{sig:crypto.sign('sha256',pae,key.privateKey).toString('base64')}]};}
export const file=value=>({value:typeof value==='string'?value:JSON.stringify(value)}),cmd=(stdout='',status=0)=>({status,stdout:typeof stdout==='string'?stdout:JSON.stringify(stdout),stderr:''});
export function fixture(phase){
 const p=historical.predicate,c=p.compilation,source=p.source;
 const r={phase,classification:'CONTROLLED_REPLAY',identity:{source:p.source,builder:p.builder,candidateImage:p.candidateImage},now:Date.parse(c.startedAt),environment:{BUILD_NUMBER:'2',JENKINS_URL:'http://jenkins.devops.local/',JOB_NAME:'petclinic-candidate-build',HEAVY_HOLDER:'candidate-build-2',REGISTRY_API:'10.0.0.3:30050',FULL_IMAGE:'127.0.0.1:13050/petclinic/petclinic:0.10.0-ci-1000002',IMAGE_TAG:'0.10.0-ci-1000002',BUILD_PROVENANCE_IMAGE:p.candidateImage,BUILD_SOURCE_COMMIT:source.commit,BUILD_SOURCE_REPOSITORY:source.repository,BUILD_BUILDER_IDENTITY:p.builder.identity,BUILD_SOURCE_NUMBER:'2',HARBOR_USER:'synthetic-user',HARBOR_PASS:'synthetic-password',SIGNING_AGE_FILE:'/fixture/NO_REAL_KEY',TRANSPORT_MAX_RETRIES:'2'},runtime:{manifest,expectedManifestSha256:sha(manifest),lease:cmd({spec:{holderIdentity:'candidate-build-2'}}),tools:Object.fromEntries(tools.files.filter(x=>['cosign','sops'].includes(x.path)).map(x=>[x.path,{sha256:x.sha256}]))},commands:{git:[],nice:[cmd()],docker:[cmd()],sops:[cmd({data:{privateKey:'SYNTHETIC_NOT_A_PRIVATE_KEY',password:'SYNTHETIC'}})],cosign:phase==='create'?[cmd(pub),cmd(),cmd(historical.envelope)]:[cmd(historical.envelope)]},files:{'.devsecops/build-compilation.json':file(c),'.devsecops/build-provenance.json':file(p),'infra/security/cosign.pub':file(pub),'.dockerignore':{value:'**\n!Dockerfile\n!target/\n!target/security-packages/\n!target/security-packages/**\n!target/spring-petclinic-4.0.0-SNAPSHOT.jar\n',measuredSha256:p.context.files.find(x=>x.name==='.dockerignore').sha256}},walk:{},network:{},io:{},tempExists:false};
 for(let i=0;i<3;i++)r.commands.git.push(cmd(source.commit),cmd(source.repository),cmd(''));
 for(const x of p.context.files)if(x.name!=='.dockerignore')r.files[x.name]={measuredSha256:x.sha256};
 for(const x of p.context.files.filter(x=>x.name.startsWith('target/security-packages/'))){
  const parts=x.name.split('/');for(let i=2;i<parts.length;i++){const parent=parts.slice(0,i).join('/'),name=parts[i],type=i===parts.length-1?'file':'directory';r.walk[parent]??=[];if(!r.walk[parent].some(e=>e.name===name))r.walk[parent].push({name,type});}
 }
 for(const name of ['.devsecops','target/platform','/tmp/build-attestation-frozen/docker'])r.io['mkdir:'+name]={};
 for(const name of ['.devsecops/build-compilation.json','.devsecops/build-provenance.json','target/platform/harbor-copy.json','/tmp/build-attestation-frozen/key','/tmp/build-attestation-frozen/docker/config.json','.devsecops/build-attestation-envelope.json','.devsecops/build-attestation-verification.json'])r.io['write:'+name]={};
 for(const k of ['temp-create','temp-chmod','temp-remove','temp-stat'])r.io[k]={};
 if(phase==='image'||phase==='harbor-copy'){
  // Synthetic registry bytes, with their actual derived digests. Never relabel these as historical index bytes.
  const children=['amd64','arm64'].map(architecture=>{const blob=JSON.stringify({architecture,os:'linux'}),json={schemaVersion:2,mediaType:'application/vnd.oci.image.manifest.v1+json',config:{digest:'sha256:'+sha(blob)},layers:[]},bytes=JSON.stringify(json);return {architecture,json,bytes,blob,digest:'sha256:'+sha(bytes)};});
  const index={schemaVersion:2,mediaType:'application/vnd.oci.image.index.v1+json',manifests:children.map(x=>({digest:x.digest,platform:{os:'linux',architecture:x.architecture}}))},bytes=JSON.stringify(index),digest='sha256:'+sha(bytes),metadata={...JSON.parse(historical.metadata),'containerimage.digest':digest};
  metadata['containerimage.descriptor']={...metadata['containerimage.descriptor'],digest};r.files['target/platform/image-build-metadata.json']=file(metadata);
  r.network['HEAD http://10.0.0.3:30050/v2/petclinic/petclinic/manifests/0.10.0-ci-1000002']=[{status:404}];r.network['GET http://10.0.0.3:30050/v2/petclinic/petclinic/manifests/'+digest]=[{status:200,bytes}];
  r.syntheticIndex={index,bytes,digest,children};r.identity={...r.identity,syntheticCandidateImage:'core.harbor.domain/petclinic/petclinic@'+digest};
  if(phase==='harbor-copy'){
   const src='http://10.0.0.3:30050/v2/petclinic/petclinic',dst='http://harbor-core.harbor.svc.cluster.local';
   r.network['GET '+dst+'/service/token?service=harbor-registry&scope=repository%3Apetclinic%2Fpetclinic%3Apull%2Cpush&account=synthetic-user']=[{status:200,json:{token:'synthetic-token'}}];
   r.network['GET '+src+'/manifests/0.10.0-ci-1000002']=[{status:200,bytes,headers:{'docker-content-digest':digest}}];
   for(const x of children){r.network['GET '+src+'/manifests/'+x.digest]=[{status:200,bytes:x.bytes,headers:{'docker-content-digest':x.digest}}];r.network['HEAD '+dst+'/v2/petclinic/petclinic/blobs/'+x.json.config.digest]=[{status:200}];r.network['PUT '+dst+'/v2/petclinic/petclinic/manifests/'+x.digest]=[{status:201,headers:{'docker-content-digest':x.digest}}];}
   r.network['PUT '+dst+'/v2/petclinic/petclinic/manifests/0.10.0-ci-1000002']=[{status:201,headers:{'docker-content-digest':digest}}];
  }
 }
 return r;
}
export function mutateSigned(r,change){const p=structuredClone(historical.predicate);change(p);r.files['infra/security/cosign.pub']=file(disposablePublic);r.files['.devsecops/build-provenance.json']=file(p);r.commands.cosign=r.phase==='create'?[cmd(disposablePublic),cmd(),cmd(signBuild(p))]:[cmd(signBuild(p))];r.syntheticSigned=true;}
export {sha,pub,verifyEnvelope};
