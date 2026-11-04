// Candidate-only offline verification evidence. Crypto is performed by the real
// fixed Cosign binary; this module only runs the EXISTING frozen command checker.
import fs from 'node:fs';import vm from 'node:vm';import {sha,freeze} from '../summary-v2/codec.mjs';
export const COSIGN_BLOB_MODE='candidate-offline-blob-v1';
const err=m=>{throw Error('POLICY_ERROR: Cosign blob evidence '+m);};
export function cosignBlobSourceIdentity(){
 const parent=fs.readFileSync(new URL('./cosign-parent.mjs',import.meta.url),'utf8');
 let projection=parent;
 for(const mark of ['IMPORT','DISPATCH']){
  if(parent.split('// COSIGN_CANDIDATE_BLOB_'+mark+'_BEGIN').length!==2||parent.split('// COSIGN_CANDIDATE_BLOB_'+mark+'_END').length!==2)err('parent dispatch markers');
  projection=projection.replace(new RegExp((mark==='DISPATCH'?' ':'')+'// COSIGN_CANDIDATE_BLOB_'+mark+'_BEGIN\\n[\\s\\S]*?'+(mark==='DISPATCH'?' ':'')+'// COSIGN_CANDIDATE_BLOB_'+mark+'_END\\n'),'');
 }
 if(sha(projection)!=='cacf526148868324f82e8b0ad073674eaf59bdeb9da4123d833fa7b008bd3d33')err('legacy parent changed outside additive dispatch');
 const original=fs.readFileSync(new URL('./versions/cosign-parent-baseline-v1.json',import.meta.url));
 if(sha(original)!=='4d497c2de02ce04489c6203c7e733cac343f011dace3cdeb64782f32ebd688ea')err('original manifest identity');
 const lock=JSON.parse(original);for(const [p,h]of Object.entries(lock.sourceHashes))if(sha(fs.readFileSync(new URL('../../../'+p,import.meta.url)))!==h)err('frozen source '+p);
 const source=fs.readFileSync(new URL('../signing.mjs',import.meta.url),'utf8'),begin=source.indexOf('const cosign=(args,allowed=[0])=>{'),end=source.indexOf('\nasync function fetchRegistry',begin);
 if(begin<0||end<=begin)err('legacy checker boundary');
 return {manifestSha256:sha(original),sourceHashes:lock.sourceHashes,checker:source.slice(begin,end),checkerSha256:sha(source.slice(begin,end))};
}
export function blobArgv(refs){
 if(!refs||!['key','object','signature'].every(k=>typeof refs[k]==='string'&&refs[k].startsWith('/var/tmp/security-manager-gitleaks-')&&!/[\x00\r\n]/.test(refs[k])&&!refs[k].split('/').includes('..')))err('local refs');
 return ['verify-blob','--key',refs.key,'--insecure-ignore-tlog=true',...(refs.signaturePresent?['--signature',refs.signature]:[]),refs.object];
}
export function legacyBlobDecision(raw){
 const source=cosignBlobSourceIdentity();
 if(!raw||raw.schemaVersion!==1||raw.stage!==COSIGN_BLOB_MODE||raw.complete!==true)return {status:'NOT_CONFIGURED',decision:null,reason:'Complete real verification facts absent'};
 if(!raw.binding||!raw.trust||!raw.tool||!raw.command||!raw.refs)err('missing required evidence');
 const hex=x=>typeof x==='string'&&/^[a-f0-9]{64}$/.test(x);
 if(raw.trust.scope!=='CONTROLLED_TEST_ONLY_NOT_PRODUCTION'||raw.trust.authorizedProject!==raw.binding.projectId||!hex(raw.trust.publicKeySha256)||!hex(raw.binding.objectSha256)||!hex(raw.binding.approvalSha256)||!hex(raw.binding.sourceRevisionDigest))err('trust/object/project binding');
 if(raw.tool.version!=='3.1.4'||raw.tool.sha256!==JSON.parse(fs.readFileSync(new URL('../scanner-tools.json',import.meta.url))).files.find(x=>x.path==='cosign').sha256)err('fixed tool');
 if(typeof raw.refs.signaturePresent!=='boolean'||raw.refs.signaturePresent&&!hex(raw.binding.signatureSha256)||!raw.refs.signaturePresent&&raw.binding.signatureSha256!==null)err('signature evidence');
 const argv=blobArgv(raw.refs);if(JSON.stringify(raw.command.argv)!==JSON.stringify(argv))err('fixed command');
 const c=raw.command;if(!Number.isInteger(c.exitStatus)||c.exitStatus<0||c.exitStatus>255||c.signal!==null||typeof c.stdout!=='string'||typeof c.stderr!=='string'||c.stdout.length>65536||c.stderr.length>65536)err('malformed execution observation');
 let decision='PASS';
 try{
  // Exact production wrapper: rejects command failures without reimplementing
  // Cosign verification, signature algorithms, trust inference or Gate policy.
  vm.runInNewContext(source.checker+'\ncosign(argv);',{toolchain:{root:'/fixed-not-executed'},env:{},argv,spawnSync:()=>({status:c.exitStatus,stdout:c.stdout,stderr:c.stderr})},{timeout:1000});
 }catch(e){if(!String(e.message).startsWith('Cosign verify-blob failed:'))err('original checker failed unexpectedly');decision='FAIL';}
 return freeze({status:decision,decision,reason:decision==='FAIL'?'Existing Cosign command acceptance rejected actual verify-blob result':null,legacyCheckerSha256:source.checkerSha256,scope:'Existing verification-command acceptance only; production signing/registry/Lease NOT_EXECUTED',rawEvidence:structuredClone(raw)});
}
