// Versioned source identities only. No finding/decision conversion or scanner execution.
import fs from 'node:fs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {createHash} from 'node:crypto';
const sha=x=>createHash('sha256').update(x).digest('hex');
const parentHash='dc3b95d577707b9d9137663bd88a8034f5ce75f87a377a3504c83afd941a6f8f';
const integrationHash='e1ac4a6cac7d7282899ece510a411988576a67e272de46f159ddab48ff858ff8';
const fail=message=>{throw Error('POLICY_ERROR: Trivy source identity: '+message);};
const blocks=['ARCHIVE','PARAMETERS','PRECONDITIONS','STAGES'];
export function removePinnedHelmBlocks(text) {
 for(const key of blocks){
  const begin='// HELM_SHADOW_'+key+'_BEGIN',end='// HELM_SHADOW_'+key+'_END';
  if(text.split(begin).length!==2 || text.split(end).length!==2)fail('ambiguous Helm block '+key);
  const regex=new RegExp('// HELM_SHADOW_'+key+'_BEGIN[\\s\\S]*?// HELM_SHADOW_'+key+'_END\\n'+(key==='STAGES'?'\\n':''));
  const next=text.replace(regex,'');if(next===text)fail('malformed Helm block '+key);text=next;
 }
 return text;
}
export function verifyTrivySourceLock({root=fileURLToPath(new URL('../../../',import.meta.url))}={}) {
 root=path.resolve(root);
 const read=p=>{
  if(path.isAbsolute(p)||p.split('/').some(x=>['..','.',''].includes(x)))fail('unsafe locked path');
  const name=path.join(root,p);if(fs.realpathSync(name)!==name)fail('symlink locked path '+p);
  if(!fs.lstatSync(name).isFile())fail('non-file locked path '+p);return fs.readFileSync(name);
 };
 const parentBytes=read('infra/security/policy/versions/trivy-parent-baseline-v1.json');
 if(sha(parentBytes)!==parentHash)fail('frozen v1 manifest changed');
 const parent=JSON.parse(parentBytes),integrationBytes=read('infra/security/policy/versions/trivy-parent-helm-shadow-v1.json');
 if(sha(integrationBytes)!==integrationHash)fail('integration manifest changed');
 const integration=JSON.parse(integrationBytes),pipeline=read('Jenkinsfile.security-audit'),identity=sha(pipeline);
 let lock,baselineId;
 if(identity===parent.sourceHashes['Jenkinsfile.security-audit']){lock=parent;baselineId='frozen-baseline-v1';}
 else if(identity===integration.sourceHashes['Jenkinsfile.security-audit']){lock=integration;baselineId='helm-shadow-integration-v1';}
 else fail('unknown Jenkinsfile identity');
 if(integration.parentManifestSha256!==parentHash || integration.policyVersion!==parent.policyVersion
  || integration.command!==parent.command || integration.productionActivation!==false)fail('invalid version lineage');
 if(JSON.stringify(Object.keys(integration.sourceHashes).sort())!==JSON.stringify(Object.keys(parent.sourceHashes).sort()))fail('source coverage changed');
 for(const [p,h]of Object.entries(parent.sourceHashes))if(p!=='Jenkinsfile.security-audit'&&integration.sourceHashes[p]!==h)fail('non-Helm gate identity changed '+p);
 for(const [p,h]of Object.entries(lock.sourceHashes))if(sha(read(p))!==h)fail('locked file changed '+p);
 let restoredV1Sha256=null;
 if(baselineId==='helm-shadow-integration-v1'){
  // Proof of the reviewed transition, after the complete new source identity was verified.
  // The actual current Jenkinsfile is never replaced or stripped for execution/replay.
  for(const [p,h]of Object.entries(integration.helmSourceHashes))if(sha(read(p))!==h)fail('Helm integration identity changed '+p);
  restoredV1Sha256=sha(removePinnedHelmBlocks(pipeline.toString('utf8')));
  if(restoredV1Sha256!==parent.sourceHashes['Jenkinsfile.security-audit'])fail('security stage text changed');
 }
 return {lock,baselineId,policyVersion:parent.policyVersion,JenkinsfileSha256:identity,
  manifestSha256:baselineId==='frozen-baseline-v1'?parentHash:integrationHash,
  parentManifestSha256:parentHash,restoredV1Sha256,sourceIdentityChecks:Object.keys(lock.sourceHashes).length,
  helmIdentityChecks:baselineId==='helm-shadow-integration-v1'?Object.keys(integration.helmSourceHashes).length:0};
}
