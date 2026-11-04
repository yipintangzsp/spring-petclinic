// Source identity verification only. The frozen decision body is unchanged.
import fs from 'node:fs';import path from 'node:path';import {fileURLToPath} from 'node:url';import {createHash} from 'node:crypto';
const sha=x=>createHash('sha256').update(x).digest('hex');
const parentHash='3311c1cc8c18adcf08d6f3d565a5d09a27c308e3522f66c6eb45993a3d14cf59',integrationHash='703522f925071eb773193c349ebcf0a53bccbda68fda24bf6cb2a615d1e27c62';
const fail=x=>{throw Error('POLICY_ERROR: Gitleaks source identity: '+x);};
export function removeGitleaksHelmBlocks(text){
 for(const k of ['ARCHIVE','PARAMETERS','PRECONDITIONS','STAGES']){
  const begin='// HELM_SHADOW_'+k+'_BEGIN',end='// HELM_SHADOW_'+k+'_END';
  if(text.split(begin).length!==2||text.split(end).length!==2)fail('ambiguous Helm block');
  text=text.replace(new RegExp('// HELM_SHADOW_'+k+'_BEGIN[\\s\\S]*?// HELM_SHADOW_'+k+'_END\\n'+(k==='STAGES'?'\\n':'')),'');
 }
 return text;
}
export function verifyGitleaksSourceLock({root=fileURLToPath(new URL('../../../',import.meta.url))}={}){
 root=path.resolve(root);const read=p=>{
  if(path.isAbsolute(p)||p.split('/').some(x=>['..','.',''].includes(x)))fail('unsafe path');const f=path.join(root,p);
  if(fs.realpathSync(f)!==f||!fs.lstatSync(f).isFile())fail('symlink/type');return fs.readFileSync(f);
 };
 const pbytes=read('infra/security/policy/versions/gitleaks-parent-baseline-v1.json'),ibytes=read('infra/security/policy/versions/gitleaks-parent-helm-shadow-v1.json');
 if(sha(pbytes)!==parentHash||sha(ibytes)!==integrationHash)fail('manifest integrity');const p=JSON.parse(pbytes),i=JSON.parse(ibytes);
 const frozen=read('infra/security/policy/versions/gitleaks-parent.frozen-v1.mjs').toString(),adapter=read('infra/security/policy/gitleaks-parent.mjs').toString();
 if(sha(adapter)!==i.currentAdapterSha256||sha(frozen)!==i.frozenAdapterSha256||sha(frozen.slice(frozen.indexOf(' const absent=')))!==i.algorithmBodySha256||sha(adapter.slice(adapter.indexOf(' const absent=')))!==i.algorithmBodySha256)fail('decision body changed');
 if(i.parentManifestSha256!==parentHash||i.policyVersion!==p.policyVersion||i.command!==p.command||i.productionActivation!==false||JSON.stringify(Object.keys(i.sourceHashes).sort())!==JSON.stringify(Object.keys(p.sourceHashes).sort()))fail('lineage/coverage');
 for(const [name,h]of Object.entries(p.sourceHashes))if(name!=='Jenkinsfile.security-audit'&&i.sourceHashes[name]!==h)fail('non-Helm gate identity');
 const pipeline=read('Jenkinsfile.security-audit'),hash=sha(pipeline);
 const baselineId=hash===p.sourceHashes['Jenkinsfile.security-audit']?'frozen-baseline-v1':hash===i.sourceHashes['Jenkinsfile.security-audit']?'gitleaks-helm-shadow-v1':null;
 if(!baselineId)fail('unknown Jenkinsfile identity');const lock=baselineId==='frozen-baseline-v1'?p:i;
 for(const [name,h]of Object.entries(lock.sourceHashes))if(sha(read(name))!==h)fail('locked file changed');
 const projected=baselineId==='gitleaks-helm-shadow-v1'?sha(removeGitleaksHelmBlocks(pipeline.toString())):hash;
 if(projected!==p.sourceHashes['Jenkinsfile.security-audit'])fail('original pipeline semantics changed');
 return {lock,baselineId,parentManifestSha256:parentHash,manifestSha256:baselineId==='frozen-baseline-v1'?parentHash:integrationHash,JenkinsfileSha256:hash,restoredV1Sha256:projected,decisionBodySha256:i.algorithmBodySha256};
}
