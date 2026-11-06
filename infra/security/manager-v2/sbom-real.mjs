// Existing Core plugin adapter. Generates only the code-owned configured project via fixed SSH.
import fs from 'node:fs';import path from 'node:path';import os from 'node:os';import {execFile} from 'node:child_process';import {promisify} from 'node:util';
import {sha,digest,freeze,canonical} from '../summary-v2/codec.mjs';import {keys} from './config.mjs';
import {sbomParent} from '../policy/sbom-parent.mjs';
const exec=promisify(execFile),key=path.join(os.homedir(),'.ssh/security-manager-v2-sbom');
export const sbomProjects=()=>JSON.parse(fs.readFileSync(new URL('./sbom/projects.json',import.meta.url))).projects;
export const sbomReady=()=>{try{const st=fs.lstatSync(key);return st.isFile()&&st.uid===process.getuid()&&!(st.mode&0o077)&&Object.values(sbomProjects()).some(p=>!p.blockedReason);}catch{return false;}};
export async function executeRealSbom(plugin,input,{projectId,runId,signal}={}){
 keys(input,['fixtureId']);const cfg=sbomProjects()[projectId];if(!cfg||cfg.fixtureId!==input.fixtureId||!sbomReady())throw Error('SBOM_PROJECT_NOT_AUTHORIZED');
 const args=['-F','/dev/null','-T','-n','-i',key,'-o','BatchMode=yes','-o','IdentitiesOnly=yes','-o','IdentityAgent=none','-o','StrictHostKeyChecking=yes','-o','UpdateHostKeys=no','-o','UserKnownHostsFile='+path.join(os.homedir(),'.ssh/known_hosts'),'-o','GlobalKnownHostsFile=/dev/null','-o','HostKeyAlias=192.168.1.58','-o','ClearAllForwardings=yes','-o','ConnectTimeout=5','-o','ConnectionAttempts=1','security-sbom@192.168.64.11','generate-v1 '+projectId+' '+runId];
 let stdout;
 try{({stdout}=await exec('/usr/bin/ssh',args,{signal,timeout:plugin.timeout,maxBuffer:2*1024*1024,env:{PATH:'/usr/bin:/bin',LANG:'C'}}));}
 catch(e){
  let packet;try{packet=JSON.parse(e.stdout);}catch{}
  const diagnostic=packet?.diagnostic;
  if(diagnostic&&diagnostic.runId===runId&&diagnostic.projectId===projectId&&diagnostic.uid===cfg.uid&&sha(canonical(diagnostic)+'\n')===packet.diagnosticSha256){
   const failure=Error(diagnostic.cleanup==='INCOMPLETE'?'RUNNER_CLEANUP_FAILED':'RUNNER_SCANNER_ERROR');
   failure.candidateEvidence={kind:'SbomExecutionDiagnostic',diagnostic,diagnosticSha256:packet.diagnosticSha256,rawReportDigest:null};throw failure;
  }
  throw Error('RUNNER_ERROR');
 }
 const packet=JSON.parse(stdout),expected=cfg.sourceArtifactSha256;
 if(packet.diagnostic?.runnerSha256!==cfg.runnerSha256||packet.diagnostic?.runId!==runId||packet.diagnostic?.exitCode!==0||packet.diagnostic?.cleanup!=='VERIFIED'||packet.diagnostic?.generationInvocations!==1||sha(canonical(packet.diagnostic)+'\n')!==packet.diagnosticSha256)throw Error('SBOM_DIAGNOSTIC_REJECTED');
 if(packet.kind!=='RestrictedLinuxSbom'||packet.runId!==runId||packet.projectId!==projectId||packet.sourceArtifactSha256!==expected||packet.toolSha256!==cfg.toolSha256||packet.uid!==cfg.uid||packet.groups.some(g=>g!==packet.gid)||!packet.noNewPrivs||packet.dockerReadable||packet.kubeconfigReadable||packet.exitCode!==0||packet.generationCount!==1)throw Error('SBOM_EXECUTION_EVIDENCE_REJECTED');
 const raw=Buffer.from(packet.sbomBase64,'base64'),packaged=Buffer.from(packet.packagedBase64,'base64');
 if(!raw.equals(packaged)||sha(raw)!==packet.sbomSha256||raw.length>1024*1024)throw Error('SBOM_BYTE_BINDING_FAILED');
 const bom=JSON.parse(raw);if(bom.bomFormat!=='CycloneDX'||bom.specVersion!=='1.6'||bom.components?.length!==packet.componentCount)throw Error('SBOM_FORMAT_INVALID');
 const fact={component:'sbom',status:'success',raw:{stage:'standalone',now:packet.completedAtMs,extraction:{status:0,base64:packet.packagedBase64},files:{'target/classes/META-INF/sbom/application.cdx.json':{value:packet.sbomBase64},'.git-sha':{value:'artifact-sha256:'+expected}},io:{'output-mkdir':{},'sbom-write':{},'summary-write':{}}}};
 const oldDecision=sbomParent(structuredClone(fact.raw)).decision;if(!['PASS','FAIL'].includes(oldDecision))throw Error('SBOM_OLD_GATE_EVIDENCE_INCOMPLETE');
 const runtimeFacts={schemaVersion:1,kind:'CandidateRuntimeSourceFacts',classification:'REAL_CONTROLLED_EXECUTION',pluginId:'sbom',validationRunId:runId,projectId,sourceArtifactSha256:expected,commitSha:cfg.commitSha,buildId:cfg.buildId,sourceIdentityKind:'FIXED_NON_GIT_INPUT',tool:{version:packet.toolVersion,sha256:packet.toolSha256},identity:{uid:packet.uid,gid:packet.gid,groups:packet.groups,noNewPrivs:packet.noNewPrivs,dockerReadable:false,kubeconfigReadable:false},startedAt:new Date(packet.startedAtMs).toISOString(),completedAt:new Date(packet.completedAtMs).toISOString(),scope:cfg.scope,packaging:packet.packaging,sbomSha256:sha(raw),format:bom.bomFormat,specVersion:bom.specVersion,componentCount:bom.components.length,exitCode:0,generationCount:1,diagnostic:packet.diagnostic,diagnosticSha256:packet.diagnosticSha256,factDigest:digest(fact),rawReportDigest:sha(raw),legacyPolicySourceField:'artifact-sha256; not a Git Commit'};
 return freeze({rawReportBytesUtf8:raw.toString(),rawReportDigest:sha(raw),fact,factDigest:digest(fact),runtimeFacts,oldDecision,executionScope:'REAL_CONTROLLED_APPLICATION_DEPENDENCY_SBOM',evidenceRefs:[{kind:'REAL_CONTROLLED_EXECUTION',validationRunId:runId,sourceArtifactSha256:expected,sbomSha256:sha(raw),canonicalRuntime:false}],cleanup:{status:'VERIFIED',privateReportDirectoryRemoved:true}});
}
