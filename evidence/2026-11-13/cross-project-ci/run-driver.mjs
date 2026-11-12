// W11 cross-project driver: SBOM dual-project real runs through Manager Core,
// per-project override isolation, cross-project rejection negatives, router receipts.
// No credentials are read or written; project-access check records booleans only.
import fs from 'node:fs';import path from 'node:path';import {randomUUID} from 'node:crypto';import {execFileSync} from 'node:child_process';
import {runCandidate} from '../../../infra/security/manager-v2/core.mjs';
import {realManagedRegistry} from '../../../infra/security/manager-v2/registry.mjs';
import {routeResults,CONSUMERS} from '../../../infra/security/manager-v2/router.mjs';
import {sbomProjects,executeRealSbom,sbomReady} from '../../../infra/security/manager-v2/sbom-real.mjs';
import {accessCredentials} from '../../../infra/security/manager-v2/view/project-access.mjs';
import {sha} from '../../../infra/security/summary-v2/codec.mjs';
const PLUGIN='sbom';
const root=path.resolve(new URL('../../../',import.meta.url).pathname);
const runsRoot=path.join(root,'.devsecops/cross-project-runs');fs.mkdirSync(runsRoot,{recursive:true,mode:0o755});
const evDir=path.join(root,'evidence/2026-11-13/cross-project-ci/raw');fs.mkdirSync(evDir,{recursive:true});
const registry=realManagedRegistry();
const projects=sbomProjects();
const A='java-sbom-demo',B='java-sbom-demo-b';
const out={sbomReady:sbomReady(),projects:{},cases:[],switchTest:{},crossProject:{},router:[],secondBusinessProject:{},projectAccess:{}};
for(const id of [A,B])out.projects[id]={fixtureId:projects[id].fixtureId,sourceKind:projects[id].sourceKind,sourceArtifactSha256:projects[id].sourceArtifactSha256,profile:projects[id].profile};
// Real second business project identity (read-only local facts)
try{const lab=path.join(process.env.HOME,'code/petclinic-devops-lab');out.secondBusinessProject={path:'~/code/petclinic-devops-lab',exists:fs.existsSync(path.join(lab,'pom.xml')),head:execFileSync('/usr/bin/git',['-C',lab,'rev-parse','HEAD'],{encoding:'utf8'}).trim(),pomSha256:sha(fs.readFileSync(path.join(lab,'pom.xml'))),platformHead:execFileSync('/usr/bin/git',['-C',root,'rev-parse','HEAD'],{encoding:'utf8'}).trim()};}
catch(e){out.secondBusinessProject={error:e.message};}
// Project-access token isolation: booleans only, values never recorded
try{const c=accessCredentials();const ids=Object.keys(c.projects).sort();out.projectAccess={projectIds:ids,allTokensDistinct:new Set(Object.values(c.projects)).size===ids.length,operatorDistinctFromProjects:!Object.values(c.projects).includes(c.operatorToken),tokenShapeOk:Object.values(c.projects).every(t=>/^[a-f0-9]{64}$/.test(t))};}
catch(e){out.projectAccess={error:e.message};}
const baseConfig=(extra={})=>({security:{enabled:true,globalMode:'audit',securityLevel:'standard',profile:'java-web',plugins:Object.fromEntries(registry.ids().map(id=>[id,{enabled:id===PLUGIN}]))},...extra});
async function one(projectId,{config,tag}={}){
 const cfg=projects[projectId],runId='web-'+randomUUID(),dir=path.join(runsRoot,runId);fs.mkdirSync(dir,{mode:0o700});
 const artifactDir=path.join(dir,'artifact');
 const run=await runCandidate({registry,runId,projectId,context:{platform:process.platform,capabilities:{SBOM_FILE:{state:'AVAILABLE'}}},inputs:{[PLUGIN]:{fixtureId:cfg.fixtureId}},config:config??baseConfig(),output:artifactDir});
 const sel=run.gate[PLUGIN];
 const rec={tag,runId,projectId,fixtureId:cfg.fixtureId,executionStatus:sel.executionStatus,policyDecision:sel.policyDecision,evaluationCount:sel.evaluationCount,resultDigest:sel.resultDigest,artifactDigest:run.artifact.sealDigest,effectiveConfigDigest:run.summary.effectiveConfigDigest,failureReason:sel.failureReason,componentCount:sel.runtimeFacts?.componentCount??sel.runtimeFacts?.components??null,cleanup:sel.cleanup?.status??null};
 out.cases.push(rec);console.log('CASE',tag,projectId,rec.executionStatus,rec.policyDecision,'eval='+rec.evaluationCount);
 fs.cpSync(artifactDir,path.join(evDir,tag),{recursive:true});
 return {rec,dir,run,artifactDir};
}
const runA=await one(A,{tag:'project-a-real'});
const runB=await one(B,{tag:'project-b-real'});
out.identityIsolation={distinctRunIds:runA.rec.runId!==runB.rec.runId,distinctResultDigests:runA.rec.resultDigest!==runB.rec.resultDigest,distinctArtifactDigests:runA.rec.artifactDigest!==runB.rec.artifactDigest,distinctEffectiveConfigDigests:runA.rec.effectiveConfigDigest!==runB.rec.effectiveConfigDigest};
// Router receipts for both real runs
for(const r of [runA,runB]){
 const rdir=path.join(r.dir,'router');fs.mkdirSync(rdir,{mode:0o700});
 const routed=routeResults({run:r.run,artifactDirectory:r.artifactDir,expectedSealDigest:r.run.artifact.sealDigest,output:rdir,definitions:CONSUMERS.filter(c=>c.consumerId!=='defectdojo-future')});
 out.router.push({projectId:r.rec.projectId,runId:r.rec.runId,receipts:routed.receipts.map(x=>({consumerId:x.consumerId,deliveryDecision:x.deliveryDecision,receiptDigest:x.receiptDigest}))});
 console.log('ROUTER',r.rec.projectId,routed.receipts.map(x=>x.consumerId+':'+x.deliveryDecision).join(','));
}
// Independent per-project switch: same config object disables sbom ONLY for project B
const switchConfig=baseConfig({projectOverrides:{[B]:{plugins:{sbom:{enabled:false}}}}});
const offB=await one(B,{config:switchConfig,tag:'switch-b-disabled'});
const onA=await one(A,{config:switchConfig,tag:'switch-a-unaffected'});
out.switchTest={disabledProject:B,disabledStatus:offB.rec.executionStatus,disabledEvaluationCount:offB.rec.evaluationCount,unaffectedProject:A,unaffectedStatus:onA.rec.executionStatus,unaffectedDecision:onA.rec.policyDecision,unaffectedEvaluationCount:onA.rec.evaluationCount,sameConfigObject:true};
// Cross-project rejection negatives (local, before any SSH execution)
const plug=registry.get(PLUGIN);
for(const [name,pid,fid] of [['aProjectWithBFixture',A,projects[B].fixtureId],['bProjectWithAFixture',B,projects[A].fixtureId],['unknownProjectWithAFixture','no-such-project',projects[A].fixtureId],['secondBusinessProjectNotOnboarded','petclinic-devops-lab',projects[A].fixtureId]]){
 try{await executeRealSbom(plug,{fixtureId:fid},{projectId:pid,runId:'web-'+randomUUID()});out.crossProject[name]='NOT_REJECTED';}
 catch(e){out.crossProject[name]=e.message;}
 console.log('CROSS',name,out.crossProject[name]);
}
fs.writeFileSync(path.join(evDir,'core-driver-summary.json'),JSON.stringify(out,null,2)+'\n');
console.log('DRIVER_DONE');
