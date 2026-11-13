// Keep the already validated Sonar runtime available during serial analysis cleanup.
import fs from 'node:fs';
import {createHash} from 'node:crypto';
import {spawnSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';

export function planSonarRuntime(item, lease, config, holder) {
 if (!holder || holder.endsWith('undefined') || lease.spec?.holderIdentity !== holder) throw Error('Owned heavy Lease required');
 if (item.metadata.uid !== config.statefulSetUid) throw Error('Sonar UID changed');
 if (item.metadata.annotations?.['petclinic.devops.local/analysis-holder']) throw Error('Analysis still owns Sonar');
 if (item.spec.replicas !== 1) throw Error('Sonar must be restored to its original replica before maintenance');
 const spec=item.spec.template.spec;
 const groups=[['initContainers',spec.initContainers??[]],['containers',spec.containers??[]]];
 const names=groups.flatMap(([,values])=>values.map(c=>c.name)).sort();
 if (JSON.stringify(names)!==JSON.stringify([...config.containerNames].sort())) throw Error('Unexpected Sonar container set');
 const changes=[];
 for (const [key,containers] of groups) for (const [index,c] of containers.entries()) {
  if (![config.sourceImage,config.image].includes(c.image)) throw Error('Unexpected Sonar version; do not overwrite');
  if (c.image!==config.image) changes.push({op:'test',path:`/spec/template/spec/${key}/${index}/image`,value:c.image},
    {op:'replace',path:`/spec/template/spec/${key}/${index}/image`,value:config.image});
  if (c.imagePullPolicy!=='IfNotPresent') changes.push({op:'add',path:`/spec/template/spec/${key}/${index}/imagePullPolicy`,value:'IfNotPresent'});
 }
 return changes.length ? [{op:'test',path:'/metadata/uid',value:config.statefulSetUid},
   {op:'test',path:'/spec/replicas',value:1},...changes] : [];
}

export function verifyContent(bytes,digest) {
 if ('sha256:'+createHash('sha256').update(bytes).digest('hex')!==digest) throw Error('Runtime cache digest mismatch');
 return JSON.parse(bytes.toString('utf8'));
}

function kube(args, timeout=15000, requestTimeout='10s') {
 const r=spawnSync('kubectl',['--request-timeout='+requestTimeout,...args],{encoding:'utf8',timeout});
 if (r.status!==0) throw Error('Sonar runtime Kubernetes operation failed: '+r.stderr.slice(-600));
 return r.stdout;
}

async function main() {
 const config=JSON.parse(fs.readFileSync(new URL('../sonarqube/runtime.json',import.meta.url),'utf8'));
 const digest=config.image.split('@')[1];
 if (!/^sha256:[a-f0-9]{64}$/.test(digest)) throw Error('Pinned runtime digest required');
 const base='http'+'://'+config.registry+'/v2/'+config.repository;
 async function get(path,accept) {
  const r=await fetch(base+path,{headers:accept?{Accept:accept}:{},signal:AbortSignal.timeout(15000)});
  if(!r.ok)throw Error('Verified local Sonar cache is unavailable: HTTP '+r.status);
  return Buffer.from(await r.arrayBuffer());
 }
 const manifest=verifyContent(await get('/manifests/'+digest,'application/vnd.oci.image.manifest.v1+json'),digest);
 const imageConfig=verifyContent(await get('/blobs/'+manifest.config.digest),manifest.config.digest);
 if(imageConfig.architecture!=='arm64'||imageConfig.os!=='linux')throw Error('Expected the current linux/arm64 Sonar runtime');
 const item=JSON.parse(kube(['-n','sonarqube','get','statefulset','sonarqube-sonarqube','-o','json']));
 const lease=JSON.parse(kube(['-n','data-infra','get','lease','platform-heavy','-o','json']));
 const holder=process.env.HEAVY_HOLDER||`jenkins-petclinic-${process.env.BUILD_NUMBER}`;
 const patch=planSonarRuntime(item,lease,config,holder);
 const before=['initContainers','containers'].flatMap(key=>(item.spec.template.spec[key]??[]).map((c,index)=>({
   group:key,index,name:c.name,image:c.image,imagePullPolicy:c.imagePullPolicy})));
 const rollbackPatch=[{op:'test',path:'/metadata/uid',value:config.statefulSetUid}];
 for(const c of before)if(c.image!==config.image)rollbackPatch.push(
   {op:'test',path:`/spec/template/spec/${c.group}/${c.index}/image`,value:config.image},
   {op:'replace',path:`/spec/template/spec/${c.group}/${c.index}/image`,value:c.image});
 const evidence={createdAt:new Date().toISOString(),uid:item.metadata.uid,holder,image:config.image,before,
   claims:(item.spec.template.spec.volumes??[]).filter(v=>v.persistentVolumeClaim).map(v=>v.persistentVolumeClaim.claimName),
   plannedChange:patch.length>0,rollbackPatch,ready:false};
 const save=()=>fs.writeFileSync('.sonar-runtime-maintenance.json',JSON.stringify(evidence,null,2));
 save();
 if(patch.length)kube(['-n','sonarqube','patch','statefulset','sonarqube-sonarqube','--type=json','-p',JSON.stringify(patch)]);
 kube(['-n','sonarqube','rollout','status','statefulset/sonarqube-sonarqube','--timeout=600s'],615000,'610s');
 const live=JSON.parse(kube(['-n','sonarqube','get','statefulset','sonarqube-sonarqube','-o','json']));
 if(planSonarRuntime(live,lease,config,holder).length || live.status?.readyReplicas!==1 || live.status.observedGeneration<live.metadata.generation) throw Error('Sonar did not converge to the exact cached runtime');
 evidence.ready=true;evidence.verifiedReadyAt=new Date().toISOString();save();
 console.log(JSON.stringify({sonarRuntime:config.image,changed:patch.length>0,ready:true,versionUnchanged:true}));
}
if(process.argv[1]===fileURLToPath(import.meta.url))main().catch(e=>{console.error(e.message);process.exitCode=1;});
