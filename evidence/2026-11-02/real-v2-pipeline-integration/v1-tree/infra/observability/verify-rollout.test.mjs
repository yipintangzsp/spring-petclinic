import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {assess,verify} from './verify-rollout.mjs';
const image='registry/petclinic:immutable',revision='release-git-sha',now=Date.now();
function state(){return {
 deployment:{metadata:{generation:2},spec:{replicas:3,template:{spec:{containers:[{name:'petclinic',image}]}}},status:{observedGeneration:2,replicas:3,updatedReplicas:3,readyReplicas:3,availableReplicas:3}},
 pods:['devops','aliyun-worker','ucloud-worker'].map((node,i)=>({metadata:{name:`pod-${i}`,uid:`uid-${i}`},spec:{nodeName:node,containers:[{name:'petclinic',image}]},status:{phase:'Running',conditions:[{type:'Ready',status:'True'}],containerStatuses:[{name:'petclinic',restartCount:0,state:{running:{}}}]}})),
 nodes:['devops','aliyun-worker','ucloud-worker'].map(name=>({metadata:{name},status:{conditions:[{type:'Ready',status:'True'}]}})),
 leases:['devops','aliyun-worker','ucloud-worker'].map(name=>({metadata:{name},spec:{renewTime:new Date(now).toISOString()}})),events:[],
 argo:{status:{sync:{status:'Synced',revision},health:{status:'Healthy'}}},
};}
test('three Ready Pods require the exact immutable image and Argo source revision',()=>{
 const s=state();assert.equal(assess(s,image,revision,now).complete,true);
 s.argo.status.sync.revision='another-commit';assert.equal(assess(s,image,revision,now).complete,false);
});
test('a concurrent rollback cannot be reported as successful deployment',()=>{
 const s=state();s.deployment.spec.template.spec.containers[0].image='registry/petclinic:previous';
 assert.match(assess(s,image,revision,now).fatal,/RELEASE_SUPERSEDED/);
});
test('available old replicas cannot conceal an unready new Pod',()=>{
 const s=state();s.pods[2].status.conditions[0].status='False';s.pods[2].status.phase='Pending';
 assert.equal(assess(s,image,revision,now).complete,false);assert.equal(assess(s,image,revision,now).blockers[0].node,'ucloud-worker');
});
test('FailedMount correlated to its Pod UID, stale Lease and non-Ready node is diagnosed',()=>{
 const s=state();s.pods[2].status.conditions[0].status='False';s.nodes[2].status.conditions[0].status='Unknown';
 s.leases[2].spec.renewTime=new Date(now-120000).toISOString();
 s.events=[{involvedObject:{uid:'uid-2'},type:'Warning',reason:'FailedMount',message:'failed to sync configmap cache: timed out waiting for the condition'}];
 const r=assess(s,image,revision,now);assert.equal(r.blockers[0].nodeSyncBlocked,true);assert.equal(r.fatal,null);
 s.nodes[2].status.conditions[0].status='True';assert.equal(assess(s,image,revision,now).blockers[0].nodeSyncBlocked,false);
});
test('a transient network image pull failure is not classified as a permanent image error',()=>{
 const s=state();s.pods[2].status.conditions[0].status='False';s.pods[2].status.containerStatuses[0].state={waiting:{reason:'ImagePullBackOff'}};
 s.events=[{involvedObject:{uid:'uid-2'},type:'Warning',reason:'Failed',message:'connection timed out'}];
 assert.equal(assess(s,image,revision,now).fatal,null);
 s.events[0].message='manifest unknown';assert.match(assess(s,image,revision,now).fatal,/pod-2 on ucloud-worker/);
});
test('bounded API failure cannot pass a release and creates a diagnostic artifact',async()=>{
 const dir=fs.mkdtempSync(path.join(os.tmpdir(),'rollout-api-failure-'));
 fs.writeFileSync(path.join(dir,'kubectl'),'#!/bin/sh\necho "API unreachable" >&2\nexit 1\n',{mode:0o700});
 const previous=process.env.PATH;process.env.PATH=dir+path.delimiter+previous;
 const output=path.join(dir,'result.json');
 try{
  await assert.rejects(verify(image,revision,{timeoutMs:30,pollMs:1,output}),/ROLLOUT_TIMEOUT/);
  const result=JSON.parse(fs.readFileSync(output));assert.match(result.failure,/ROLLOUT_TIMEOUT/);assert.ok(result.samples.some(s=>s.apiError));
 }finally{process.env.PATH=previous;fs.rmSync(dir,{recursive:true,force:true});}
});

test('cached Ready Pods on an unreachable node cannot pass a release',()=>{
 const s=state();s.nodes[2].status.conditions[0].status='Unknown';assert.equal(assess(s,image,revision,now).complete,false);
 s.nodes[2].status.conditions[0].status='True';s.leases[2].spec.renewTime=new Date(now-60000).toISOString();assert.equal(assess(s,image,revision,now).complete,false);
});
