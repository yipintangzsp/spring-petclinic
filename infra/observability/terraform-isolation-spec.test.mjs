import {test} from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import {jobSpec,admissionPolicies,namespace} from './terraform-isolation-spec.mjs';
const args={name:'tf-test-case',image:'127.0.0.1:30050/petclinic/terraform-runner@sha256:'+'a'.repeat(64),mode:'shared',source:'b'.repeat(40),api:'https://10.0.0.3:6443',canary:'10.42.0.1'};
test('isolated Job has no host storage, no default token, non-root readonly kernel confinement',()=>{const j=jobSpec(args),p=j.spec.template.spec;assert.equal(j.metadata.namespace,namespace);assert.equal(p.automountServiceAccountToken,false);assert.equal(p.hostPID,false);assert.equal(p.hostNetwork,false);assert.equal(p.securityContext.runAsUser,65532);assert.equal(p.containers[0].securityContext.readOnlyRootFilesystem,true);assert.equal(p.containers[0].securityContext.allowPrivilegeEscalation,false);assert.deepEqual(p.containers[0].securityContext.capabilities.drop,['ALL']);assert.ok(p.volumes.every(v=>v.emptyDir||v.projected));assert.equal(p.containers[0].resources.limits.memory,'512Mi');assert.equal(p.volumes[1].projected.sources[0].serviceAccountToken.expirationSeconds,600);});
test('mutable images, arbitrary endpoints and wrong node address rejected',()=>{for(const change of [{image:'python:latest'},{api:'https://example.com:443'},{canary:'127.0.0.1'},{mode:'shell'}])assert.throws(()=>jobSpec({...args,...change}));});
test('admission denies both Pod and Job escape and fences former runtime identity',()=>{const x=admissionPolicies(args.image);assert.equal(x.items.length,6);for(const p of x.items.filter(x=>x.kind==='ValidatingAdmissionPolicy')){assert.equal(p.spec.failurePolicy,'Fail');assert.ok(p.spec.validations.length>0);assert.ok(p.spec.validations.every(v=>v.reason==='Forbidden'));}const pod=x.items[0];assert.equal(pod.spec.matchConstraints.namespaceSelector.matchLabels['petclinic.devops.local/execution-sandbox'],'true');assert.ok(pod.spec.validations.some(v=>v.expression.includes('readOnlyRootFilesystem')));assert.ok(pod.spec.validations.some(v=>v.expression.includes(args.image)));assert.ok(x.items.some(x=>x.spec?.validations?.some(v=>v.expression.includes('terraform-execution')&&v.expression.includes('subjects'))));});
test('executor metadata forbids persistent storage, service secrets and extra compute',()=>{const b=JSON.parse(fs.readFileSync('infra/devops-lab/iac/isolated/bootstrap.json'));const q=b.items.find(x=>x.kind==='ResourceQuota');assert.equal(q.spec.hard.pods,'1');assert.equal(q.spec.hard.persistentvolumeclaims,'0');assert.equal(q.spec.hard.secrets,'0');const role=b.items.find(x=>x.kind==='Role');assert.ok(role.rules.every(r=>!r.resources.includes('secrets')&&!r.resources.includes('pods/exec')));const np=b.items.find(x=>x.kind==='NetworkPolicy');assert.deepEqual(np.spec.podSelector,{});assert.deepEqual(np.spec.egress[0].to,[{ipBlock:{cidr:'10.0.0.3/32'}}]);assert.deepEqual(np.spec.egress[0].ports,[{protocol:'TCP',port:6443}]);});

import {createCanaryServer,client,selectOwnedPod,observedLog} from './terraform-executor.mjs';
import net from 'node:net';
test('canary peer resets cannot crash the deployment controller',async()=>{
 const server=createCanaryServer();await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
 try{await new Promise((resolve,reject)=>{server.once('connection',socket=>{try{assert.ok(socket.listenerCount('error')>0);socket.emit('error',Error('simulated ECONNRESET'));resolve();}catch(e){reject(e);}});const client=net.connect(server.address().port,'127.0.0.1');client.on('error',()=>{});client.on('data',()=>client.end());});}finally{await new Promise(resolve=>server.close(resolve));}
});

import http from 'node:http';
test('DELETE transmits UID precondition and foreground policy to API server',async()=>{
 let received;const server=http.createServer((request,response)=>{let text='';request.on('data',c=>text+=c);request.on('end',()=>{received={method:request.method,body:JSON.parse(text),length:request.headers['content-length']};response.writeHead(200,{'Content-Type':'application/json'});response.end('{}');});});
 await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
 try{const api=client('test-only',{ca:Buffer.from(''),transport:http,origin:'http://127.0.0.1:'+server.address().port});const body={apiVersion:'v1',kind:'DeleteOptions',preconditions:{uid:'owned-job-uid'},propagationPolicy:'Foreground'};assert.equal((await api('DELETE','/owned-job',body)).status,200);assert.deepEqual(received.body,body);assert.equal(received.method,'DELETE');assert.ok(Number(received.length)>0);}finally{await new Promise(resolve=>server.close(resolve));}
});

const ownedPod={metadata:{name:'owned',uid:'pod-uid',ownerReferences:[{uid:'job-uid'}]}};
test('deadline can use previously observed owned Pod after controller removal',()=>assert.equal(selectOwnedPod([],ownedPod,'job-uid',true),ownedPod));
test('missing Pod without an observed UID cannot prove deadline completion',()=>assert.throws(()=>selectOwnedPod([],null,'job-uid',true)));
test('ordinary success and failure cannot silently reuse a disappeared Pod',()=>assert.throws(()=>selectOwnedPod([],ownedPod,'job-uid',false)));
test('foreign owner or replacement Pod cannot pass the cached UID guard',()=>{assert.throws(()=>selectOwnedPod([ownedPod],null,'foreign',true));assert.throws(()=>selectOwnedPod([{metadata:{...ownedPod.metadata,uid:'replacement'}}],ownedPod,'job-uid',true));});

test('empty startup logs and transient responses preserve evidence without granting success',()=>{
 assert.equal(observedLog('',{status:204,text:''}),'');
 assert.equal(observedLog('partial',{status:204,text:''}),'partial');
 assert.equal(observedLog('partial',{status:200,text:''}),'partial');
 assert.equal(observedLog('partial',{status:200,text:'complete'}),'complete');
 for(const status of [400,404,408,429,500,502,503,504])assert.equal(observedLog('saved',{status}),'saved');
 for(const status of [201,401,403])assert.throws(()=>observedLog('saved',{status}));
});
