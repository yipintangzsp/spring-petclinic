import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {planSonarRuntime,verifyContent} from './ensure-sonar-runtime.mjs';
const config={statefulSetUid:'original',sourceImage:'sonarqube:validated',image:'registry/sonarqube@sha256:pinned',containerNames:['init-sysctl','concat-properties','sonarqube']};
const lease={spec:{holderIdentity:'jenkins-petclinic-149'}};
function original(){return {metadata:{uid:'original',annotations:{}},spec:{replicas:1,template:{spec:{initContainers:[{name:'init-sysctl',image:config.sourceImage,imagePullPolicy:'IfNotPresent'},{name:'concat-properties',image:config.sourceImage,imagePullPolicy:'IfNotPresent'}],containers:[{name:'sonarqube',image:config.sourceImage,imagePullPolicy:'IfNotPresent'}],volumes:[{name:'original-pvc'}]}}}};}
function plan(v=original(),l=lease){return planSonarRuntime(v,l,config,'jenkins-petclinic-149');}
test('runtime patch pins both init containers and main without changing PVC or resources',()=>{
 const v=original(),before=structuredClone(v);const p=plan(v);
 assert.deepEqual(v,before);assert.equal(p.filter(x=>x.op==='replace').length,3);
 assert(p.filter(x=>x.op==='replace').every(x=>x.path.endsWith('/image')&&x.value===config.image));
 assert(p.some(x=>x.path==='/metadata/uid'&&x.op==='test'));
});
test('already pinned runtime requires no mutation',()=>{const v=original();for(const c of [...v.spec.template.spec.initContainers,...v.spec.template.spec.containers])c.image=config.image;assert.deepEqual(plan(v),[]);});
test('another heavy task cannot change Sonar',()=>assert.throws(()=>plan(original(),{spec:{holderIdentity:'airflow:other'}}),/Lease/));
test('replacement StatefulSet cannot be changed',()=>{const v=original();v.metadata.uid='foreign';assert.throws(()=>plan(v),/UID/);});
test('analysis owner cannot be overridden',()=>{const v=original();v.metadata.annotations['petclinic.devops.local/analysis-holder']='airflow:run';assert.throws(()=>plan(v),/owns/);});
test('paused service cannot be taken over',()=>{const v=original();v.spec.replicas=0;assert.throws(()=>plan(v),/replica/);});
test('different image or container set is preserved',()=>{const v=original();v.spec.template.spec.containers[0].image='sonarqube:new';assert.throws(()=>plan(v),/version/);v.spec.template.spec.containers=[];assert.throws(()=>plan(v),/container set/);});
test('cache content must match its immutable digest',()=>{const bytes=Buffer.from('{"architecture":"arm64"}');const digest='sha256:'+createHash('sha256').update(bytes).digest('hex');assert.equal(verifyContent(bytes,digest).architecture,'arm64');assert.throws(()=>verifyContent(Buffer.from('{}'),digest),/digest mismatch/);});
