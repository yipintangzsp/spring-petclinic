import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import {promoteManifest} from './promote-private.mjs';
const original=fs.readFileSync(new URL('../../k8s/production/petclinic.yaml',import.meta.url),'utf8');
const release={image:'core.harbor.domain/petclinic/petclinic@sha256:'+'a'.repeat(64),tag:'0.10.0-ci-116',number:'116',source:'b'.repeat(40),time:'2026-10-11T05:00:00Z'};
test('promotion pins a digest and retains database, resources and zero surge',()=>{
 const result=promoteManifest(original,release);
 assert.ok(result.includes('image: '+release.image));
 assert.ok(result.includes("value: '0.10.0-ci-116'"));
 for(const line of original.split('\n').filter(x=>/SPRING_SQL_INIT_MODE|secretKeyRef|claimName|POSTGRES|memory:|maxSurge:|maxUnavailable:/.test(x)))assert.ok(result.includes(line));
});
test('reject mutable tags and mismatched build identity',()=>{
 assert.throws(()=>promoteManifest(original,{...release,image:'core.harbor.domain/petclinic/petclinic:latest'}));
 assert.throws(()=>promoteManifest(original,{...release,number:'117'}));
});
test('reject missing or duplicate release fields',()=>{
 assert.throws(()=>promoteManifest(original.replace('name: BUILD_NUMBER','name: OTHER'),release));
 assert.throws(()=>promoteManifest(original+'\nimage: '+release.image,release));
});
