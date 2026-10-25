import {test} from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {validateRecipe,packageHash} from './terraform-provider-build.mjs';
const recipe=()=>JSON.parse(fs.readFileSync('infra/devops-lab/iac/isolated/security/provider-build.json'));
test('verified custom source recipe preserves fixed offline build bounds',()=>{const r=recipe();assert.equal(validateRecipe(r),r);});
test('resource escalation or unexpected build input cannot enter native build',()=>{for(const change of [r=>r.limits.cpu=2,r=>r.limits.memory_mib=4096,r=>r.limits.timeout_seconds=3600,r=>r.inputs['../escape']=Object.values(r.inputs)[0],r=>r.source_archive_root='../outside',r=>r.inputs['provider-source.tar.gz'].bytes=1024**4]){const r=recipe();change(r);assert.throws(()=>validateRecipe(r));}});
test('unverified vendor, mutable image and online build flags are rejected',()=>{for(const change of [r=>delete r.vendor_validation.errors,r=>r.vendor_validation.errors=['unverified file'],r=>r.builder_image='python:latest',r=>r.build_flags=['-mod=mod'],r=>r.custom_build_not_upstream_signed_binary=false]){const r=recipe();change(r);assert.throws(()=>validateRecipe(r));}});
test('provider package checksum changes on content tampering and refuses extra files or links',()=>{const d=fs.mkdtempSync(path.join(os.tmpdir(),'provider-package-'));const n='terraform-provider-kubernetes_v3.4.0-petclinic.1_x5';try{fs.writeFileSync(d+'/LICENSE.txt','license\n');fs.writeFileSync(d+'/'+n,'binary\n');const h=packageHash(d);fs.writeFileSync(d+'/'+n,'changed\n');assert.notEqual(packageHash(d),h);fs.writeFileSync(d+'/unexpected','x');assert.throws(()=>packageHash(d));fs.unlinkSync(d+'/unexpected');fs.unlinkSync(d+'/'+n);fs.symlinkSync(d+'/LICENSE.txt',d+'/'+n);assert.throws(()=>packageHash(d));}finally{fs.rmSync(d,{recursive:true,force:true});}});

import {hasUnmaintainedOpenpgpPath} from './terraform-provider-build.mjs';
test('old package path detection crosses streaming block boundaries and keeps maintained fork separate',()=>{const d=fs.mkdtempSync(path.join(os.tmpdir(),'old-pgp-path-'));try{const f=path.join(d,'binary');fs.writeFileSync(f,Buffer.concat([Buffer.alloc(1024*1024-8),Buffer.from('golang.org/x/crypto/openpgp/packet')]));assert.equal(hasUnmaintainedOpenpgpPath(f),true);fs.writeFileSync(f,'github.com/ProtonMail/go-crypto/openpgp');assert.equal(hasUnmaintainedOpenpgpPath(f),false);}finally{fs.rmSync(d,{recursive:true,force:true});}});
