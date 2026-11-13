// Controlled fixture tests of strict byte identity, NOT a replacement proxy validator.
import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import {verifyCheckpoint} from './verify-checkpoint.mjs';
const sha=b=>crypto.createHash('sha256').update(b).digest('hex');
const fixture={inbounds:[{listen:'127.0.0.1',port:10808,protocol:'mixed',settings:{auth:'noauth'}}],routing:{domainStrategy:'AsIs',rules:[]},outbounds:[{protocol:'fixture',settings:{address:'example.invalid'},streamSettings:{allowInsecure:false}}]};
const bytes=Buffer.from(JSON.stringify(fixture)),expected=sha(bytes);
for(const [name,mutate] of [
 ['listener',x=>x.inbounds[0].listen='127.0.0.2'],
 ['port',x=>x.inbounds[0].port=10809],
 ['LAN exposure',x=>x.inbounds[0].listen='0.0.0.0'],
 ['routing mode',x=>x.routing.domainStrategy='IPIfNonMatch'],
 ['outbound identity',x=>x.outbounds[0].settings.address='other.example.invalid'],
 ['security flag',x=>x.outbounds[0].streamSettings.allowInsecure=true],
])test(`strict byte contract rejects controlled ${name} change`,()=>{const copy=structuredClone(fixture);mutate(copy);assert.notEqual(sha(Buffer.from(JSON.stringify(copy))),expected);assert.equal(sha(bytes),expected);});
test('existing strict byte contract does not exempt whitespace volatility',()=>assert.notEqual(sha(Buffer.from(JSON.stringify(fixture,null,2))),expected));
test('sealed checkpoint still refuses acceptance on unexplained historical proxy drift',()=>{const base=path.dirname(new URL(import.meta.url).pathname),root=path.resolve(base,'../../..'),anchor=JSON.parse(fs.readFileSync(path.join(base,'checkpoint-digest.json')));const r=verifyCheckpoint({root,checkpointPath:anchor.checkpointPath,expectedSha256:anchor.sha256});assert.equal(r.status,'FAILED');assert.equal(r.resumeAllowed,false);assert.ok(r.blockedReasons.includes('UNEXPLAINED_PROXY_CONFIG_DRIFT'));});
