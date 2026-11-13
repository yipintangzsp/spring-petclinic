import test from 'node:test';import assert from 'node:assert/strict';import fs from 'node:fs';import {kubescapeEvidence} from './kubescape-evidence.mjs';
const archived=JSON.parse(fs.readFileSync('evidence/2026-11-01/remaining-policy/archived-270.json')).reports['kubescape-gate.json'];
test('archived audit findings retained separately from successful execution',()=>{const raw={report:archived},before=JSON.stringify(raw),r=kubescapeEvidence(raw);assert.equal(r.decision,'PASS');assert.ok(r.findings>0);assert.equal(r.auditDisposition,'WARN');assert.equal(JSON.stringify(raw),before);});
test('synthetic execution failure blocks; not a real negative claim',()=>{assert.equal(kubescapeEvidence({report:{mode:'AUDIT',status:'failed',error:'fixture'}}).decision,'FAIL');});
test('missing scan evidence never becomes PASS',()=>{assert.equal(kubescapeEvidence({report:{...archived,scans:[]}}).decision,null);assert.equal(kubescapeEvidence({}).status,'NOT_CONFIGURED');});
