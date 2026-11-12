import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import net from 'node:net';
import {routeResultsWithLoki} from '../router.mjs';
import {replay} from '../consumers/dojo-http-fixtures.mjs';
import {deliverRunToLoki,grafanaRunUrl,withExistingLokiChannel,lokiDeliveryRecord} from './loki-delivery.mjs';
import {digest} from '../../summary-v2/codec.mjs';
const temporary=fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(),'auto-loki-test-')));let n=0;
const output=()=>{const p=path.join(temporary,String(n++));fs.mkdirSync(p,{mode:0o700});return p;};
const source=()=>{const x=replay('A-three-valid');return {run:{summary:x.summary},artifactDirectory:x.dir,expectedSealDigest:x.expected,expectedProjectId:x.summary.projectId};};
test.after(()=>fs.rmSync(temporary,{recursive:true}));
test('selected Router sends only selected plugin facts; default remains dry-run',async()=>{
 const input=source(),before=fs.readFileSync(path.join(input.artifactDirectory,'candidate-summary.json')),out=output();
 const r=await routeResultsWithLoki({...input,definitions:[],singlePluginId:'semgrep',lokiOutput:out});
 assert.equal(r.lokiDelivery.deliveryState,'DRY_RUN');assert.equal(r.lokiDelivery.httpRequestCount,0);
 const plan=JSON.parse(fs.readFileSync(path.join(out,fs.readdirSync(out)[0],'loki-plan.json')));
 assert.equal(plan.events.length,1);assert.equal(plan.events[0].pluginId,'semgrep');
 assert.equal(plan.events[0].resultDigest,input.run.summary.pluginResults.find(p=>p.pluginId==='semgrep').resultDigest);
 assert.deepEqual(fs.readFileSync(path.join(input.artifactDirectory,'candidate-summary.json')),before);
});
test('historical REAL evidence cannot be relabeled as fresh automatic execution',async()=>{
 const input=source(),r=await routeResultsWithLoki({...input,definitions:[],singlePluginId:'semgrep',freshRunId:input.run.summary.runId,lokiOutput:output()});
 assert.equal(r.lokiDelivery.deliveryState,'ERROR');assert.equal(r.lokiDelivery.diagnosticCode,'LOKI_FRESH_EXECUTION_EVIDENCE_REQUIRED');assert.equal(r.lokiDelivery.httpRequestCount,0);
});
test('wrong fresh Run ID is rejected before HTTP',async()=>{
 const r=await routeResultsWithLoki({...source(),definitions:[],singlePluginId:'semgrep',freshRunId:'wrong-run',lokiOutput:output()});
 assert.equal(r.lokiDelivery.diagnosticCode,'LOKI_FRESH_RUN_BINDING');assert.equal(r.lokiDelivery.httpRequestCount,0);
});
test('MOCK or incomplete scanner result never opens real channel',async()=>{
 await assert.rejects(deliverRunToLoki({evidenceClass:'MOCK',state:'COMPLETED',evaluationCount:1},temporary),/LOKI_REAL_RESULT_REQUIRED/);
 await assert.rejects(deliverRunToLoki({evidenceClass:'REAL',state:'DISABLED',evaluationCount:0},temporary),/LOKI_REAL_RESULT_REQUIRED/);
});
test('preoccupied localhost port refuses channel rather than trusting a listener',async()=>{
 const s=net.createServer();await new Promise((resolve,reject)=>{s.once('error',reject);s.listen(32189,'127.0.0.1',resolve);});
 try{await assert.rejects(withExistingLokiChannel(()=>assert.fail('must not run')),/LOKI_CHANNEL_PORT_OCCUPIED/);}finally{await new Promise(resolve=>s.close(resolve));}
});
test('Grafana link binds exact project, run, digest and execution time window',()=>{
 const u=new URL(grafanaRunUrl({runId:'web-fixed',projectId:'java-fixture',resultDigest:'a'.repeat(64),completedAt:'2026-11-06T04:31:25.265Z'}));
 assert.equal(u.host,'grafana.devops.local');assert.equal(u.searchParams.get('var-run'),'web-fixed');assert.equal(u.searchParams.get('var-project'),'java-fixture');assert.equal(u.searchParams.get('var-resultDigest'),'a'.repeat(64));
 assert.equal(Number(u.searchParams.get('to'))-Number(u.searchParams.get('from')),360000);
});

test('preparation-error Router receipt carries an explicit null HTTP status',async()=>{
 const r=await routeResultsWithLoki({...source(),definitions:[],singlePluginId:'semgrep',freshRunId:'wrong-run',lokiOutput:output()});
 assert.equal(r.lokiDelivery.deliveryState,'ERROR');assert.ok(Object.hasOwn(r.lokiDelivery,'httpStatus'));assert.equal(r.lokiDelivery.httpStatus,null);
 const {receiptDigest,...body}=r.lokiDelivery;assert.equal(digest(body),receiptDigest);
});
test('view delivery record stays pure JSON when the receipt has no HTTP status',()=>{
 const receipt={deliveryState:'ERROR',diagnosticCode:'LOKI_PLUGIN_SELECTION_REJECTED',timestamp:'2026-11-12T11:39:12.773Z',httpRequestCount:0,receiptDigest:'a'.repeat(64)};
 const record=lokiDeliveryRecord({runId:'web-fixed',resultDigest:'b'.repeat(64)},receipt,'http://grafana.devops.local/x','loki-delivery/router-receipt.json');
 assert.equal(record.pushHttpStatus,null);assert.equal(record.pushState,'ERROR');assert.equal(record.reason,'LOKI_PLUGIN_SELECTION_REJECTED');
 digest({lokiDelivery:record});
 assert.throws(()=>digest({lokiDelivery:{pushHttpStatus:undefined}}),/non-JSON value/);
});
