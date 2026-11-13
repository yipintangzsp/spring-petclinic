import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import {evaluate} from './engine.mjs';

const root='evidence/2026-11-02/falco-time-contract-repair/';
const fixture=(mode,name)=>JSON.parse(fs.readFileSync(root+'fixtures/'+mode+'--'+name+'.json'));
const run=raw=>evaluate({component:raw.mode==='baseline'?'falco-baseline':'falco-final',status:'success',raw});
const evidence=[];
for(const mode of ['baseline','check']){
 test(mode+': missing first observed clock is incomplete, never a fixed-offset PASS',()=>{
  const raw=fixture(mode,'original-drift-2s');delete raw.observations.samples[0].windowEndMs;
  const before=JSON.stringify(raw),r=run(raw);assert.equal(r.status,'NOT_CONFIGURED');assert.equal(r.decision,null);assert.equal(JSON.stringify(raw),before);
  evidence.push({mode,name:'missing-first-clock',status:r.status,decision:r.decision});
 });
 test(mode+': missing second observed clock cannot fall back to first+16s',()=>{
  const raw=fixture(mode,'original-drift-2s');delete raw.observations.samples[1].windowEndMs;
  const r=run(raw);assert.equal(r.status,'NOT_CONFIGURED');assert.equal(r.decision,null);
  evidence.push({mode,name:'missing-second-clock',status:r.status,decision:r.decision});
 });
 test(mode+': malformed string/null/fractional timestamps are explicit missing evidence',()=>{
  for(const value of ['2026-11-02T00:00:18Z',null,1.5]){
   const raw=fixture(mode,'original-drift-2s');raw.observations.samples[1].windowEndMs=value;
   const r=run(raw);assert.equal(r.status,'NOT_CONFIGURED');assert.equal(r.decision,null);
  }
  evidence.push({mode,name:'invalid-clock-values',status:'NOT_CONFIGURED',valuesTested:3});
 });
 test(mode+': unexecuted second query needs no invented observation',()=>{
  const raw=fixture(mode,'sample-0-upper-exact');assert.equal(raw.timing.observations.length,1);assert.equal(raw.timing.wait,null);
  delete raw.observations.samples[1].windowEndMs;
  const r=run(raw);assert.equal(r.decision,'PASS');assert.equal(r.liveChecks.length,1);
  evidence.push({mode,name:'unexecuted-second-sample',status:r.status,decision:r.decision});
 });
 test(mode+': operational query timeout remains FAIL even without a successful clock fact',()=>{
  const raw=fixture(mode,'first-log-timeout-no-retry');delete raw.observations.samples[0].windowEndMs;
  const r=run(raw);assert.equal(r.decision,'FAIL');assert.equal(r.status,'FAIL');
  evidence.push({mode,name:'timeout-no-successful-clock',status:r.status,decision:r.decision});
 });
 test(mode+': sample clocks remain independent of legacy raw.now; facts unchanged',()=>{
  const raw=fixture(mode,'original-drift-2s');raw.now+=3000;
  const before=JSON.stringify(raw),r=run(raw);assert.equal(r.decision,'FAIL');assert.equal(JSON.stringify(raw),before);
  assert.equal(r.runtimeAssessment.first.end,new Date(raw.observations.samples[0].windowEndMs).toISOString());
  assert.equal(r.runtimeAssessment.second.end,new Date(raw.observations.samples[1].windowEndMs).toISOString());
  evidence.push({mode,name:'no-raw-now-derived-sample-clock',decision:r.decision});
 });
}
test.after(()=>fs.writeFileSync(root+'timing-evidence-guards.json',JSON.stringify({classification:'SYNTHETIC_CONTRACT_GUARDS_NOT_PRODUCTION_EXECUTIONS',evidence},null,2)+'\n'));
