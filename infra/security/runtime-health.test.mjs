import test from 'node:test';
import assert from 'node:assert/strict';
import {validatePriorExit,validateRuntimeContinuity,driverDiagnostics} from './runtime/health-contract.mjs';
const state=()=>({ready:true,restarts:4,priorExit:{exitCode:0,reason:'Completed'},podUid:'pod',nodeBootId:'boot',containerId:'container',runningSince:'start',image:'digest'});
test('clean VM shutdown history is retained; crash, OOM and unknown exits fail closed',()=>{
 validatePriorExit(state());
 for(const priorExit of [{exitCode:137,reason:'OOMKilled'},{exitCode:1,reason:'Error'},undefined])assert.throws(()=>validatePriorExit({...state(),priorExit}));
 assert.throws(()=>validatePriorExit({...state(),ready:false}));
 for(const restarts of [undefined,-1,NaN])assert.throws(()=>validatePriorExit({...state(),restarts}));
});
test('any new restart, zero-count replacement, new boot or container change fails current build continuity',()=>{
 const baseline=state();validateRuntimeContinuity(state(),baseline);
 for(const current of [{...state(),restarts:5},{...state(),podUid:'replacement',restarts:0},{...state(),nodeBootId:'new-boot'},{...state(),containerId:'new-container'},{...state(),ready:false}])assert.throws(()=>validateRuntimeContinuity(current,baseline));
});
test('operational fatal/driver errors block; ordinary security events and proc race warnings stay visible',()=>{
 assert.equal(driverDiagnostics('Error attaching BPF probe').fatalDriverLines,1);
 assert.equal(driverDiagnostics('FATAL driver stopped').fatalDriverLines,1);
 const log=JSON.stringify({rule:'example',output:'process printed fatal error loading BPF'})+'\n[libs]: Unable to determine path for file descriptor: readlink() failed';
 assert.deepEqual(driverDiagnostics(log),{fatalDriverLines:0,procFdWarnings:1});
});
