import test from 'node:test';import assert from 'node:assert/strict';
import {memoryFacts,decision} from './mac-budget.mjs';
const vm='Mach Virtual Memory Statistics: (page size of 16384 bytes)\nPages free: 4000.\nFile-backed pages: 300000.\n';
const normal={...memoryFacts(vm,0),cpuBusyPercent:68,freeDiskBytes:16*1024**3};
test('Mac reclaimable estimate uses page units and includes file-backed memory',()=>{assert.equal(normal.reclaimableMemoryBytes,304000*16384);assert.equal(decision(normal),null);});
test('kernel urgent 2 is not confused with dispatch flag values',()=>{assert.equal(memoryFacts(vm,2).pressureMeaning,'URGENT');assert.equal(decision({...normal,pressureLevel:2}),'MAC_MEMORY_PRESSURE_BLOCKED');});
test('all elevated or unknown pressures rejected',()=>{for(const p of [1,2,3,4])assert.equal(decision({...normal,pressureLevel:p}),'MAC_MEMORY_PRESSURE_BLOCKED');assert.throws(()=>memoryFacts(vm,5));});
test('original numeric safety floors preserved',()=>{assert.equal(decision({...normal,reclaimableMemoryBytes:512*1024**2-1}),'MAC_AVAILABLE_MEMORY_BLOCKED');assert.equal(decision({...normal,freeDiskBytes:512*1024**2-1}),'MAC_AVAILABLE_DISK_BLOCKED');assert.equal(decision({...normal,cpuBusyPercent:75.01}),'MAC_CPU_PRESSURE_BLOCKED');});
test('missing and impossible telemetry fails closed',()=>{assert.throws(()=>memoryFacts('',0));for(const v of [NaN,-1,101])assert.equal(decision({...normal,cpuBusyPercent:v}),'MAC_RESOURCE_STATE_UNKNOWN_BLOCKED');assert.equal(decision({...normal,pressureLevel:5}),'MAC_RESOURCE_STATE_UNKNOWN_BLOCKED');});
