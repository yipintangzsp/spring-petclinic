// Mac host admission for a tiny Gitleaks fixture; not a VM or Trivy budget.
import os from 'node:os';
import fs from 'node:fs';
import {execFile} from 'node:child_process';
import {promisify} from 'node:util';
const exec=promisify(execFile);
const blocked=code=>Object.assign(Error(code),{code});
const command=async(bin,args)=>(await exec(bin,args,{timeout:2500,maxBuffer:32768,env:{PATH:'/usr/bin:/bin',LANG:'C'}})).stdout;
export function memoryFacts(text,pressure){
 const page=Number(text.match(/page size of (\d+) bytes/)?.[1]);
 const count=name=>Number(text.match(new RegExp('^'+name+':\\s+(\\d+)','m'))?.[1]);
 const free=count('Pages free'),fileBacked=count('File-backed pages');
 if(!Number.isSafeInteger(page)||page<=0||![free,fileBacked].every(Number.isSafeInteger)||![0,1,2,3,4].includes(pressure))throw blocked('MAC_RESOURCE_STATE_UNKNOWN_BLOCKED');
 return {pageSize:page,freePageBytes:free*page,fileBackedBytes:fileBacked*page,
  reclaimableMemoryBytes:(free+fileBacked)*page,pressureLevel:pressure,
  pressureMeaning:['NORMAL','WARNING','URGENT','CRITICAL','JETSAM'][pressure]};
}
export function decision(b){
 if(![b.cpuBusyPercent,b.reclaimableMemoryBytes,b.freeDiskBytes,b.pressureLevel].every(Number.isFinite)||b.cpuBusyPercent<0||b.cpuBusyPercent>100||b.reclaimableMemoryBytes<0||b.freeDiskBytes<0||![0,1,2,3,4].includes(b.pressureLevel))return 'MAC_RESOURCE_STATE_UNKNOWN_BLOCKED';
 if(b.pressureLevel!==0)return 'MAC_MEMORY_PRESSURE_BLOCKED';
 if(b.reclaimableMemoryBytes<512*1024**2)return 'MAC_AVAILABLE_MEMORY_BLOCKED';
 if(b.freeDiskBytes<512*1024**2)return 'MAC_AVAILABLE_DISK_BLOCKED';
 if(b.cpuBusyPercent>75)return 'MAC_CPU_PRESSURE_BLOCKED';
 return null;
}
const totals=()=>os.cpus().reduce((a,c)=>{a.idle+=c.times.idle;for(const n of Object.values(c.times))a.total+=n;return a;},{idle:0,total:0});
export async function macBudget(directory){
 if(process.platform!=='darwin')throw blocked('MAC_RESOURCE_STATE_UNKNOWN_BLOCKED');
 const start=totals();await new Promise(r=>setTimeout(r,250));const end=totals();
 if(end.total<=start.total)throw blocked('MAC_RESOURCE_STATE_UNKNOWN_BLOCKED');
 const [vm,level,swap]=await Promise.all([command('/usr/bin/vm_stat',[]),command('/usr/sbin/sysctl',['-n','kern.memorystatus_vm_pressure_level']),command('/usr/sbin/sysctl',['vm.swapusage'])]);
 const disk=fs.statfsSync(directory);
 return {at:new Date().toISOString(),scope:'MAC_HOST_GITLEAKS_SMALL_FIXTURE',
  ...memoryFacts(vm,Number(level.trim())),cpuBusyPercent:100*(1-(end.idle-start.idle)/(end.total-start.total)),
  cpuWindowMs:250,load1DiagnosticOnly:os.loadavg()[0],cpuCount:os.cpus().length,
  freeDiskBytes:Number(disk.bavail)*Number(disk.bsize),swapObservation:swap.trim(),
  thresholds:{maxCpuBusyPercent:75,minReclaimableMemoryBytes:512*1024**2,minFreeDiskBytes:512*1024**2,requiredPressureLevel:0},
  memoryDefinition:'free + file-backed pages; pressure must be NORMAL; not total RAM or os.freemem alone',
  definitionSource:'https://github.com/apple-oss-distributions/xnu/blob/main/doc/vm/memorystatus_notify.md'};
}
