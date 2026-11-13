from pathlib import Path
import subprocess,json,os,shlex
O=Path(__file__).resolve().parent;local=json.loads((O/'local-candidate-inventory.json').read_text());out={'classification':'READ_ONLY_EXISTING_CONTEXTS_AND_SAMPLER_ONLY_NO_REFRESH','contexts':[]}
for line in local['dockerContexts'].get('stdout','').splitlines():
 x=json.loads(line);endpoint=x.get('DockerEndpoint','');path=endpoint[7:] if endpoint.startswith('unix://') else None
 row={'context':x['Name'],'endpoint':endpoint,'socketExists':bool(path and Path(path).exists())}
 if row['socketExists']:
  fmt='{"version":{{json .ServerVersion}},"architecture":{{json .Architecture}},"OS":{{json .OSType}},"storageDriver":{{json .Driver}},"root":{{json .DockerRootDir}},"runningContainers":{{.ContainersRunning}}}'
  p=subprocess.run(['docker','--context',x['Name'],'info','--format',fmt],capture_output=True,text=True,timeout=12);row['readExit']=p.returncode
  if p.returncode==0:row['engine']=json.loads(p.stdout)
 out['contexts'].append(row)
base=['docker','--context','colima-security-test']
p=subprocess.run(base+['inspect','security-test-sops-control-plane','--format','{"id":{{json .Id}},"image":{{json .Config.Image}},"mounts":{{json .Mounts}},"storageDriver":{{json .GraphDriver.Name}},"privileged":{{json .HostConfig.Privileged}}}'],capture_output=True,text=True,timeout=12);out['existingKindInspectExit']=p.returncode
if not p.returncode:out['existingKind']=json.loads(p.stdout)
p=subprocess.run(base+['exec','security-test-sops-control-plane','sh','-c',"uname -m; df -B1 -P / /tmp /var/lib/containerd; stat -f -c '%n|%T|%S|%b|%a' / /tmp /var/lib/containerd"],capture_output=True,text=True,timeout=12);out['existingKindRead']={'exit':p.returncode,'metadata':p.stdout if not p.returncode else None}
code="""import time,os,json,shutil
path='/mnt/lima-colima-security-test';values=[];last=time.monotonic_ns();cpu=time.process_time_ns();start=time.monotonic_ns()
for i in range(100):
 before=time.monotonic_ns();s=os.statvfs(path);values.append({'t':before,'available':s.f_bavail*s.f_frsize});time.sleep(.01)
end=time.monotonic_ns();cpu=time.process_time_ns()-cpu;gaps=[(b['t']-a['t'])/1e6 for a,b in zip(values,values[1:])]
print(json.dumps({'classification':'READ_ONLY_SAMPLER_CALIBRATION_ONLY','samples':len(values),'clockResolutionSeconds':time.get_clock_info('monotonic').resolution,'wallMs':(end-start)/1e6,'cpuMs':cpu/1e6,'cpuFraction':cpu/(end-start),'minGapMs':min(gaps),'maxGapMs':max(gaps),'meanGapMs':sum(gaps)/len(gaps),'statvfsPath':path,'minAvailableBytes':min(x['available'] for x in values),'allocationTraceAvailableTools':{n:shutil.which(n) is not None for n in ['bpftrace','trace-cmd','perf']},'zeroDBRefreshes':True,'fullPeakMeasurementProven':False}))"""
p=subprocess.run(['colima','ssh','--profile','security-test','--','python3','-c',code],capture_output=True,text=True,timeout=15);out['samplerCalibration']={'exit':p.returncode,'result':json.loads(p.stdout) if not p.returncode else None}
(O/'validation-existing-detail.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps(out))
