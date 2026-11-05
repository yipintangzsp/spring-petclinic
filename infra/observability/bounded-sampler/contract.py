"""Offline-tested timing/budget protocol. No SSH calls, no production entry point."""
import math,re
class ContractError(Exception):pass
BUDGET={'maxSamples':6,'minimumIntervalSeconds':120,'collectorWallSeconds':2.5,'transportWallSeconds':4,'sessionWallSeconds':620,'workerCpuSeconds':.25,'workerRssBytes':64*1024*1024,'perStreamBytes':32768,'totalOutputBytes':512*1024,'maxWorkerChildren':2,'maxPidsPerWorker':8,'maxClockUncertaintySeconds':.5,'terminateGraceSeconds':.1,'reapDeadlineSeconds':.5}
def plan_check(plan):
 if set(plan)!={'samples','intervalSeconds','durationSeconds'}:raise ContractError('UNKNOWN_PLAN_FIELD')
 if type(plan['samples'])is not int or not 1<=plan['samples']<=BUDGET['maxSamples']:raise ContractError('SAMPLE_LIMIT')
 if not math.isfinite(plan['intervalSeconds'])or plan['intervalSeconds']<BUDGET['minimumIntervalSeconds']:raise ContractError('CADENCE_LIMIT')
 if not math.isfinite(plan['durationSeconds'])or not 0<plan['durationSeconds']<=BUDGET['sessionWallSeconds']:raise ContractError('SESSION_LIMIT')
 if (plan['samples']-1)*plan['intervalSeconds']+2*BUDGET['transportWallSeconds']>plan['durationSeconds']:raise ContractError('INSUFFICIENT_DEADLINE')
 return dict(plan)
class Session:
 """No scheduler/loop: caller must request each due sample; any failure closes it."""
 def __init__(self,plan,start_mono):self.plan=plan_check(plan);self.start=start_mono;self.last=None;self.count=0;self.bytes=0;self.closed=False
 def ready(self,mono):
  if self.closed:raise ContractError('SESSION_CLOSED')
  if mono<self.start or mono-self.start>=self.plan['durationSeconds']or self.count>=self.plan['samples']:self.closed=True;raise ContractError('SESSION_COMPLETE_OR_DEADLINE')
  if self.last is not None and mono-self.last<self.plan['intervalSeconds']:raise ContractError('TOO_SOON')
  return True
 def finish(self,mono,output_bytes,ok):
  self.ready(mono);self.count+=1;self.last=mono;self.bytes+=output_bytes
  if not ok or output_bytes<0 or self.bytes>BUDGET['totalOutputBytes']:self.closed=True
  if self.closed:raise ContractError('FAIL_CLOSED')

def clock_alignment(host_send,guest_received,guest_sent,host_received):
 """Offset = Guest UTC - Host UTC; monotonic differences only within each host.
 Nonnegative delays bound offset; no symmetric-network assumption. Unseen clock
 steps/drift remain a limitation even after local step checks.
 """
 def duration(a,b):
  m=(b['monotonicNs']-a['monotonicNs'])/1e9;u=(b['utcNs']-a['utcNs'])/1e9
  if m<0 or abs(m-u)>.02:raise ContractError('CLOCK_STEP_OR_ORDER')
  return m
 hd=duration(host_send,host_received);gd=duration(guest_received,guest_sent)
 lower=(guest_sent['utcNs']-host_received['utcNs'])/1e9;upper=(guest_received['utcNs']-host_send['utcNs'])/1e9
 if lower>upper or gd>hd+.02:raise ContractError('INVALID_CLOCK_BOUNDS')
 uncertainty=(upper-lower)/2
 if uncertainty>BUDGET['maxClockUncertaintySeconds']:raise ContractError('CLOCK_UNCERTAINTY_LIMIT')
 return {'offsetDefinition':'GUEST_UTC_MINUS_HOST_UTC','offsetLowerSeconds':lower,'offsetUpperSeconds':upper,'offsetMidpointSeconds':(lower+upper)/2,'uncertaintySeconds':uncertainty,'hostExchangeSeconds':hd,'guestExecutionSeconds':gd,'syncStatus':'UNKNOWN','assumption':'No unobserved realtime clock step during exchange; not NTP/PTP proof; transport/startup included','causalProof':False}
def guest_window_on_host(guest_start,guest_end,alignment):
 return {'earliestStartUtcNs':guest_start['utcNs']-round(alignment['offsetUpperSeconds']*1e9),'latestEndUtcNs':guest_end['utcNs']-round(alignment['offsetLowerSeconds']*1e9),'interpretation':'Uncertainty-expanded candidate window, not proof of causal ordering'}
def ssh_argv(host,user,pids,source_id):
 """Future reviewed transport argv only; this module never executes it.
 Existing known_hosts required. No LocalCommand, proxy, forwarding or persistence.
 """
 if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9.-]{0,252}',host)or not re.fullmatch(r'[a-z_][a-z0-9_-]{0,31}',user)or not re.fullmatch(r'[A-Za-z0-9_-]{1,40}',source_id):raise ContractError('TRANSPORT_ID_INVALID')
 if len(pids)>8 or len(set(pids))!=len(pids)or any(type(p)is not int or not 0<p<=2147483647 for p in pids):raise ContractError('TRANSPORT_PID_INVALID')
 remote='python3 -B - --role guest --source-id '+source_id
 if pids:remote+=' --pids '+','.join(map(str,pids))
 return ['ssh','-F','/dev/null','-T','-o','BatchMode=yes','-o','StrictHostKeyChecking=yes','-o','UpdateHostKeys=no','-o','ConnectTimeout=2','-o','ConnectionAttempts=1','-o','ServerAliveInterval=1','-o','ServerAliveCountMax=1','-o','ControlMaster=no','-o','ControlPath=none','-o','ControlPersist=no','-o','ProxyCommand=none','-o','ProxyJump=none','-o','PermitLocalCommand=no','-o','ClearAllForwardings=yes','-o','RequestTTY=no',user+'@'+host,remote]
