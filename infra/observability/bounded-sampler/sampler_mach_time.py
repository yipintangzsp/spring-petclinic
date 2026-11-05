#!/usr/bin/env python3
"""Current entrypoint: correct Darwin proc_pid_rusage Mach ticks to seconds.
The first sealed candidate is preserved; import adds no network or child process.
"""
import ctypes
import sampler as original

def mach_seconds(ticks,numer,denom):
 if not isinstance(numer,int)or not isinstance(denom,int)or numer<=0 or denom<=0 or ticks<0:raise original.SampleError('MACH_TIMEBASE_INVALID')
 return ticks*numer/denom/1e9
class TimebaseInfo(ctypes.Structure):_fields_=[('numer',ctypes.c_uint32),('denom',ctypes.c_uint32)]
class DarwinMachTime(original.DarwinNative):
 def __init__(self):
  super().__init__();info=TimebaseInfo();self.lib.mach_timebase_info.argtypes=[ctypes.POINTER(TimebaseInfo)]
  if self.lib.mach_timebase_info(ctypes.byref(info))!=0 or not info.numer or not info.denom:raise original.SampleError('MACH_TIMEBASE_UNAVAILABLE')
  self.timebase={'numer':info.numer,'denom':info.denom}
 def process(self,pid):
  r=super().process(pid)
  # Base's division by 1e9 was insufficient on arm64; preserve old evidence.
  r['cpuSeconds']=r['cpuSeconds']*self.timebase['numer']/self.timebase['denom']
  r['cpuTimeSource']='proc_pid_rusage Mach ticks converted with mach_timebase_info'
  r['timebase']=self.timebase
  return r
original.DarwinNative=DarwinMachTime
if __name__=='__main__':raise SystemExit(original.cli())
