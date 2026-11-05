"""Run the original 43 cases against the corrected entrypoint + CPU-unit proof."""
import sampler_mach_time as current
import test_sampler as legacy
import unittest,sys,pathlib,json,time,resource,os
original_command=legacy.command

def corrected_command(role,root=None):
 c=original_command(role,root);c[2]=str(legacy.HERE/'sampler_mach_time.py');return c
legacy.command=corrected_command
class Units(unittest.TestCase):
 def test_mach_unit_formula(self):
  self.assertEqual(current.mach_seconds(24000000,1000,24),1)
  with self.assertRaises(current.original.SampleError):current.mach_seconds(1,1,0)
 def test_native_self_cpu_unit_against_getrusage(self):
  if sys.platform!='darwin':self.skipTest('Darwin unit sanity requires native macOS')
  backend=current.DarwinMachTime();a=resource.getrusage(resource.RUSAGE_SELF);r=backend.process(os.getpid());b=resource.getrusage(resource.RUSAGE_SELF)
  low=a.ru_utime+a.ru_stime;high=b.ru_utime+b.ru_stime
  observation={'nativeConvertedCpuSeconds':r['cpuSeconds'],'getrusageBeforeSeconds':low,'getrusageAfterSeconds':high,'timebase':r['timebase'],'toleranceSeconds':.01,'classification':'REAL_NATIVE_DARWIN_SELF_ONLY_NO_CPU_STRESS','rejectedPriorUnconvertedSeconds':r['cpuSeconds']*r['timebase']['denom']/r['timebase']['numer']}
  pathlib.Path('native-unit-sanity.json').write_text(json.dumps(observation,indent=2)+'\n')
  self.assertGreaterEqual(r['cpuSeconds'],low-.01);self.assertLessEqual(r['cpuSeconds'],high+.01)
if __name__=='__main__':
 suite=unittest.TestSuite([unittest.defaultTestLoader.loadTestsFromTestCase(legacy.Tests),unittest.defaultTestLoader.loadTestsFromTestCase(Units)])
 start=time.monotonic();result=unittest.TextTestRunner(verbosity=2,resultclass=legacy.RecordedResult).run(suite)
 pathlib.Path('test-results.json').write_text(json.dumps({'classification':'CORRECTED_ENTRYPOINT_OFFLINE_REAL_EXECUTION_WITH_SYNTHETIC_LINUX_PROC','environment':{'system':sys.platform,'machine':os.uname().machine,'uid':os.getuid(),'productionGuestAccess':False,'network':'OS_SANDBOX_DENIED'},'tests':result.testsRun,'failures':len(result.failures),'errors':len(result.errors),'skipped':[{'test':str(t),'reason':r}for t,r in result.skipped],'wallSeconds':time.monotonic()-start,'cases':legacy.CASES,'metrics':legacy.METRICS},indent=2)+'\n')
 raise SystemExit(0 if result.wasSuccessful()else 1)
