"""Run only in a sandboxed disposable copy; never on the production Linux node."""
import ast,contextlib,copy,io,json,os,pathlib,platform,resource,shutil,statistics,subprocess,sys,tempfile,time,unittest
import sampler,contract,runner
HERE=pathlib.Path(__file__).resolve().parent
METRICS=[]
def fixture(root):
 root.mkdir();(root/'pressure').mkdir();(root/'123').mkdir()
 (root/'loadavg').write_text('1.0 1.1 1.2 2/200 123\n')
 (root/'stat').write_text('cpu 10 0 5 100 0 0 0 0 0 0\n'+''.join('cpu%d 1 0 1 10\n'%i for i in range(6))+'procs_running 2\nprocs_blocked 0\n')
 for n in ['cpu','memory','io']:(root/'pressure'/n).write_text('some avg10=1.00 avg60=1.00 avg300=1.00 total=100\nfull avg10=0.00 avg60=0.00 avg300=0.00 total=0\n')
 (root/'meminfo').write_text('MemTotal: 2048000 kB\nMemAvailable: 1024000 kB\nSwapTotal: 2048 kB\nSwapFree: 2048 kB\n')
 a=['S']+['0']*49;a[11]='10';a[12]='2';a[19]='456';a[21]='100'
 (root/'123/stat').write_text('123 (SYNTHETIC_PRIVATE_COMM) '+' '.join(a)+'\n')
 (root/'123/cgroup').write_text('0::/private-token-SYNTHETIC_SECRET/kubepods-pod32543aa9_4b6f_418f_be1b_3795796f37b6.slice/a\n')
 (root/'123/environ').write_text('PASSWORD=SYNTHETIC_SECRET');(root/'123/cmdline').write_text('SYNTHETIC_SECRET')
 return root

def command(role,root=None):
 c=[sys.executable,'-B',str(HERE/'sampler.py'),'--role',role,'--pids','self'if role=='host'else'123','--source-id','offline-'+role]
 if root:c+=['--offline-fixture',str(root)]
 return c

def run_cli(role,root=None):
 cmds={'host':command(role,root),'guest':command(role,root)};r=runner.run_local_pair(cmds)
 if r['status']=='PASS':
  guest=r['workers']['guest'];record=guest['record'];r['clockAlignment']=contract.clock_alignment(guest['hostSent'],record['started'],record['completed'],guest['hostReceived']);r['guestWindowOnHost']=contract.guest_window_on_host(record['started'],record['completed'],r['clockAlignment'])
 METRICS.append({'case':'cli-'+role,'result':r});return r

class Tests(unittest.TestCase):
 def setUp(self):self.t=tempfile.TemporaryDirectory(dir=HERE);self.root=fixture(pathlib.Path(self.t.name)/'proc')
 def tearDown(self):self.t.cleanup()
 def guest(self):return sampler.LinuxProc(str(self.root))
 def err(self,fn,code):
  with self.assertRaises(sampler.SampleError)as e:fn()
  self.assertEqual(e.exception.code,code)
 def test_single_guest_fixture_real_execution(self):
  r=run_cli('guest',self.root);self.assertEqual(r['status'],'PASS');self.assertTrue(r['cleanupVerified']);self.assertEqual(r['workers']['guest']['record']['classification'],'SYNTHETIC_PROC_FIXTURE_REAL_EXECUTION')
 def test_multi_bounded_fixture_performance(self):
  for _ in range(5):self.assertEqual(run_cli('guest',self.root)['status'],'PASS')
 def test_native_host_actual_performance(self):
  if sys.platform!='darwin':self.skipTest('Darwin native test unavailable')
  for _ in range(3):
   r=run_cli('host');self.assertEqual(r['status'],'PASS');self.assertEqual(r['workers']['host']['record']['classification'],'NATIVE_READ_ONLY_DARWIN')
 def test_native_linux_proc(self):
  if sys.platform!='linux':self.skipTest('Non-production native Linux environment not available; fixture is not Linux native')
  self.assertGreater(sampler.LinuxProc().system()['cpuCount'],0)
 def test_real_clock_only_handshake(self):
  c=command('guest',self.root)+['--clock-only'];r=runner.run_local_pair({'host':c,'guest':c});METRICS.append({'case':self._testMethodName,'result':r})
  self.assertEqual(r['status'],'PASS');g=r['workers']['guest'];a=contract.clock_alignment(g['hostSent'],g['record']['started'],g['record']['completed'],g['hostReceived']);self.assertLess(a['uncertaintySeconds'],.5);self.assertEqual(g['record']['metricReads'],0)
 def test_serialize_nan_refused(self):
  with self.assertRaises(ValueError):sampler.encode({'x':float('nan')})
 def test_host_headroom_stop_unit(self):
  self.assertEqual(sampler.pressure_stops({'hostLoadavg':[100,1,1],'cpuCount':10,'freeBytes':0,'inactiveBytes':0}),['HOST_LOAD_GE_2_PER_CPU','HOST_MEMORY_HEADROOM'])
 def test_worker_error_json_exit_zero_not_pass(self):
  r=self.helper_pair('import json;print(json.dumps(dict(status="ERROR")))',.5);self.assertEqual(r['status'],'FAIL');self.assertTrue(r['cleanupVerified'])
 def test_missing_proc(self):
  (self.root/'pressure/cpu').unlink();self.err(self.guest().system,'METRIC_MISSING')
 def test_parse_failure(self):
  (self.root/'loadavg').write_text('not metrics');self.err(self.guest().system,'METRIC_PARSE_ERROR')
 def test_nonfinite_metric(self):
  (self.root/'loadavg').write_text('nan 1 1 1/2 3');self.err(self.guest().system,'METRIC_PARSE_ERROR')
 def test_pid_disappearance(self):
  (self.root/'123/stat').unlink();self.err(lambda:self.guest().process(123),'PID_DISAPPEARED')
 def test_permission_denial_real_filesystem(self):
  if os.getuid()==0:self.skipTest('Cannot prove non-root permission denial as root')
  p=self.root/'meminfo';p.chmod(0)
  try:self.err(self.guest().system,'PERMISSION_DENIED')
  finally:p.chmod(0o600)
 def test_symlink_file_rejected(self):
  p=self.root/'meminfo';p.unlink();p.symlink_to(self.root/'loadavg');self.err(self.guest().system,'READ_ERROR')
 def test_symlink_directory_rejected(self):
  old=self.root/'123';old.rename(self.root/'original');old.symlink_to(self.root/'original',target_is_directory=True)
  self.err(lambda:self.guest().process(123),'READ_ERROR')
 def test_fifo_no_block(self):
  p=self.root/'meminfo';p.unlink();os.mkfifo(p);self.err(self.guest().system,'NON_REGULAR_METRIC')
 def test_file_size_limit(self):
  (self.root/'meminfo').write_text('x'*(sampler.FILE_CAP+1));self.err(self.guest().system,'METRIC_SIZE_LIMIT')
 def test_pid_count_limit(self):self.err(lambda:sampler.pid_list(','.join(str(i)for i in range(1,10))),'PID_LIMIT_OR_FORMAT')
 def test_pid_arg_injection(self):self.err(lambda:sampler.pid_list('1;id'),'PID_LIMIT_OR_FORMAT')
 def test_no_discovery_or_external_commands(self):
  s=ast.parse((HERE/'sampler.py').read_text());imports=[n.names[0].name for n in ast.walk(s)if isinstance(n,ast.Import)]
  self.assertNotIn('subprocess',imports);self.assertNotIn('socket',imports)
  calls=[n.func.attr for n in ast.walk(s)if isinstance(n,ast.Call)and isinstance(n.func,ast.Attribute)]
  for name in ['listdir','scandir','walk','system','popen','fork','execv','kill','killpg']:
   if name=='system':continue # backend.system is a bounded read, not os.system
   self.assertNotIn(name,calls)
 def test_raw_privacy_redaction(self):
  x,_=sampler.collect(self.guest(),[123],.001);b=sampler.encode(x)
  self.assertNotIn(b'SYNTHETIC_SECRET',b);self.assertNotIn(b'SYNTHETIC_PRIVATE_COMM',b);self.assertNotIn(b'private-token',b)
 def test_pressure_stops_before_pid_read(self):
  (self.root/'loadavg').write_text('98 77 20 68/3000 123');g=self.guest()
  g.process=lambda p:(_ for _ in()).throw(AssertionError('must not read PID'))
  facts,code=sampler.collect(g,[123],.001);self.assertEqual(code,30);self.assertEqual(facts['processReads'],0)
 def test_cpu_psi_stop(self):
  (self.root/'pressure/cpu').write_text('some avg10=96.00 avg60=96.00 avg300=96.00 total=100\n')
  self.assertIn('CPU_SOME_AVG10_GE_70',sampler.pressure_stops(self.guest().system()))
 def test_pid_reuse(self):
  g=self.guest();orig=g.process;count=0
  def read(p):
   nonlocal count
   r=orig(p);count+=1;r['identity']+=count;return r
  g.process=read;self.err(lambda:sampler.collect(g,[123],.001),'PID_REUSED')
 def test_output_encode_limit(self):self.err(lambda:sampler.encode({'x':'a'*32768}),'OUTPUT_LIMIT')
 def helper_pair(self,body,timeout=.2,cap=32768):
  c=[sys.executable,'-B','-c',body];r=runner.run_local_pair({'host':c,'guest':c},timeout,cap);METRICS.append({'case':self._testMethodName,'result':r});return r
 def test_transport_timeout_contract_without_network(self):
  r=self.helper_pair('import time;time.sleep(4)');self.assertEqual(r['failure'],'WORKER_TIMEOUT');self.assertTrue(r['cleanupVerified'])
 def test_unreachable_guest_contract_without_network(self):
  r=self.helper_pair('raise SystemExit(255)');self.assertEqual(r['status'],'FAIL');self.assertTrue(r['cleanupVerified'])
 def test_host_failure_cancels_peer(self):
  r=runner.run_local_pair({'host':[sys.executable,'-B','-c','raise SystemExit(7)'],'guest':[sys.executable,'-B','-c','import time;time.sleep(4)']},.3);METRICS.append({'case':self._testMethodName,'result':r});self.assertEqual(r['status'],'FAIL');self.assertTrue(r['cleanupVerified'])
 def test_term_ignored_escalates_exact_owned_pids(self):
  r=self.helper_pair('import signal,time;signal.signal(signal.SIGTERM,signal.SIG_IGN);time.sleep(4)',.3);self.assertEqual(r['status'],'FAIL');self.assertTrue(all(w['exit']==-9 for w in r['workers'].values()));self.assertTrue(r['cleanupVerified'])
 def test_stream_output_cap(self):
  r=self.helper_pair('print("x"*40000)',.5,1024);self.assertEqual(r['failure'],'OUTPUT_LIMIT');self.assertTrue(r['cleanupVerified']);self.assertTrue(all(w['stdoutBytes']<=1024 for w in r['workers'].values()))
 def test_stderr_privacy(self):
  r=self.helper_pair('import sys;sys.stderr.write("SYNTHETIC_SECRET");raise SystemExit(1)');self.assertNotIn('SYNTHETIC_SECRET',json.dumps(r))
 def test_cli_wall_timeout(self):
  code='import sampler,time;sampler.LinuxProc.system=lambda self:time.sleep(4);raise SystemExit(sampler.cli())'
  c=[sys.executable,'-B','-c',code,'--role','guest','--offline-fixture',str(self.root)]
  r=runner.run_local_pair({'host':c,'guest':c},3);METRICS.append({'case':self._testMethodName,'result':r});self.assertEqual(r['status'],'FAIL');self.assertTrue(r['cleanupVerified']);self.assertTrue(any(w.get('record',{}).get('error')=='TASK_TIMEOUT'for w in r['workers'].values()))
 def test_no_online_entry(self):
  with self.assertRaises(ValueError):runner.run_local_pair({'host':['ssh','prod'],'guest':['ssh','prod']})
 def test_strict_ssh_plan_no_execution(self):
  argv=contract.ssh_argv('example.invalid','tester',[123],'guest')
  self.assertIn('StrictHostKeyChecking=yes',argv);self.assertIn('ConnectionAttempts=1',argv);self.assertNotIn('sudo',' '.join(argv));self.assertIn('ControlPersist=no',argv)
  with self.assertRaises(contract.ContractError):contract.ssh_argv('x;id','tester',[],'guest')
 def test_session_budget(self):
  s=contract.Session({'samples':3,'intervalSeconds':120,'durationSeconds':300},0)
  for i in range(3):s.finish(i*120,100,True)
  with self.assertRaises(contract.ContractError):s.ready(360)
 def test_interval_enforced(self):
  s=contract.Session({'samples':3,'intervalSeconds':120,'durationSeconds':300},0);s.finish(0,10,True)
  with self.assertRaises(contract.ContractError):s.ready(1)
 def test_fail_closed_no_retry(self):
  s=contract.Session({'samples':1,'intervalSeconds':120,'durationSeconds':20},0)
  with self.assertRaises(contract.ContractError):s.finish(0,10,False)
  with self.assertRaises(contract.ContractError):s.ready(1)
 def test_total_output_bound(self):
  s=contract.Session({'samples':1,'intervalSeconds':120,'durationSeconds':20},0)
  with self.assertRaises(contract.ContractError):s.finish(0,contract.BUDGET['totalOutputBytes']+1,True)
 def test_plan_limits(self):
  for p in [{'samples':7,'intervalSeconds':120,'durationSeconds':620},{'samples':2,'intervalSeconds':1,'durationSeconds':620},{'samples':2,'intervalSeconds':120,'durationSeconds':1800}]:
   with self.assertRaises(contract.ContractError):contract.plan_check(p)
 def clocks(self,offset=5):
  def s(u,m):return {'utcNs':round(u*1e9),'monotonicNs':round(m*1e9)}
  return s(100,1000),s(100.05+offset,2000),s(100.25+offset,2000.2),s(100.3,1000.3)
 def test_clock_offset_noncomparable_monotonic(self):
  a=contract.clock_alignment(*self.clocks());self.assertAlmostEqual(a['offsetMidpointSeconds'],5);self.assertAlmostEqual(a['uncertaintySeconds'],.05);self.assertFalse(a['causalProof'])
 def test_clock_step(self):
  x=list(self.clocks());x[3]['utcNs']+=1000000000
  with self.assertRaises(contract.ContractError):contract.clock_alignment(*x)
 def test_clock_uncertainty(self):
  x=list(self.clocks());x[3]['utcNs']+=2000000000;x[3]['monotonicNs']+=2000000000
  with self.assertRaises(contract.ContractError):contract.clock_alignment(*x)
 def test_clock_window_join(self):
  x=self.clocks();a=contract.clock_alignment(*x);w=contract.guest_window_on_host(x[1],x[2],a)
  self.assertLessEqual(w['earliestStartUtcNs'],100100000000);self.assertGreaterEqual(w['latestEndUtcNs'],100200000000)

class RecordedResult(unittest.TextTestResult):
 def startTest(self,test):self.b=time.monotonic();self.c=time.process_time();super().startTest(test)
 def stopTest(self,test):CASES.append({'name':test.id(),'wallSeconds':time.monotonic()-self.b,'harnessCpuSeconds':time.process_time()-self.c});super().stopTest(test)
CASES=[]
if __name__=='__main__':
 suite=unittest.defaultTestLoader.loadTestsFromTestCase(Tests);start=time.monotonic();result=unittest.TextTestRunner(verbosity=2,resultclass=RecordedResult).run(suite)
 pathlib.Path('test-results.json').write_text(json.dumps({'classification':'OFFLINE_SANDBOX_REAL_EXECUTION_WITH_SYNTHETIC_LINUX_PROC_NOT_PRODUCTION','environment':{'system':platform.system(),'release':platform.release(),'machine':platform.machine(),'cpuCount':os.cpu_count(),'uid':os.getuid(),'isRoot':os.getuid()==0,'python':platform.python_version(),'sandbox':'deny network; only disposable tree writable','sharedHostCaution':'macOS also hosts devops VM; no workload stress, native reads only, two bounded workers maximum'},'tests':result.testsRun,'failures':len(result.failures),'errors':len(result.errors),'skipped':[{'test':str(t),'reason':r}for t,r in result.skipped],'wallSeconds':time.monotonic()-start,'cases':CASES,'metrics':METRICS},indent=2)+'\n')
 raise SystemExit(0 if result.wasSuccessful()else 1)
