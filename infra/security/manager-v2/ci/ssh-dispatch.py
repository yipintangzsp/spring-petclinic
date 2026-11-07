"""Fixed CI transport; token stays server-side. Legacy scanner/proof entry retained."""
import os,sys,json,socket,http.client,time,signal
if os.environ.get('SSH_ORIGINAL_COMMAND')!='manager-ci-v1':os.execv('/usr/bin/python3',['/usr/bin/python3','-I','/usr/local/libexec/security-gitleaks-ci-proof.py'])
signal.alarm(45)
try:
 if os.getuid()!=24021:raise RuntimeError('CI_IDENTITY_REJECTED')
 cap=json.load(open('/var/lib/security-gitleaks/manager-ci-capability.json'))
 class UnixHTTP(http.client.HTTPConnection):
  def connect(self):self.sock=socket.socket(socket.AF_UNIX);self.sock.settimeout(8);self.sock.connect('/var/lib/security-gitleaks/ci-channel/manager.sock')
 body=sys.stdin.buffer.read(2049)
 if len(body)>2048:raise RuntimeError('CI_INPUT_LIMIT')
 json.loads(body)
 def request(method,path,data=None):
  c=UnixHTTP('localhost',timeout=8);c.request(method,path,body=data,headers={'Authorization':'Bearer '+cap['token'],'Content-Type':'application/json'});r=c.getresponse();b=r.read(16385);c.close()
  if len(b)>16384:raise RuntimeError('CI_RESULT_LIMIT')
  return r.status,json.loads(b)
 status,r=request('POST','/v1/runs',body)
 if status!=202:print(json.dumps(r));sys.exit(1)
 run=r['runId']
 for _ in range(35):
  status,r=request('GET','/v1/runs/'+run)
  if status!=200:raise RuntimeError('CI_QUERY_REJECTED')
  if r['state']not in ['QUEUED','RUNNING']:break
  time.sleep(.5)
 print(json.dumps(r));sys.exit(0 if r['state']=='COMPLETED'and r['policyDecision']=='PASS'else 1)
except BaseException as e:
 if isinstance(e,SystemExit):raise
 print(json.dumps({'error':str(e)if isinstance(e,RuntimeError)else'CI_TRANSPORT_ERROR'}));sys.exit(1)
