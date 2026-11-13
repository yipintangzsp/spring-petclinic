"""Two bounded events through the pre-existing security Loki endpoint; ephemeral local SSH forward only."""
import json,pathlib,subprocess,time,urllib.request,urllib.parse,socket,datetime,os,signal
HERE=pathlib.Path(__file__).resolve().parent;REPO=HERE.parents[2];WEB='http://security.devops.local:17862';LOKI='http://127.0.0.1:32189'
op=urllib.request.build_opener(urllib.request.ProxyHandler({}))
def save(n,x):
 with (HERE/n).open('x')as f:json.dump(x,f,indent=2);f.write('\n')
def get(url):
 with op.open(url,timeout=8)as r:return json.load(r)
def emit(run,phase):
 p=subprocess.run(['node',str(HERE/'emit.mjs'),run['runId'],run['pluginId'],phase],cwd=REPO,capture_output=True,text=True,timeout=15)
 if p.returncode:raise RuntimeError('Existing Consumer delivery failed: '+p.stderr[-900:])
 print(p.stdout.strip(),flush=True);return json.loads(p.stdout)
def query(event,phase):
 at=int(datetime.datetime.fromisoformat(event['timestamp'].replace('Z','+00:00')).timestamp()*1000000000)
 q='{service_name="security-manager-v2",environment="validation",schema_version="1",job="devsecops-security-v2"} | json | runId='+json.dumps(event['runId'])+' | resultDigest='+json.dumps(event['resultDigest'])
 params=urllib.parse.urlencode({'query':q,'start':str(at-1000000000),'end':str(at+1000000000),'limit':'10','direction':'forward'})
 results=[]
 for _ in range(3):
  response=get(LOKI+'/loki/api/v1/query_range?'+params);assert response['status']=='success'
  results=[{'timestampNs':v[0],'stream':s['stream'],'event':json.loads(v[1])}for s in response['data']['result']for v in s['values']]
  if results:break
  time.sleep(1)
 assert results,'Push ACK but no matching query result'
 for r in results:
  e=r['event'];assert e['runId']==event['runId'] and e['pluginId']==event['plugin']and e['policyDecision']==event['policy']and e['resultDigest']==event['resultDigest']
  assert e['sourceClassification']==event['sourceClassification']and e['findingCount']==0 and e['findingCountKnown']is True
  assert not any('run' in k.lower()or'digest'in k.lower()for k in r['stream'])
 receipt={'queriedAt':datetime.datetime.now(datetime.timezone.utc).isoformat(),'query':q,'startNs':str(at-1000000000),'endNs':str(at+1000000000),'results':results,'runId':event['runId'],'resultDigest':event['resultDigest'],'deliveryStatus':'DELIVERED','transport':'strict-host-key SSH local forward to existing 10.43.7.197:3100','sourceClass':event['sourceClassification']}
 save(phase+'-query.json',receipt);print(json.dumps({'queryBack':True,'phase':phase,'runId':event['runId'],'matches':len(results)}),flush=True);return receipt
# No inherited proxy, arbitrary destination, remote executable or credentials.
check=socket.socket();check.bind(('127.0.0.1',32189));check.close()
args=['ssh','-F','/dev/null','-T','-N','-o','BatchMode=yes','-o','ConnectTimeout=6','-o','ConnectionAttempts=1','-o','StrictHostKeyChecking=yes','-o','HostName=192.168.64.11','-o','HostKeyAlias=192.168.1.58','-o','ExitOnForwardFailure=yes','-o','ServerAliveInterval=5','-o','ServerAliveCountMax=2','-L','127.0.0.1:32189:10.43.7.197:3100','zhang@192.168.1.58']
p=subprocess.Popen(args,stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.PIPE,start_new_session=True)
try:
 for _ in range(25):
  assert p.poll()is None,'SSH forward did not start'
  try:
   info=get(LOKI+'/loki/api/v1/status/buildinfo')
   if info.get('version')=='3.7.4':break
  except (urllib.error.URLError,TimeoutError):pass
  time.sleep(.2)
 else:raise RuntimeError('Existing Loki target identity not verified')
 cfg=get(WEB+'/api/config');assert cfg['settings']['enabled']and cfg['settings']['plugins']['gitleaks']['enabled']and cfg['settings']['securityLevel']=='standard'
 old=next(r for r in get(WEB+'/api/runs')['runs']if r['pluginId']=='semgrep'and r['scenarioId']=='clean'and r['evidenceClass']=='REAL'and r['state']=='COMPLETED'and r['policyDecision']=='PASS')
 historical=query(emit(old,'recent'),'recent')
 # Exactly one new tiny controlled scan, through the existing Web API.
 token=get(WEB+'/api/plugins')['csrfToken'];request=urllib.request.Request(WEB+'/api/run',data=json.dumps({'pluginId':'gitleaks','scenarioId':'clean'}).encode(),headers={'Origin':WEB,'Content-Type':'application/json','X-CSRF-Token':token})
 with op.open(request,timeout=8)as response:created=json.load(response)
 for _ in range(65):
  fresh=get(WEB+'/api/runs/'+created['runId'])
  if fresh['state']not in ['RUNNING','QUEUED']:break
  time.sleep(.5)
 save('fresh-web-run.json',fresh)
 assert fresh['state']=='COMPLETED'and fresh['evidenceClass']=='REAL'and fresh['policyDecision']=='PASS'and fresh['evaluationCount']==1,fresh.get('reason')
 current=query(emit(fresh,'fresh'),'fresh')
 save('roundtrip.json',{'recentHistorical':historical,'fresh':current,'earlierOldGitleaksAck':'historical/delivery.json','earlierOldGitleaksQueryStatus':'NOT_VERIFIED','newRealScans':1,'policyEvaluations':1,'lokiPushes':2,'eventsPushed':2,'queryVerified':True,'lokiConfigurationChanged':False,'grafanaImported':False,'grafanaPermission':'NON_ADMIN_IDENTITY_REQUIRED','productionSecurityManager':'NOT_ACTIVE','release':0,'rollout':0})
finally:
 p.terminate()
 try:p.communicate(timeout=4)
 except subprocess.TimeoutExpired:p.kill();p.communicate(timeout=2)
 save('forward-cleanup-resume.json',{'sshPid':p.pid,'terminated':p.poll()is not None,'persistentServiceCreated':False,'sshAuthorizationChanges':0,'boundAddress':'127.0.0.1','released':True})
