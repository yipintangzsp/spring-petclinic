"""Run on the admin Mac: python3 verify.py /absolute/private/evidence-dir. Uses existing shared lease; no real escape or production mutation."""
import os,sys,json,time,secrets,shlex,datetime
from pathlib import Path
os.environ['PETCLINIC_SSH_ADDRESS']='192.168.64.11';sys.path.insert(0,str(Path(__file__).resolve().parents[2]/'analytics'));from controlled import HeavyRun,kube,remote
E=Path(sys.argv[1]).resolve();E.mkdir(parents=True,exist_ok=True,mode=0o700);(E/'source').mkdir(exist_ok=True);batch='runtime-'+time.strftime('%Y%m%d%H%M%S');name=batch;owner='phase4-'+secrets.token_hex(4);uid=None;results=[];events=[]
ns={'apiVersion':'v1','kind':'Namespace','metadata':{'name':'devsecops-test','labels':{'petclinic.devops.local/owner':'platform-runtime-security','pod-security.kubernetes.io/enforce':'restricted'}}}
quota={'apiVersion':'v1','kind':'ResourceQuota','metadata':{'name':'runtime-test-budget','namespace':'devsecops-test'},'spec':{'hard':{'pods':'1','requests.cpu':'100m','requests.memory':'256Mi','limits.cpu':'500m','limits.memory':'512Mi','persistentvolumeclaims':'0'}}}
net={'apiVersion':'networking.k8s.io/v1','kind':'NetworkPolicy','metadata':{'name':'runtime-test-deny','namespace':'devsecops-test'},'spec':{'podSelector':{},'policyTypes':['Ingress','Egress']}}
(E/'source/test-boundary.json').write_text(json.dumps({'apiVersion':'v1','kind':'List','items':[ns,quota,net]},indent=2)+'\n')
pod={'apiVersion':'v1','kind':'Pod','metadata':{'name':name,'namespace':'devsecops-test','labels':{'app':'runtime-security-test','petclinic.devops.local/run':owner}},'spec':{'nodeSelector':{'kubernetes.io/hostname':'devops'},'restartPolicy':'Never','activeDeadlineSeconds':600,'automountServiceAccountToken':False,'securityContext':{'runAsNonRoot':True,'runAsUser':10001,'runAsGroup':10001,'fsGroup':10001,'seccompProfile':{'type':'RuntimeDefault'}},'containers':[{'name':'test','image':'127.0.0.1:30050/petclinic/petclinic@sha256:c8160221d55311268ae8654ffa7289ee9bffefea378dc8a0b43190e090c43ee1','imagePullPolicy':'IfNotPresent','command':['/bin/sleep','590'],'securityContext':{'allowPrivilegeEscalation':False,'readOnlyRootFilesystem':True,'capabilities':{'drop':['ALL']}},'resources':{'requests':{'cpu':'50m','memory':'128Mi'},'limits':{'cpu':'250m','memory':'256Mi'}}}]}}
exec_code="import subprocess,json,sys; a=json.load(sys.stdin);r=subprocess.run(['sudo','-n','kubectl','--request-timeout=10s','-n','devsecops-test','exec',a['pod'],'--',*a['command']],capture_output=True,text=True,timeout=15);print(json.dumps({'exit':r.returncode,'stdout':r.stdout[:2000],'stderr':r.stderr[:2000]}))"
def execute(cmd):return json.loads(remote('python3 -c '+shlex.quote(exec_code),json.dumps({'pod':name,'command':cmd}),timeout=25))
with HeavyRun('falco-runtime-acceptance',1024,E/('tests-'+batch)) as run:
 try:
  prior=kube(['get','ns','devsecops-test','--ignore-not-found','-o','json'])
  if prior:assert prior['metadata'].get('labels',{}).get('petclinic.devops.local/owner')=='platform-runtime-security','Foreign namespace preserved'
  for item in [ns,quota,net]:kube(['apply','-f','-'],item)
  created=kube(['create','-f','-','-o','json'],pod);uid=created['metadata']['uid'];run.compute_stopped=False
  for _ in range(45):
   run.check();p=kube(['-n','devsecops-test','get','pod',name,'-o','json'])
   if all(c.get('ready') for c in p['status'].get('containerStatuses',[])) and p['status'].get('containerStatuses'):break
   time.sleep(2)
  else:raise RuntimeError('Test Pod not ready')
  time.sleep(5)
  actions=[('shell',['/bin/sh','-c','printf runtime-shell'],'Platform Runtime Shell'),('sensitive-read',['/bin/cat','/etc/passwd'],'Platform Runtime Sensitive Read'),('package-manager',['/usr/bin/apt-get','--version'],'Platform Runtime Package Manager'),('network-tool',['/usr/bin/curl','--version'],'Platform Runtime HTTP Utility'),('readonly-write',['/usr/bin/touch','/etc/'+batch],'Platform Runtime Sensitive Write'),('namespace-tool',['/usr/bin/nsenter','--target','2147483647','--mount','--','/bin/true'],'Platform Runtime Namespace Or Mount')]
  for case,cmd,rule in actions:
   run.check();t=time.time();r=execute(cmd)
   results.append({'case':case,'command':cmd,'startedAt':t,'result':r,'expectedRule':rule,'status':'pending','preventedByHardening':case=='readonly-write' and r['exit']!=0 and 'Read-only file system' in r['stderr']});print(case,r['exit'],flush=True);time.sleep(2)
  for _ in range(15):
   raw=remote('sudo -n kubectl -n devsecops-system logs ds/platform-falco --since=10m',timeout=25);events=[]
   for line in raw.splitlines():
    try:a=json.loads(line)
    except ValueError:continue
    if a.get('output_fields',{}).get('k8s.pod.name')==name:events.append(a)
   for r in results:
    proc={'shell':'sh','sensitive-read':'cat','package-manager':'apt-get','network-tool':'curl','readonly-write':'touch','namespace-tool':'nsenter'}[r['case']]
    matched=[e for e in events if e.get('rule')==r['expectedRule'] and e.get('output_fields',{}).get('proc.name')==proc and datetime.datetime.fromisoformat(e['time'].replace('Z','+00:00')).timestamp()>=r['startedAt']-1]
    if matched:r.update({'status':'PASS','event':matched[0]})
   if all(r['status']=='PASS' for r in results):break
   run.check();time.sleep(2)
  (E/'runtime-test-events.json').write_text(json.dumps(events,indent=2));(E/'runtime-tests.json').write_text(json.dumps({'batch':batch,'pod':name,'uid':uid,'namespace':'devsecops-test','results':results},indent=2))
  assert all(r['status']=='PASS' for r in results),[(r['case'],r['result']) for r in results if r['status']!='PASS']
  assert next(r for r in results if r['case']=='readonly-write')['preventedByHardening']
  assert not any(e.get('output_fields',{}).get('proc.name','').startswith('runc:') for e in events),'Reviewed bootstrap still emitted business alerts'
  for case in ['sensitive-read','readonly-write']:
   item=next(r for r in results if r['case']==case);assert item['event']['output_fields'].get('evt.arg.name')==item['command'][-1],'Exact attempted/read path missing'
  print('SIX_RUNTIME_CASES_PASS',flush=True)
 finally:
  if uid:
   actual=kube(['-n','devsecops-test','get','pod',name,'--ignore-not-found','-o','json'])
   if actual:
    assert actual['metadata']['uid']==uid and actual['metadata']['labels']['petclinic.devops.local/run']==owner
    kube(['-n','devsecops-test','delete','pod',name,'--wait=true','--timeout=40s'],timeout=50)
   assert not kube(['-n','devsecops-test','get','pod',name,'--ignore-not-found','-o','json'])
   run.compute_stopped=True
   (E/'test-cleanup.json').write_text(json.dumps({'pod':name,'uid':uid,'removed':True,'privilegedTestPodsCreated':0},indent=2))
