"""Authorized isolated real-execution matrix, stop on first mismatch/blocker.
No production client, no Gate/adapter/policy edits. Private material stays in RAM/tmpfs.
"""
from pathlib import Path
import sys,os,json,hashlib,importlib.util,subprocess,tarfile,io,copy,time,base64,shutil,traceback,tempfile
import yaml
REPO=Path.cwd();OUT=REPO/'evidence/2026-11-02/sops-authoritative-differential-02';PRIOR=REPO/'evidence/2026-11-02/sops-authoritative-baseline-02'
sys.path.insert(0,str(REPO/'infra/security/testing'));import isolated_sops_executor as g
spec=importlib.util.spec_from_file_location('owned_manager',PRIOR/'create_fixture.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);m.OUT=OUT;m.REQUESTS=0
B=json.loads((PRIOR/'authoritative-baseline.json').read_text());ROOT=Path(B['root']);NODE=Path('/private/tmp/sm-node-executor-erg_cakg/runtime');RUN='sm-sops-20261102-02'
DOCKER=['/opt/homebrew/bin/docker','--host','unix:///Users/zhangsir/.colima/security-test/docker.sock'];IMAGE='sha256:452d707d4862f52530247495d180205e029056831160e22870e37e3f6c1ac31f'
CASES=['POSITIVE_FULL_PATH','WRONG_AGE_KEY','DECRYPT_ERROR','SECRET_MISSING','SECRET_TYPE_MISMATCH','SECRET_DATA_MISMATCH','UID_CONTINUITY_FAILURE','VALUE_PRESERVATION_FAILURE','LEASE_HOLDER_MISMATCH','RBAC_DENIED','TOOL_MISSING','REPORT_WRITE_FAILURE']
canonical={};uids={};results=[];receipts=[];containers=[];BLOCK=None
def sha(b):return hashlib.sha256(b).hexdigest()
def dump(p,o):p.parent.mkdir(parents=True,exist_ok=True);p.write_text(json.dumps(o,indent=2))
def key(o):return (o['kind'],o.get('namespace') or o.get('metadata',{}).get('namespace'),o.get('name') or o['metadata']['name'])
def url(k):
 kind,ns,name=k;plural={'Namespace':'namespaces','ServiceAccount':'serviceaccounts','Secret':'secrets','Lease':'leases','Role':'roles','RoleBinding':'rolebindings','ClusterRole':'clusterroles','ClusterRoleBinding':'clusterrolebindings'}[kind]
 group='/apis/rbac.authorization.k8s.io/v1' if 'Role' in kind else '/apis/coordination.k8s.io/v1' if kind=='Lease' else '/api/v1'
 return group+('/namespaces/'+ns if ns else '')+'/'+plural+'/'+name
def get(k):
 c,o=m.api('GET',url(k));assert c==200,('OWNED_OBJECT_MISSING',k);return o
def semantic(o):
 o=copy.deepcopy(o);o.pop('status',None)
 for n in ['uid','creationTimestamp','resourceVersion','managedFields','generation']:o['metadata'].pop(n,None)
 return o
def fp(o):return sha(json.dumps(semantic(o),sort_keys=True,separators=(',',':')).encode())
def summary(o):
 v={'kind':o['kind'],'namespace':o['metadata'].get('namespace'),'name':o['metadata']['name'],'uid':o['metadata']['uid'],'semanticSha256':fp(o),'resourceVersion':o['metadata']['resourceVersion']}
 if o['kind']=='Secret':v.update(type=o['type'],keyNames=sorted(o['data']),dataSha256=sha(json.dumps(o['data'],sort_keys=True,separators=(',',':')).encode()))
 if o['kind']=='Lease':v['holderIdentity']=o['spec']['holderIdentity']
 return v
def assert_owned(o):assert o['metadata'].get('labels',{}).get('security-manager.test/run-id')==RUN
def write_obj(k,change):
 o=get(k);assert_owned(o);change(o);c,new=m.api('PUT',url(k),o);assert c==200;return new
def replace_secret(typ=None):
 k=('Secret','petclinic','petclinic-db');old=get(k);assert_owned(old)
 m.api('DELETE',url(k),{'apiVersion':'v1','kind':'DeleteOptions','preconditions':{'uid':old['metadata']['uid']}})
 for _ in range(50):
  if m.api('GET',url(k))[0]==404:break
  time.sleep(.1)
 else:raise RuntimeError('DELETE_NOT_COMPLETED')
 new=copy.deepcopy(canonical[k]);new['metadata']={n:v for n,v in new['metadata'].items() if n in ('name','namespace','labels','annotations')}
 if typ:new['type']=typ
 c,new=m.api('POST',url(k).rsplit('/',1)[0],new);assert c==201
 receipt={'kind':'EXPECTED_UID_REPLACEMENT','name':k[2],'originalBaselineUid':B['objects'][-4]['uid'],'previousUid':old['metadata']['uid'],'replacementUid':new['metadata']['uid'],'dataSha256':summary(new)['dataSha256'],'semanticBaselineMatch':fp(new)==fp(canonical[k])}
 uids[k]=new['metadata']['uid'];receipts.append(receipt);return receipt
def restore_missing():
 k=('Secret','petclinic','petclinic-db');new=copy.deepcopy(canonical[k]);new['metadata']={n:v for n,v in new['metadata'].items() if n in ('name','namespace','labels','annotations')}
 c,new=m.api('POST',url(k).rsplit('/',1)[0],new);assert c==201
 receipt={'kind':'EXPECTED_UID_REPLACEMENT','name':k[2],'previousUid':uids[k],'replacementUid':new['metadata']['uid'],'originalBaselineUid':canonical[k]['metadata']['uid'],'semanticBaselineMatch':fp(new)==fp(canonical[k])};uids[k]=new['metadata']['uid'];receipts.append(receipt);return receipt
def verify(label):
 states=[]
 for k,original in canonical.items():
  actual=get(k);assert actual['metadata']['uid']==uids[k],('UNEXPECTED_UID_DRIFT',k)
  assert fp(actual)==fp(original),('SEMANTIC_DRIFT',k);states.append(summary(actual))
 for name,h in B['frozenSourceSha256'].items():assert sha((REPO/name).read_bytes())==h,('FROZEN_SOURCE_DRIFT',name)
 for f in B['crypto']['files']:assert sha((ROOT/f['path']).read_bytes())==f['encryptedSha256']
 result={'status':'MATCHED','semanticBaselineRestored':True,'originalUidIdentical':all(uids[k]==o['metadata']['uid'] for k,o in canonical.items()),'objects':states,'uidReceipts':copy.deepcopy(receipts)};dump(OUT/(label+'.json'),result);return result
def tarbytes(scenario):
 buf=io.BytesIO()
 with tarfile.open(fileobj=buf,mode='w') as tar:
  def add(name,data,mode=0o600):
   info=tarfile.TarInfo(name);info.size=len(data);info.mode=mode;info.uid=65532;info.gid=65532;tar.addfile(info,io.BytesIO(data))
  def file(p,name,mode=0o600):add(name,p.read_bytes(),mode)
  for n in ['bootstrap.py','collector.py','observer.mjs']:file(OUT/n,n)
  add('case.json',json.dumps({'scenario':scenario}).encode())
  file(ROOT/'metadata/executor.kubeconfig','input.kubeconfig');file(ROOT/'metadata/executor-profile.json','input-profile.json')
  for n in ['baseline.agekey','negative-wrong-key.agekey']:file(ROOT/'keys'/n,'keys/'+n)
  for n in ['sops','age','age-keygen','kubectl']:file(ROOT/'tools'/n,'tools/'+n,0o500)
  file(NODE/'bin/node','node/bin/node',0o500)
  for n in ['isolated_sops_executor.py','sops_observation.py']:file(REPO/'infra/security/testing'/n,'python/'+n)
  for p in Path(yaml.__path__[0]).glob('*.py'):file(p,'python/yaml/'+p.name)
  for p in (REPO/'infra/security').rglob('*'):
   if p.is_file() and p.suffix in ('.mjs','.json') and 'secrets' not in p.relative_to(REPO/'infra/security').parts:
    file(p,'work/'+str(p.relative_to(REPO)))
  add('work/.git-sha',subprocess.check_output(['git','rev-parse','HEAD'],cwd=REPO))
  for f in B['crypto']['files']:
   data=(ROOT/f['path']).read_bytes()
   if scenario=='DECRYPT_ERROR' and f['name']=='petclinic-db':
    o=json.loads(data);v=o['data']['password'];start=v.index('data:')+5;o['data']['password']=v[:start]+('A' if v[start]!='A' else 'B')+v[start+1:];data=json.dumps(o).encode()
   add('work/infra/security/secrets/'+f['name']+'.enc.json',data)
  # Explicit directory modes are needed by the unchanged private-path guard.
  for n in ['keys','python','tools','work','results','control','boundary']:
   info=tarfile.TarInfo(n);info.type=tarfile.DIRTYPE;info.mode=0o700;tar.addfile(info)
 return buf.getvalue()
BOOT="import sys,tarfile,os;os.umask(0o077);tarfile.open(fileobj=sys.stdin.buffer,mode='r|').extractall('/fixture');os.execv('/usr/bin/python3',['/usr/bin/python3','/fixture/bootstrap.py'])"
def execute(scenario,num):
 name='sm-sops-diff-'+str(num);containers.append(name)
 cmd=DOCKER+['run','--rm','-i','--name',name,'--network','kind','--user','65532:65532','--read-only','--cap-drop','ALL','--security-opt','no-new-privileges','--pids-limit','128','--memory','900m','--cpus','2','--tmpfs','/fixture:rw,nosuid,nodev,exec,size=700m,mode=0700,uid=65532,gid=65532','--tmpfs','/var/jenkins_home/platform-security/20261027:rw,nosuid,nodev,exec,size=64m,mode=0700,uid=65532,gid=65532','--entrypoint','/usr/bin/python3',IMAGE,'-c',BOOT]
 data=tarbytes(scenario)
 # Output is bounded safe evidence only. No shell or inherited Docker context.
 stdoutFile=tempfile.TemporaryFile(dir=ROOT/'metadata');stderrFile=tempfile.TemporaryFile(dir=ROOT/'metadata')
 p=subprocess.Popen(cmd,stdin=subprocess.PIPE,stdout=stdoutFile,stderr=stderrFile)
 p.stdin.write(data);p.stdin.close();del data
 start=time.monotonic();mutated=False
 while p.poll() is None:
  if time.monotonic()-start>210:
   subprocess.run(DOCKER+['stop','--time','2',name],capture_output=True);raise RuntimeError('EXECUTOR_TIMEOUT')
  if scenario in ('UID_CONTINUITY_FAILURE','VALUE_PRESERVATION_FAILURE') and not mutated:
   probe=subprocess.run(DOCKER+['exec',name,'/usr/bin/python3','-c',"from pathlib import Path; p=Path('/fixture/control/request.json'); print(p.read_text() if p.exists() else '{}')"],capture_output=True)
   if probe.returncode==0 and json.loads(probe.stdout or b'{}').get('operation')==scenario:
    if scenario=='UID_CONTINUITY_FAILURE':receipt=replace_secret()
    else:
     k=('Secret','petclinic','petclinic-db');before=get(k);after=write_obj(k,lambda o:o['data'].update(password=base64.b64encode(b'FIXTURE_ONLY_PASSWORD_B').decode()));receipt={'kind':'REAL_VALUE_MUTATION','uid':after['metadata']['uid'],'beforeFingerprint':summary(before)['dataSha256'],'afterFingerprint':summary(after)['dataSha256']}
    payload=json.dumps({'success':True,**receipt}).encode()
    delivered=subprocess.run(DOCKER+['exec','-i',name,'/usr/bin/python3','-c',"import sys;from pathlib import Path;Path('/fixture/control/done.json').write_bytes(sys.stdin.buffer.read())"],input=payload,capture_output=True);assert delivered.returncode==0;mutated=True
  time.sleep(.2)
 stdoutFile.seek(0);stderrFile.seek(0);stdout=stdoutFile.read();stderr=stderrFile.read();stdoutFile.close();stderrFile.close();assert len(stdout)<4*1024*1024
 if p.returncode!=0:
  return {'scenario':scenario,'comparison':'INCOMPLETE','executorExit':p.returncode,'stderr':{'bytes':len(stderr),'sha256':sha(stderr)},'safeExecutorError':stderr.decode(errors='replace')[-2000:] if not stdout else None}
 doc=json.loads(stdout);doc['executor']={'exitCode':p.returncode,'elapsedSeconds':round(time.monotonic()-start,3),'stderrBytes':len(stderr),'stderrSha256':sha(stderr),'nonRootUid':65532,'network':'kind','noAdminCredential':True,'noHostMount':True,'containerRemoved':True};return doc
def main():
 global BLOCK
 assert json.loads((OUT/'precheck.json').read_text())['status']=='MATCHED'
 # Copy only existing kubectl executable from the pinned base, no registry/network.
 binary=subprocess.run(DOCKER+['run','--rm','--network','none','--read-only','--entrypoint','/usr/bin/python3',IMAGE,'-c',"import sys;sys.stdout.buffer.write(open('/usr/bin/kubectl','rb').read())"],capture_output=True,check=True).stdout
 g.write_private(ROOT/'tools/kubectl',binary,0o500);dump(OUT/'kubectl-identity.json',{'sourceImage':IMAGE,'sha256':sha(binary),'bytes':len(binary)});del binary
 for entry in B['objects']:
  k=key(entry);o=get(k);assert o['metadata']['uid']==entry['uid'];assert sha(json.dumps(o,sort_keys=True,separators=(',',':')).encode())==entry['snapshotSha256'];canonical[k]=o;uids[k]=o['metadata']['uid']
 dump(OUT/'comparison-contract.json',{'scenarios':CASES,'policyVersion':'baseline-v1','securityLevel':'standard','frozenSources':B['frozenSourceSha256'],'sourceType':'REAL_CONTROLLED_EXECUTION','originalBaselineSha256':sha((PRIOR/'authoritative-baseline.json').read_bytes()),'noExpectedDecisionInRawFacts':True})
 for i,scenario in enumerate(CASES,1):
  label=f'{i:02d}-{scenario}';verify(label+'-pre');delta={};receiptStart=len(receipts)
  try:
   k=('Secret','petclinic','petclinic-db')
   if scenario=='SECRET_MISSING':
    old=get(k);m.api('DELETE',url(k),{'apiVersion':'v1','kind':'DeleteOptions','preconditions':{'uid':old['metadata']['uid']}});assert m.api('GET',url(k))[0]==404;delta={'deletedUid':old['metadata']['uid']}
   if scenario=='SECRET_TYPE_MISMATCH':delta=replace_secret('kubernetes.io/basic-auth')
   if scenario=='SECRET_DATA_MISMATCH':
    before=get(k);after=write_obj(k,lambda o:o['data'].update(password=base64.b64encode(b'FIXTURE_ONLY_PASSWORD_B').decode()));delta={'beforeFingerprint':summary(before)['dataSha256'],'afterFingerprint':summary(after)['dataSha256'],'uid':after['metadata']['uid']}
   if scenario=='LEASE_HOLDER_MISMATCH':
    after=write_obj(('Lease','data-infra','platform-heavy'),lambda o:o['spec'].update(holderIdentity='sm-sops-controlled-mismatch'));delta={'holder':after['spec']['holderIdentity'],'uid':after['metadata']['uid']}
   if scenario=='RBAC_DENIED':
    after=write_obj(('Role','petclinic','sops-fixture-reconciler-business'),lambda o:[r.update(verbs=[v for v in r['verbs'] if v!='get']) for r in o['rules']]);delta={'role':summary(after),'removedVerb':'get'}
   doc=execute(scenario,i);doc['controlledDelta']=delta;dump(OUT/(label+'-execution.json'),doc)
   comparison=doc.get('result',{}).get('comparison',doc.get('comparison','INCOMPLETE'))
   results.append({'scenario':scenario,'comparison':comparison,'evidence':label+'-execution.json','oldDecision':doc.get('result',{}).get('oldGate',{}).get('oldDecision'),'policyDecision':doc.get('result',{}).get('policy',{}).get('decision')})
   print(json.dumps(results[-1]),flush=True)
   if comparison!='MATCH':BLOCK={'scenario':scenario,'comparison':comparison,'evidence':label+'-execution.json'}
  except Exception as exc:
   BLOCK={'scenario':scenario,'type':type(exc).__name__,'reason':str(exc)};dump(OUT/(label+'-manager-blocker.json'),BLOCK)
  finally:
   try:
    if scenario=='SECRET_MISSING':restore_missing()
    if scenario=='SECRET_TYPE_MISMATCH':replace_secret()
    if scenario in ('SECRET_DATA_MISMATCH','VALUE_PRESERVATION_FAILURE'):write_obj(k,lambda o:o.update(data=copy.deepcopy(canonical[k]['data'])))
    if scenario=='LEASE_HOLDER_MISMATCH':
     lk=('Lease','data-infra','platform-heavy');write_obj(lk,lambda o:o.update(spec=copy.deepcopy(canonical[lk]['spec'])))
    if scenario=='RBAC_DENIED':
     rk=('Role','petclinic','sops-fixture-reconciler-business');write_obj(rk,lambda o:o.update(rules=copy.deepcopy(canonical[rk]['rules'])))
     p=g.profile_from_document(json.loads((ROOT/'metadata/executor-profile.json').read_text()));g.execute(str(p.binding.path),{'KUBECONFIG':str(p.binding.path)},profile=p,mode='child',child_command=[sys.executable,str(PRIOR/'verify_rbac.py')],child_cwd=ROOT);shutil.copyfile(ROOT/'evidence/rbac-verification.json',OUT/(label+'-restored-auth.json'))
    restored=verify(label+'-restored');dump(OUT/(label+'-restoration-receipt.json'),{'semanticBaselineRestored':True,'originalUidIdentical':restored['originalUidIdentical'],'newUidReceipts':receipts[receiptStart:]})
   except Exception as exc:BLOCK={'scenario':scenario,'restorationFailed':True,'type':type(exc).__name__,'reason':str(exc)}
  dump(OUT/'matrix-progress.json',{'results':results,'blocker':BLOCK,'uidReceipts':receipts})
  if BLOCK:break
 verify('final-clean-state')
 dump(OUT/'matrix-result.json',{'approved':len(CASES),'executed':len(results),'results':results,'blocker':BLOCK,'uidReceipts':receipts,'productionApiAccess':0})
if __name__=='__main__':
 try:main()
 except Exception as exc:
  dump(OUT/'runner-blocker.json',{'type':type(exc).__name__,'reason':str(exc),'stack':traceback.format_exc()});print('RUNNER_BLOCKER',type(exc).__name__,flush=True);raise SystemExit(1)
