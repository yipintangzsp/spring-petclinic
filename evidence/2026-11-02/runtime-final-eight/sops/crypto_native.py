"""Linux fixture-only crypto. No API, Gate, Policy, HOME fallback or external keys."""
from pathlib import Path
import os,sys,subprocess,json,hashlib,tarfile
os.umask(0o077);root=Path('/fixture');os.chdir(root)
env={'HOME':'/fixture/home','PATH':'/usr/bin:/bin','LANG':'C.UTF-8'}
versions={}
for tool,expected in [('sops','3.13.3'),('age','1.3.2'),('age-keygen','1.3.2')]:
 r=subprocess.run([str(root/'tools'/tool),'--version'],env=env,capture_output=True,timeout=15)
 text=(r.stdout+r.stderr).decode(errors='replace').strip()
 if r.returncode or expected not in text:raise RuntimeError('TOOL_VERSION_MISMATCH '+tool)
 versions[tool]=text
if sys.argv[-1]=='versions':
 print(json.dumps({'versions':versions,'architecture':'Linux AArch64'}));sys.exit(0)
mode=sys.argv[-1]
if mode=='keys':
 assert not (root/'keys/baseline.agekey').exists() and not (root/'keys/negative-wrong-key.agekey').exists()
 recipients={}
 for kind,name in [('baseline','baseline'),('wrongKey','negative-wrong-key')]:
  key=root/'keys'/(name+'.agekey')
  r=subprocess.run([str(root/'tools/age-keygen'),'-o',str(key)],env=env,capture_output=True,timeout=15)
  if r.returncode:raise RuntimeError('KEY_GENERATION_FAILED')
  key.chmod(0o600)
  r=subprocess.run([str(root/'tools/age-keygen'),'-y',str(key)],env=env,capture_output=True,timeout=15)
  if r.returncode:raise RuntimeError('RECIPIENT_FAILED')
  recipient=r.stdout.decode().strip();recipients[kind]={'recipient':recipient,'fingerprint':hashlib.sha256(recipient.encode()).hexdigest()}
  (root/'keys'/(name+'.recipient')).write_text(recipient+'\n')
 assert recipients['baseline']['recipient']!=recipients['wrongKey']['recipient']
 (root/'metadata/key-evidence.json').write_text(json.dumps({'classification':'REAL_DISPOSABLE_TEST_KEYS_ONLY','recipients':recipients,'privateKeyContentsRecorded':False},indent=2))
 with tarfile.open(fileobj=sys.stdout.buffer,mode='w|') as t:
  t.add(root/'keys',arcname='keys')
  t.add(root/'metadata/key-evidence.json',arcname='metadata/key-evidence.json')
 sys.exit(0)
assert mode=='encrypt'
recipients={}
for kind,name in [('baseline','baseline'),('wrongKey','negative-wrong-key')]:
 key=root/'keys'/(name+'.agekey')
 assert key.exists() and key.stat().st_mode & 0o777 == 0o600
 r=subprocess.run([str(root/'tools/age-keygen'),'-y',str(key)],env=env,capture_output=True,timeout=15)
 assert r.returncode==0
 recipient=r.stdout.decode().strip();assert recipient==(root/'keys'/(name+'.recipient')).read_text().strip()
 recipients[kind]={'recipient':recipient,'fingerprint':hashlib.sha256(recipient.encode()).hexdigest()}
assert recipients['baseline']['recipient']!=recipients['wrongKey']['recipient']
results=[]
for p in sorted((root/'plaintext').glob('*.json')):
 desired=p.read_bytes();target=json.loads(desired)
 dest=root/'encrypted'/('infra/security/secrets/'+p.stem+'.enc.json');dest.parent.mkdir(parents=True,exist_ok=True)
 r=subprocess.run([str(root/'tools/sops'),'encrypt','--age',recipients['baseline']['recipient'],'--encrypted-regex','^(data)$','--input-type','json','--output-type','json',str(p)],env=env,capture_output=True,timeout=20)
 if r.returncode:raise RuntimeError('ENCRYPTION_FAILED')
 dest.write_bytes(r.stdout);cipher_before=hashlib.sha256(r.stdout).hexdigest()
 encrypted=json.loads(r.stdout);assert len(encrypted['sops']['age'])==1 and encrypted['sops']['age'][0]['recipient']==recipients['baseline']['recipient']
 de={**env,'SOPS_AGE_KEY_FILE':str(root/'keys/baseline.agekey')}
 r=subprocess.run([str(root/'tools/sops'),'decrypt',str(dest)],env=de,capture_output=True,timeout=20)
 if r.returncode or json.loads(r.stdout)!=target:raise RuntimeError('POSITIVE_DECRYPT_MISMATCH')
 assert cipher_before==hashlib.sha256(dest.read_bytes()).hexdigest()
 results.append({'path':str(dest.relative_to(root)),'name':target['metadata']['name'],'namespace':target['metadata']['namespace'],'type':target['type'],'keyNames':sorted(target['data']),'plaintextSha256':hashlib.sha256(desired).hexdigest(),'encryptedSha256':cipher_before,'dataSha256':hashlib.sha256(json.dumps(target['data'],sort_keys=True,separators=(',',':')).encode()).hexdigest(),'positiveDecryptExit':r.returncode,'exactStructureMatch':True,'recipient':recipients['baseline']['recipient']})
assert len(results)==4
chosen=root/results[0]['path'];wrongenv={**env,'SOPS_AGE_KEY_FILE':str(root/'keys/negative-wrong-key.agekey')}
r=subprocess.run([str(root/'tools/sops'),'decrypt',str(chosen)],env=wrongenv,capture_output=True,timeout=20)
assert r.returncode!=0 and not r.stdout
negative={'factType':'DECRYPT_EXECUTION_FACT','source':'real-isolated-sops-process','path':str(chosen.relative_to(root)),'exitCode':r.returncode,'stdoutBytes':len(r.stdout),'stderrBytes':len(r.stderr),'stderrSha256':hashlib.sha256(r.stderr).hexdigest(),'encryptedRecipient':recipients['baseline']['recipient'],'attemptedKeyRecipient':recipients['wrongKey']['recipient'],'homeIsEmpty':not (root/'home/.config').exists(),'policyDecisionGenerated':False}
meta={'classification':'REAL_CONTROLLED_FIXTURE_CRYPTO_ONLY_NOT_GATE_COMPATIBILITY','versions':versions,'recipients':recipients,'files':results,'wrongKey':negative,'gateExecutions':0,'policyDifferentials':0}
(root/'metadata/crypto-evidence.json').write_text(json.dumps(meta,indent=2))
with tarfile.open(fileobj=sys.stdout.buffer,mode='w|') as t:
 for d in ['encrypted']:
  t.add(root/d,arcname=d)
 t.add(root/'metadata/crypto-evidence.json',arcname='metadata/crypto-evidence.json')
