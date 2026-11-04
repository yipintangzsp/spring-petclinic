"""Generate disposable test keys, sign ONLY local fixtures, delete keys before Manager."""
from pathlib import Path
import runpy,json
OUT=Path(__file__).resolve().parent;api=runpy.run_path(str(OUT/'inspect-production.py'));root=json.loads((OUT/'tool-preparation.json').read_text())['workspace']
script=r'''
import pathlib,subprocess,json,os,hashlib,shutil,time
r=pathlib.Path(ROOT);assert r.is_dir() and r.stat().st_uid==0 and shutil.disk_usage(r).free>2*1024**3
private=r/'cosign-private';private.mkdir(mode=0o700);os.chown(private,65534,65534)
fixtures=r/'cosign-fixtures';fixtures.mkdir(mode=0o755);rows=[];trust=[];commands=[]
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def execute(args,kind):
 cmd=['setpriv','--reuid=65534','--regid=65534','--clear-groups','--no-new-privs','--bounding-set=-all','env','-i','PATH=/usr/bin:/bin','HOME='+str(private),'TMPDIR='+str(private),'COSIGN_PASSWORD=',str(r/'cosign'),*args]
 p=subprocess.run(cmd,cwd=private,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=30)
 assert b'PRIVATE KEY'not in p.stdout and b'PRIVATE KEY'not in p.stderr
 commands.append({'kind':kind,'argv':args,'exit':p.returncode,'stdoutSha256':hashlib.sha256(p.stdout).hexdigest(),'stderrSha256':hashlib.sha256(p.stderr).hexdigest()})
 assert p.returncode==0,{'kind':kind,'exit':p.returncode,'stderr':p.stderr.decode()[-700:]}
try:
 for project in ['java-fixture','service-fixture']:
  prefix=private/project
  execute(['generate-key-pair','--output-key-prefix',str(prefix)],'GENERATE_DISPOSABLE_TEST_KEY')
  assert prefix.with_suffix('.key').is_file();prefix.with_suffix('.key').chmod(0o600)
  pub=fixtures/(project+'.pub');shutil.copyfile(prefix.with_suffix('.pub'),pub);pub.chmod(0o444)
  trust.append({'projectId':project,'trustId':'ephemeral-test-'+project,'publicKeyPath':str(pub),'publicKeySha256':sha(pub),'scope':'CONTROLLED_TEST_ONLY_NOT_PRODUCTION'})
 for project in ['java-fixture','service-fixture']:
  # The object contains no production image or credential. It is plain local data.
  data=json.dumps({'kind':'DisposableCosignValidationObject','projectId':project,'purpose':'NON_PRODUCTION_NO_PROMOTION','revision':'cosign-third-plugin-v1'},sort_keys=True).encode()
  obj=fixtures/(project+'-valid.json');obj.write_bytes(data);obj.chmod(0o444)
  sigPrivate=private/(project+'.sig')
  execute(['sign-blob','--yes','--new-bundle-format=false','--use-signing-config=false','--tlog-upload=false','--key',str(private/(project+'.key')),'--output-signature',str(sigPrivate),str(obj)],'SIGN_DISPOSABLE_LOCAL_OBJECT')
  sig=fixtures/(project+'-valid.sig');shutil.copyfile(sigPrivate,sig);sig.chmod(0o444)
  def entry(name,objectPath,signaturePath,present=True):return {'projectId':project,'objectId':project+'-'+name,'trustId':'ephemeral-test-'+project,'objectPath':str(objectPath),'objectSha256':sha(objectPath),'signaturePath':str(signaturePath),'signaturePresent':present,'signatureSha256':sha(signaturePath)if present else None,'sourceRevisionDigest':hashlib.sha256(data).hexdigest()}
  rows.append(entry('valid',obj,sig))
  if project=='java-fixture':
   tampered=fixtures/(project+'-tampered.json');tampered.write_bytes(data+b' ');tampered.chmod(0o444);rows.append(entry('tampered',tampered,sig))
   wrongPrivate=private/'wrong-trust.sig'
   execute(['sign-blob','--yes','--new-bundle-format=false','--use-signing-config=false','--tlog-upload=false','--key',str(private/'service-fixture.key'),'--output-signature',str(wrongPrivate),str(obj)],'SIGN_TEST_OBJECT_WITH_OTHER_TEST_IDENTITY')
   wrong=fixtures/'java-wrong-trust.sig';shutil.copyfile(wrongPrivate,wrong);wrong.chmod(0o444);rows.append(entry('wrong-trust',obj,wrong))
   rows.append(entry('missing',obj,fixtures/'ABSENT_SIGNATURE.sig',False))
   malformed=fixtures/'malformed.sig';malformed.write_text('THIS_IS_NOT_A_COSIGN_SIGNATURE\n');malformed.chmod(0o444);rows.append(entry('malformed',obj,malformed))
 fixtures.chmod(0o555)
finally:
 shutil.rmtree(private);assert not private.exists()
 assert not list(fixtures.glob('*.key'))
receipt={'classification':'REAL_CONTROLLED_TEST_MATERIAL_PREPARATION_NOT_PRODUCTION_SIGNING','commands':commands,'objects':rows,'trustIdentities':trust,'keysGenerated':2,'testSignaturesCreated':3,'privateDirectoryRemovedBeforeManager':not private.exists(),'remainingPrivateKeyFiles':0,'productionPrivateKeyRead':False,'productionImageSigned':False,'registryWrites':0,'release':0,'rollout':0}
(r/'signature-preparation.json').write_text(json.dumps(receipt));(r/'signature-preparation.json').chmod(0o444);print(json.dumps(receipt))
'''
x=json.loads(api['remote']('sudo -n python3 -','ROOT='+repr(root)+'\n'+script,120));api['save']('signature-preparation.json',x);print(json.dumps({'keysGenerated':x['keysGenerated'],'testSignaturesCreated':x['testSignaturesCreated'],'privateDirectoryRemovedBeforeManager':x['privateDirectoryRemovedBeforeManager'],'objects':len(x['objects']),'productionSigning':False}))
