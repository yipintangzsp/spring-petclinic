"""Actual absent-file test only; no binaries, key generation, signing or scans."""
from pathlib import Path
import runpy,json,base64,io,tarfile,hashlib
OUT=Path(__file__).resolve().parent;ROOT=OUT.parents[2];api=runpy.run_path(str(OUT/'inspect-production.py'));old=json.loads((OUT/'linux-package-attempt2.json').read_text())
files=old['files'];blob=io.BytesIO();current={}
with tarfile.open(fileobj=blob,mode='w:gz') as tar:
 for n in files:
  p=ROOT/n;data=p.read_bytes();current[n]=hashlib.sha256(data).hexdigest();t=tarfile.TarInfo('package/'+n);t.size=len(data);t.mode=0o444;tar.addfile(t,io.BytesIO(data))
 # Public, explicitly synthetic signed object material; not secret/source code.
 for p in (OUT/'real-linux/cosign-fixtures').iterdir():
  if not p.is_file():continue
  data=p.read_bytes();t=tarfile.TarInfo('cosign-fixtures/'+p.name);t.size=len(data);t.mode=0o444;tar.addfile(t,io.BytesIO(data))
encoded=base64.b64encode(blob.getvalue()).decode();sig=json.loads((OUT/'signature-preparation.json').read_text());oldRoot=json.loads((OUT/'tool-preparation.json').read_text())['workspace']
script=r'''
import pathlib,tempfile,os,json,tarfile,io,base64,subprocess,shutil,hashlib
root=pathlib.Path(tempfile.mkdtemp(prefix='security-manager-gitleaks-',dir='/var/tmp'));root.chmod(0o755)
try:
 with tarfile.open(fileobj=io.BytesIO(base64.b64decode(BLOB))) as tar:
  for m in tar.getmembers():
   p=pathlib.PurePosixPath(m.name);assert m.isfile() and not p.is_absolute() and '..'not in p.parts
   dest=root/p;dest.parent.mkdir(parents=True,exist_ok=True);dest.write_bytes(tar.extractfile(m).read());dest.chmod(0o444)
 for d,ds,fs in os.walk(root):pathlib.Path(d).chmod(0o555)
 root.chmod(0o755);out=root/'outputs';out.mkdir(mode=0o700);os.chown(out,65534,65534)
 sig=json.loads(SIG_JSON.replace(OLD_ROOT,str(root)))
 approval={'schemaVersion':1,'scope':'SYNTHETIC_NON_RELEASE_OFFLINE_COSIGN_VERIFICATION','workspace':str(root),'executionUid':65534,'outputRoot':str(out),'tool':{'path':str(root/'cosign'),'version':'3.1.4'},'objects':sig['objects'],'trustIdentities':sig['trustIdentities'],'authorization':{'status':'APPROVED_CONTROLLED_NON_PRODUCTION_FIXTURES_ONLY','subject':'USER_REQUEST_57249cad'}}
 (root/'cosign-approval.json').write_text(json.dumps(approval));(root/'cosign-approval.json').chmod(0o444)
 js="""import fs from 'node:fs';import path from 'node:path';import assert from 'node:assert/strict';import {runCandidate} from './infra/security/manager-v2/core.mjs';import {realThreePluginsRegistry,registry} from './infra/security/manager-v2/registry.mjs';import {cosignExecutionCounts} from './infra/security/manager-v2/cosign-real.mjs';
 const root=process.argv[1],r=realThreePluginsRegistry(),before=cosignExecutionCounts();assert.equal(fs.existsSync(root+'/cosign'),false);const result=await runCandidate({config:{security:{plugins:Object.fromEntries(registry().ids().map(id=>[id,{enabled:id==='cosign'}]))}},registry:r,runId:'actual-absent-binary',projectId:'java-fixture',context:{platform:'linux',capabilities:Object.fromEntries(r.get('cosign').requiredCapabilities.map(k=>[k,{state:'AVAILABLE'}]))},inputs:{cosign:{approvalFile:root+'/cosign-approval.json',objectId:'java-fixture-valid'}},output:root+'/outputs/actual-absent-binary'});
 assert.equal(result.gate.cosign.executionStatus,'NOT_CONFIGURED');assert.equal(result.gate.cosign.failureReason,'COSIGN_TOOL_NOT_CONFIGURED');assert.equal(result.gate.cosign.policyDecision,null);assert.equal(result.gate.cosign.evaluationCount,0);assert.deepEqual(cosignExecutionCounts(),before);console.log(JSON.stringify({status:'PASS',realAbsentFile:true,countsBefore:before,countsAfter:cosignExecutionCounts(),result:result.gate.cosign,artifact:result.artifact,promotion:result.summary.promotion}));"""
 cmd=['setpriv','--reuid=65534','--regid=65534','--clear-groups','--no-new-privs','--bounding-set=-all','env','-i','PATH=/usr/bin:/bin','HOME='+str(out),'node','--max-old-space-size=256','--input-type=module','-e',js,str(root)]
 p=subprocess.run(cmd,cwd=root/'package',capture_output=True,text=True,timeout=30)
 result={'classification':'REAL_CONTROLLED_FILESYSTEM_PREREQUISITE_TEST_NOT_COSIGN_VERIFICATION','exit':p.returncode,'stdout':p.stdout,'stderr':p.stderr,'binaryFileAbsent':not(root/'cosign').exists(),'signatureMaterial':'PUBLIC_TEST_FIXTURE_REPLAY_FOR_PREREQUISITE_ONLY','scannerExecutions':0,'keysGenerated':0,'codeHashes':MANIFEST,'files':{}}
 for f in out.rglob('*.json'):result['files'][str(f.relative_to(root))]={'sha256':hashlib.sha256(f.read_bytes()).hexdigest(),'bytesUtf8':f.read_text()}
finally:
 shutil.rmtree(root);result['temporaryDomainRemoved']=not root.exists()
print(json.dumps(result))
'''
prefix='BLOB='+repr(encoded)+'\nSIG_JSON='+repr(json.dumps(sig))+'\nOLD_ROOT='+repr(oldRoot)+'\nMANIFEST='+repr(current)+'\n'
x=json.loads(api['remote']('sudo -n python3 -',prefix+script,90));api['save']('actual-missing-tool-execution.json',x);print(json.dumps({'exit':x['exit'],'binaryAbsent':x['binaryFileAbsent'],'temporaryDomainRemoved':x['temporaryDomainRemoved'],'stdout':x['stdout'][:700],'stderr':x['stderr'][-1000:]}))
assert x['exit']==0 and x['temporaryDomainRemoved']
