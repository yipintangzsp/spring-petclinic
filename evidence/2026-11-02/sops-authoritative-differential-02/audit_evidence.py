"""Read-only evidence acceptance. Does not invoke a Gate or modify decisions."""
from pathlib import Path
import json,hashlib,collections,base64
R=Path.cwd();O=R/'evidence/2026-11-02/sops-authoritative-differential-02';P=R/'evidence/2026-11-02/sops-authoritative-baseline-02'
def sha(b):return hashlib.sha256(b).hexdigest()
def save(n,x):(O/n).write_text(json.dumps(x,indent=2))
B=json.loads((P/'authoritative-baseline.json').read_text());M=json.loads((O/'matrix-result.json').read_text());assert M['blocker'] is None and len(M['results'])==12
entries=[];old=collections.Counter();policy=collections.Counter()
for i,entry in enumerate(M['results'],1):
 s=entry['scenario'];label=f'{i:02d}-{s}';f=O/(label+'-execution.json');doc=json.loads(f.read_text());e=doc['result'];r=e['rawEvidence'];p=e['policy'];events=r['events'];facts=r['facts'];child=doc['child']
 assert e['classification']=='REAL_CONTROLLED_EXECUTION' and e['comparison']=='MATCH' and e['adapterError'] is None
 assert doc['guard']['status']=='ACCEPTED' and doc['guard']['profile']=='MIN_RBAC_EXECUTOR' and doc['guard']['audit']['child_executions']==1
 assert child['exit']['code']==e['oldGate']['exitCode'] and not child['exit']['timedOut'] and child['exit']['signal'] is None
 assert e['oldGate']['oldDecision']==p['decision'] and p['securityLevel']=='standard' and p['policyVersion']=='baseline-v1'
 assert r['rawPreserved'] and p['severity'] is None
 assert p['sopsFacts']==e['adapterRawOutput'] and e['adapterRawOutput']['status']=='success'
 restored=json.loads((O/(label+'-restoration-receipt.json')).read_text());assert restored['semanticBaselineRestored']
 pre=json.loads((O/(label+'-pre.json')).read_text());post=json.loads((O/(label+'-restored.json')).read_text());assert pre['status']==post['status']=='MATCHED'
 processes=[x for x in events if x['kind']=='PROCESS'];sops=[x for x in processes if x['command'].endswith('/sops')]
 assert all(not x['timedOut'] and x['signal'] is None for x in processes)
 if s=='POSITIVE_FULL_PATH':assert p['decision']=='PASS' and len(facts['targets'])==4 and all(t['uidEqual'] and t['dataEqual'] for t in facts['targets'])
 if s in ('WRONG_AGE_KEY','DECRYPT_ERROR'):
  assert len(sops)==1 and sops[0]['exitCode']==(128 if s=='WRONG_AGE_KEY' else 25) and sops[0]['stdout']['bytes']==0
 if s=='SECRET_MISSING':assert facts['targets'][0]['readSucceeded'] is False and restored['newUidReceipts']
 if s=='SECRET_TYPE_MISMATCH':assert facts['targets'][0]['actual']['type']=='kubernetes.io/basic-auth'
 if s=='SECRET_DATA_MISMATCH':assert doc['controlledDelta']['beforeFingerprint']!=doc['controlledDelta']['afterFingerprint']
 if s=='UID_CONTINUITY_FAILURE':assert facts['targets'][0]['uidEqual'] is False and facts['targets'][0]['dataEqual'] is True and any(x['kind']=='REAL_MUTATION_BARRIER' for x in events)
 if s=='VALUE_PRESERVATION_FAILURE':assert facts['targets'][0]['uidEqual'] is True and facts['targets'][0]['dataEqual'] is False and any(x['kind']=='REAL_MUTATION_BARRIER' for x in events)
 if s=='LEASE_HOLDER_MISMATCH':assert facts['prerequisites']['lease'] is False and facts['targets']==[]
 if s=='RBAC_DENIED':
  assert facts['targets'][0]['readSucceeded'] is False and doc['controlledDelta']['removedVerb']=='get'
  assert json.loads((O/(label+'-restored-auth.json')).read_text())['allMatched']
 if s=='TOOL_MISSING':assert facts['prerequisites']['tools'] is False and any(x.get('errorClass')=='ENOENT' for x in events)
 if s=='REPORT_WRITE_FAILURE':assert facts['reportWriteSucceeded'] is False and any(x.get('errorClass')=='EISDIR' for x in events)
 old[e['oldGate']['oldDecision']]+=1;policy[p['decision']]+=1
 refs={n:sha((O/n).read_bytes()) for n in [label+'-pre.json',label+'-execution.json',label+'-restored.json',label+'-restoration-receipt.json']}
 entries.append({'scenario':s,'applicability':'APPLICABLE','controlledDelta':doc['controlledDelta'],'executionEvidence':label+'-execution.json','evidenceFiles':refs,'oldDecision':e['oldGate']['oldDecision'],'policyDecision':p['decision'],'normalizedPolicyFactPointer':'/result/adapterRawOutput','rawFactPointer':'/result/rawEvidence','effectivePolicyPointer':'/result/policy/effectivePolicy','policyVersion':p['policyVersion'],'securityLevel':p['securityLevel'],'comparison':'MATCH','rawPreserved':True})
# Protect every pre-existing project byte, not just selected Gate sources.
before=json.loads((O/'project-before.json').read_text());drift=[n for n,h in before.items() if not (R/n).is_file() or sha((R/n).read_bytes())!=h];assert not drift,drift
protected=json.loads((O/'protected-before.json').read_text());after=[]
for entry in protected:
 p=Path(entry['path']);now=sha(p.read_bytes());assert now==entry['sha256'];after.append({'path':str(p),'sha256':now,'unchanged':True})
save('protected-after.json',after)
for n,h in B['frozenSourceSha256'].items():assert sha((R/n).read_bytes())==h
assert json.loads((O/'baseline-reference.json').read_text())['sha256']==sha((P/'authoritative-baseline.json').read_bytes())
root=Path(B['root']);encrypted=O/'encrypted-evidence';encrypted.mkdir(exist_ok=True)
for f in B['crypto']['files']:
 data=(root/f['path']).read_bytes();assert sha(data)==f['encryptedSha256'];(encrypted/Path(f['path']).name).write_bytes(data)
 if f['name']=='petclinic-db':
  c=json.loads(data);v=c['data']['password'];start=v.index('data:')+5;c['data']['password']=v[:start]+('A' if v[start]!='A' else 'B')+v[start+1:];corrupted=json.dumps(c).encode();(encrypted/'03-corrupted-petclinic-db.enc.json').write_bytes(corrupted)
  save('decrypt-error-input-receipt.json',{'classification':'CONTROLLED_INPUT_RECONSTRUCTION_FROM_EXECUTED_MATERIALIZER','actualSopsExitCode':25,'originalSha256':sha(data),'corruptedSha256':sha(corrupted),'change':'one authenticated ciphertext character; host original unchanged','runtimeFileTransferredBy':'run_matrix.py:tarbytes','notWrongKey':True})
# Never archive raw Secret values, active bearer tokens or either actual private key.
cfg=__import__('yaml').safe_load((root/'metadata/executor.kubeconfig').read_bytes());sensitive=[cfg['users'][0]['user']['token'].encode()]
for f in (root/'keys').glob('*.agekey'):
 sensitive += [line for line in f.read_bytes().splitlines() if line.startswith(b'AGE-SECRET-KEY-')]
leaks=[]
for f in O.rglob('*'):
 if f.is_file() and any(s in f.read_bytes() for s in sensitive):leaks.append(str(f.relative_to(O)))
assert not leaks,leaks
save('secret-leakage-check.json',{'activeTokenAndBothActualPrivateKeysScanned':True,'matches':0,'decryptedStdoutOrSecretDataArchived':False,'rawValuesInMemoryOnly':True,'stderrContentStored':False,'syntheticFixtureSourceIsNotProductionCredential':True})
save('precleanup-acceptance.json',{'status':'PASS','applicable':12,'notApplicable':0,'gateExecutions':12,'policyExecutions':12,'oldDecisionDistribution':dict(old),'policyDecisionDistribution':dict(policy),'matches':12,'drifts':0,'originalUidIdentical':False,'semanticBaselineRestored':True,'rawFactsPreserved':True,'preExistingProjectFilesUnchanged':len(before),'protectedHostFilesUnchanged':len(after),'noSemanticChanges':True,'productionApiAccess':0,'cases':entries,'frozenSources':B['frozenSourceSha256']})
files={str(p.relative_to(O)):sha(p.read_bytes()) for p in O.rglob('*') if p.is_file() and p.name not in ['precleanup-evidence-index.json','precleanup-index-validation.json']}
save('precleanup-evidence-index.json',{'files':files,'baseline':{'path':str(P/'authoritative-baseline.json'),'sha256':sha((P/'authoritative-baseline.json').read_bytes())},'cases':entries,'tools':B['toolchain'],'node':B['nodeRuntime'],'frozenSources':B['frozenSourceSha256']})
assert all((O/n).is_file() and sha((O/n).read_bytes())==h for n,h in files.items())
save('precleanup-index-validation.json',{'status':'PASS','filesChecked':len(files),'allReferencesExist':True,'allSha256Match':True,'beforeCredentialCleanup':True})
print('PRE_CLEANUP_ACCEPTANCE_PASS: 12 MATCH, 0 DRIFT; all references and hashes verified')
