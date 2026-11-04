"""Verify this round bytes and explicit incident recovery, never upgrade old integrity."""
from pathlib import Path
import hashlib,json,subprocess
OUT=Path(__file__).resolve().parent;ROOT=OUT.parents[2];sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
b=json.loads((OUT/'protected-before.json').read_text())
assert all(sha(ROOT/n)==h for n,h in b['protected'].items()),'Protected bytes differ'
for n,h in b['approvedExistingFileChanges'].items():
 assert hashlib.sha256(subprocess.check_output(['git','show',b['base']+':'+n],cwd=ROOT)).hexdigest()==h,'Unexplained baseline change'
code=json.loads((OUT/'code-sha256.json').read_text());assert all(sha(ROOT/n)==h for n,h in code.items())
pkg=json.loads((OUT/'linux-package-attempt3.json').read_text());assert all(sha(ROOT/n)==h for n,h in pkg['files'].items()),'Executed code differs from final code'
export=json.loads((OUT/'export-proof.json').read_text());assert export['fakePlaintextAbsent'] and not export['sourceExported']
assert all(sha(OUT/'real-linux'/n)==h['sha256'] for n,h in export['manifest'].items())
check=json.loads((OUT/'clean-checkout-attempt3.json').read_text());assert check['exit']==0 and check['tests']==check['pass']==230 and check['fail']==0 and check['temporaryTreeRemoved']
cleanup=json.loads((OUT/'linux-cleanup.json').read_text());assert cleanup['workspaceRemoved'] and cleanup['residualProcesses']==0
assert all(json.loads((OUT/'production-comparison.json').read_text())['checks'].values())
incident=json.loads((OUT/'legacy-evidence-incident.json').read_text());assert incident['changedCount']==78
assert all(sha(ROOT/n)==h for n,h in incident['preRoundHashes'].items()),'History incident not exactly repaired'
tail=json.loads((OUT/'exact-byte-tail-recovery-receipt.json').read_text());assert not tail['remainingProtectedDifferences']
v=json.loads((OUT/'VERDICT.json').read_text());assert v['verdict']['ORIGINAL_EVIDENCE_INTEGRITY']=='FAILED' and v['verdict']['FINAL_WIRED_CAPABILITY']=='14/16'
sealed=json.loads((OUT/'evidence-sha256.json').read_text());actual={str(p.relative_to(OUT)):sha(p) for p in OUT.rglob('*') if p.is_file() and p.name!='evidence-sha256.json'};assert sealed==actual,'This round evidence changed'
print(json.dumps({'newRoundSeal':'VERIFIED_SCOPED_BYTES','localRealCases':14,'offlineTests':230,'nativeTools':['gitleaks','semgrep'],'protectedBytesMatch':len(b['protected']),'historyWriteIncident':True,'exactHistoryByteRestorations':78,'historyMtimePreserved':False,'originalEvidenceIntegrity':'FAILED','productionSecurityManager':'NOT_ACTIVE','runtime':'14/16','release':0,'rollout':0}))
