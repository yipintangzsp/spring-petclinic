"""Verify NEW seal; preserve all pre-existing evidence and frozen code.

Approved candidate evolution is compared to current code hashes. Historical
candidate seal is checked against its exact Git baseline, never rewritten.
"""
from pathlib import Path
import hashlib,json,subprocess
OUT=Path(__file__).resolve().parent;ROOT=OUT.parents[2]
sha=lambda b:hashlib.sha256(b).hexdigest()
base=json.loads((OUT/'baseline.json').read_text())
for name,h in base['protectedFiles'].items():assert sha((ROOT/name).read_bytes())==h,'Protected file changed: '+name
historical=json.loads((ROOT/'evidence/2026-11-04/gitleaks-ephemeral-agent-plan/code-sha256.json').read_text())
for name,h in historical.items():
 assert base['approvedCandidateBefore'][name]==h,'Candidate already unexplained at start: '+name
 old=subprocess.check_output(['git','show',base['head']+':'+name],cwd=ROOT)
 assert sha(old)==h,'Historical candidate Git mismatch: '+name
current=json.loads((OUT/'candidate-sha256.json').read_text())
actualCode={str(p.relative_to(ROOT)):sha(p.read_bytes()) for p in (ROOT/'infra/jenkins/gitleaks-validation/ephemeral-agent').rglob('*') if p.is_file()}
assert current==actualCode,'Current approved candidate changed after sealing'
sealed=json.loads((OUT/'evidence-sha256.json').read_text())
actual={str(p.relative_to(OUT)):sha(p.read_bytes()) for p in OUT.rglob('*') if p.is_file() and p.name!='evidence-sha256.json'}
assert sealed==actual,'New evidence changed after sealing'
checks=json.loads((OUT/'production-comparison.json').read_text())['checks'];assert all(checks.values())
tests=json.loads((OUT/'clean-checkout.json').read_text());assert tests['pass']==241 and tests['fail']==0 and tests['temporaryCheckoutRemoved']
v=json.loads((OUT/'VERDICT.json').read_text());assert v['CI_EXECUTION_READINESS']=='CI_EXECUTION_NOT_READY'
assert v['ORIGINAL_EVIDENCE_INTEGRITY']=='FAILED' and v['FINAL_WIRED_CAPABILITY']=='14/16'
print(json.dumps({'newRoundSeal':'VERIFIED','protectedFilesUnchanged':len(base['protectedFiles']),'historicalCandidateGitBytesVerified':len(historical),'currentCandidateFiles':len(current),'newEvidenceFiles':len(sealed),'offlineTests':241,'realAgentValidation':'NOT_TESTED','CI_EXECUTION_READINESS':'CI_EXECUTION_NOT_READY','originalEvidenceIntegrity':'FAILED','runtime':'14/16'}))
