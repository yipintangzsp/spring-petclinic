"""Verify only this round's seal and preservation since its starting snapshot.

Does not upgrade ORIGINAL_EVIDENCE_INTEGRITY, runtime, CI or Agent validation.
"""
from pathlib import Path
import hashlib,json
OUT=Path(__file__).resolve().parent;ROOT=OUT.parents[2]
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
e=json.loads((OUT/'evidence-sha256.json').read_text())
actual={str(p.relative_to(OUT)):sha(p) for p in OUT.rglob('*') if p.is_file() and p.name!='evidence-sha256.json'}
assert e==actual,'This round evidence changed'
c=json.loads((OUT/'code-sha256.json').read_text());assert all(sha(ROOT/p)==h for p,h in c.items()),'Candidate files changed'
b=json.loads((OUT/'protected-before.json').read_text())['files'];assert all(sha(ROOT/p)==h for p,h in b.items()),'Existing protected files changed'
print(json.dumps({'thisRoundSeal':'VERIFIED','candidateFiles':len(c),'evidenceFiles':len(e),'existingFilesPreserved':len(b),
 'originalEvidenceIntegrity':'FAILED','realAgentValidation':'NOT_TESTED','CI_EXECUTION_READINESS':'CI_EXECUTION_NOT_READY','runtime':'14/16'}))
